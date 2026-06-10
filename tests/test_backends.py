"""Tests for the EvidenceSource seam (synthetic + live triage adapter).

The live adapter is exercised against a small fixture directory that mimics a
KAPE/Velociraptor triage collection (aliased filenames + tool column names),
proving the agent/detectors/analyzers run unchanged across sources without a
real forensic image.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from find_evil.backends import (  # noqa: E402
    LiveTriageSource, SyntheticSource, make_source,
)
from find_evil.agent import TriageAgent  # noqa: E402

DATA = os.path.join(ROOT, "data", "synthetic")


def test_synthetic_source_loads_case():
    src = SyntheticSource(os.path.join(DATA, "case-lab-01"))
    recs = src.load()
    assert recs["sysmon"]
    assert all(r.ref.startswith("sysmon.evtx.jsonl:") for r in recs["sysmon"])


def test_make_source_defaults_to_synthetic(monkeypatch=None):
    os.environ.pop("FIND_EVIL_LIVE_DIR", None)
    src = make_source(os.path.join(DATA, "case-lab-01"))
    assert isinstance(src, SyntheticSource)
    assert src.label == "synthetic"


def test_make_source_switches_to_live(tmp_path):
    live = tmp_path / "triage"
    live.mkdir()
    (live / "threat_intel.csv").write_text("row,indicator,type,verdict\n1,1.2.3.4,ipv4,malicious\n")
    os.environ["FIND_EVIL_LIVE_DIR"] = str(live)
    try:
        src = make_source(os.path.join(DATA, "case-lab-01"))
        assert isinstance(src, LiveTriageSource)
        assert src.label.startswith("live:")
    finally:
        os.environ.pop("FIND_EVIL_LIVE_DIR", None)


def _write_kape_fixture(root):
    """A KAPE-style triage collection with aliased filenames + tool columns."""
    os.makedirs(os.path.join(root, "EventLogs"), exist_ok=True)
    os.makedirs(os.path.join(root, "Registry"), exist_ok=True)
    # Sysmon EVTX exported by EvtxECmd as JSON-lines with tool field names
    sysmon = os.path.join(root, "EventLogs", "Microsoft-Windows-Sysmon%4Operational.json")
    with open(sysmon, "w") as fh:
        fh.write(json.dumps({"row": 1, "EventID": 1, "UtcTime": "2026-06-06T01:00:00Z",
                             "Image": "C:\\Windows\\System32\\cmd.exe",
                             "ParentImage": "C:\\Program Files\\WINWORD.EXE",
                             "CommandLine": "cmd /c powershell -enc AAAA", "ProcessId": 10,
                             "ParentProcessId": 4, "type": "ProcessCreate"}) + "\n")
    # PECmd prefetch output with tool column headers
    pf = os.path.join(root, "Registry", "WIN-HOST_PECmd_Output.csv")
    with open(pf, "w") as fh:
        fh.write("ExecutableName,LastRun,RunCount,SourceFilename\n")
        fh.write("POWERSHELL.EXE,2026-06-06T01:00:05Z,3,POWERSHELL.EXE-AAAA.pf\n")
    # local offline threat-intel export (read by the live path for scoring)
    with open(os.path.join(root, "threat_intel.csv"), "w") as fh:
        fh.write("row,indicator,type,verdict,note\n1,1.2.3.4,ipv4,malicious,test\n")


def test_live_source_normalises_kape_columns(tmp_path):
    root = tmp_path / "kape"
    root.mkdir()
    _write_kape_fixture(str(root))
    src = LiveTriageSource(str(root))
    recs = src.load()
    # sysmon EVTX field names normalised to our schema
    sm = recs["sysmon"]
    assert sm and sm[0].get("image", "").lower().endswith("cmd.exe")
    assert sm[0].get("type") == "ProcessCreate"
    assert "powershell" in (sm[0].get("cmdline") or "").lower()
    # prefetch tool columns normalised
    pf = recs["prefetch"]
    assert pf and pf[0].get("executable") == "POWERSHELL.EXE"
    assert pf[0].get("run_count") == "3"
    # provenance ref points at the real on-disk filename
    assert sm[0].ref.startswith("Microsoft-Windows-Sysmon")


def test_agent_runs_unchanged_against_live_source(tmp_path):
    """The agent pipeline must execute end-to-end on a live triage dir."""
    root = tmp_path / "kape2"
    root.mkdir()
    _write_kape_fixture(str(root))
    os.environ["FIND_EVIL_LIVE_DIR"] = str(root)
    try:
        agent = TriageAgent(case_id="live-test", case_dir=str(root))
        summary = agent.run()
        # the encoded-PS + LOLBin chain in the fixture should produce >=1 detection
        assert summary["detections"] >= 1
        assert agent.es.source_label.startswith("live:")
        # analyzers ran and the process tree saw the cmd.exe process
        pt = agent.analyzer_results["process_tree"]
        assert any("cmd.exe" in (n["image"] or "").lower() for n in pt.items)
    finally:
        os.environ.pop("FIND_EVIL_LIVE_DIR", None)
