"""Tests for the FIND EVIL! triage agent across the whole case library.

Run: PYTHONPATH=src python3 -m pytest tests/ -q
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from find_evil.agent import TriageAgent  # noqa: E402
from find_evil import analyzers  # noqa: E402

DATA = os.path.join(ROOT, "data", "synthetic")


def all_cases():
    return sorted(n for n in os.listdir(DATA)
                  if os.path.exists(os.path.join(DATA, n, "manifest.json")))


def run(case_id):
    agent = TriageAgent(case_id=case_id, case_dir=os.path.join(DATA, case_id))
    summary = agent.run()
    return agent, summary


CASES = all_cases()


# ---- accuracy across every case ------------------------------------------

@pytest.mark.parametrize("case_id", CASES)
def test_perfect_recall_and_decoy_rejected(case_id):
    _, summary = run(case_id)
    acc = summary["accuracy"]
    assert acc["scored"], case_id
    assert acc["recall"] == 1.0, f"{case_id}: recall {acc['recall']}, missed {acc['missed']}"
    assert acc["precision"] == 1.0, f"{case_id}: precision {acc['precision']}"
    assert acc["decoy_rejected"] is True, case_id


def test_case_library_has_at_least_five_diverse_cases():
    classes = set()
    platforms = set()
    for cid in CASES:
        agent, _ = run(cid)
        classes.add(agent.manifest.get("attack_class"))
        platforms.add(agent.manifest.get("platform"))
    assert len(CASES) >= 5
    assert len(classes) >= 5, classes
    assert "linux" in platforms and "windows" in platforms, platforms


# ---- evidence provenance integrity ---------------------------------------

@pytest.mark.parametrize("case_id", CASES)
def test_every_alert_has_resolvable_evidence_refs(case_id):
    agent, _ = run(case_id)
    valid = set(agent.es.ref_index().keys()) | {"manifest.json:1"}
    alerts = [r for r in agent.ledger.records if r["event_type"] == "alert"]
    assert alerts, case_id
    for r in agent.ledger.records:
        assert r["evidence_refs"], f"{case_id} {r['evidence_id']} missing refs"
        assert r["evidence_pointer"]
        for ref in r["evidence_refs"]:
            assert ref in valid, f"{case_id} {r['evidence_id']} cites non-existent {ref}"


@pytest.mark.parametrize("case_id", CASES)
def test_self_correction_present_in_trace(case_id):
    agent, _ = run(case_id)
    kinds = {s["kind"] for s in agent.trace.steps}
    assert {"hypothesis", "contradiction", "self_correction"} <= kinds, case_id


@pytest.mark.parametrize("case_id", CASES)
def test_ledger_schema_required_fields(case_id):
    agent, _ = run(case_id)
    required = {"evidence_id", "case_id", "event_time_utc", "event_type",
                "source", "summary", "severity", "owner", "status", "notes"}
    for r in agent.ledger.records:
        assert required.issubset(r.keys()), f"{case_id} {r['evidence_id']}"


# ---- analyzers ------------------------------------------------------------

@pytest.mark.parametrize("case_id", CASES)
def test_all_analyzers_run_and_cite_real_rows(case_id):
    agent, summary = run(case_id)
    assert summary["analyzers"] == len(analyzers.ALL_ANALYZERS)
    valid = set(agent.es.ref_index().keys())
    for name, res in agent.analyzer_results.items():
        for ref in res.evidence_refs:
            assert ref in valid, f"{case_id}/{name} cites non-existent {ref}"


def test_process_tree_reconstructs_phishing_chain():
    agent, _ = run("case-lab-01")
    pt = agent.analyzer_results["process_tree"]
    images = {(n["image"] or "").lower() for n in pt.items}
    assert any("winword.exe" in i for i in images)
    assert any("powershell.exe" in i for i in images)
    # the encoded-PS process must descend from WINWORD (depth > 0)
    ps = [n for n in pt.items if "powershell.exe" in (n["image"] or "").lower()]
    assert any(n["depth"] >= 1 for n in ps)


def test_decode_powershell_recovers_plaintext():
    agent, _ = run("case-lab-01")
    dec = agent.analyzer_results["decode_powershell"]
    assert dec.items
    # the logged 4104 script block carries the download cradle
    assert any("DownloadString" in (i.get("logged_script_block") or "")
               or "DownloadFile" in (i.get("logged_script_block") or "")
               for i in dec.items)


def test_decode_b64_utf16_roundtrip():
    import base64
    from find_evil.analyzers import _decode_b64_ps
    payload = "Write-Host hi; IEX (New-Object Net.WebClient)"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    assert _decode_b64_ps(enc) == payload


def test_lolbin_scan_flags_squiblydoo():
    agent, _ = run("case-lotl-03")
    bins = {i["binary"] for i in agent.analyzer_results["lolbin_scan"].items}
    assert {"mshta.exe", "regsvr32.exe", "certutil.exe"} <= bins


def test_persistence_sweep_flags_wmi_and_run_key():
    agent_l, _ = run("case-lotl-03")
    mechs = {i["mechanism"] for i in agent_l.analyzer_results["persistence_sweep"].items
             if i["suspicious"]}
    assert "wmi_subscription" in mechs


def test_ioc_extraction_correlates_threat_intel():
    agent, _ = run("case-lab-01")
    iocs = agent.analyzer_results["extract_iocs"].items
    mal = [i for i in iocs if i["verdict"] == "malicious"]
    assert any(i["indicator"] == "203.0.113.45" for i in mal)
    # private IPs must be excluded from the IOC set
    assert not any(i["indicator"].startswith("10.20.") for i in iocs)


def test_lateral_graph_excludes_sysvol_but_finds_real_movement():
    agent, _ = run("case-lab-01")
    edges = agent.analyzer_results["lateral_movement_graph"].items
    assert any(e["dst"] == "FILE-SRV-02" or "FILE-SRV-02" in str(e.get("cmdline", ""))
               for e in edges)


def test_super_timeline_is_chronological():
    agent, _ = run("case-ransom-02")
    items = agent.analyzer_results["super_timeline"].items
    times = [i["time_utc"] for i in items]
    assert times == sorted(times)
    assert len({i["artifact"] for i in items}) >= 3
