"""Evidence-source seam: the agent reads forensic artifacts through an
``EvidenceSource`` so the SAME agent / detectors / analyzers / eval run
unchanged against either synthetic data or a real triage collection.

Two implementations ship:

* ``SyntheticSource`` — the offline, stdlib-only loader over the synthetic
  evidence artifacts in ``data/synthetic/<case>/`` (the default; what the
  whole demo runs on). No network, never mutates evidence.
* ``LiveTriageSource`` — reads from an actual mounted forensic-triage
  directory (KAPE / Velociraptor / SIFT-style output) when
  ``FIND_EVIL_LIVE_DIR`` points at it. It is real, correct, read-only code:
  it discovers KAPE module CSVs and EVTX-derived JSONL on disk, normalises
  their column names into the logical artifact schema the agent expects,
  and is unit-testable against a fixture directory without a real image.

The one-line switch::

    source = make_source(case_dir)   # auto: live if env set, else synthetic

Every row carries a stable, immutable provenance ``ref`` (``<file>:<row>``)
regardless of source, so findings cite real artifact rows in both modes.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class EvidenceRecord:
    """One immutable row of evidence with a stable provenance ref."""

    ref: str  # "<file>:<row>"
    artifact: str  # logical artifact name, e.g. "sysmon"
    source_file: str  # filename within the case dir
    row: int
    data: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


# logical artifact name -> (filename, format). Shared by both sources; the
# live source additionally probes alias filenames produced by KAPE/Velociraptor.
ARTIFACTS: dict[str, tuple[str, str]] = {
    "security": ("security.evtx.jsonl", "jsonl"),
    "sysmon": ("sysmon.evtx.jsonl", "jsonl"),
    "powershell": ("powershell.evtx.jsonl", "jsonl"),
    "prefetch": ("prefetch.csv", "csv"),
    "amcache": ("amcache.csv", "csv"),
    "registry_run": ("registry_run.csv", "csv"),
    "scheduled_tasks": ("scheduled_tasks.csv", "csv"),
    "services": ("services.csv", "csv"),
    "wmi": ("wmi.csv", "csv"),
    "netflow": ("netflow.csv", "csv"),
    "mft": ("mft_timeline.csv", "csv"),
    "usb": ("usb.csv", "csv"),
    "filemod": ("filemod.csv", "csv"),
    "threat_intel": ("threat_intel.csv", "csv"),
    # Linux artifacts (web-server compromise case)
    "auth_log": ("auth_log.jsonl", "jsonl"),
    "bash_history": ("bash_history.csv", "csv"),
    "web_access": ("web_access.jsonl", "jsonl"),
    "linux_proc": ("linux_proc.jsonl", "jsonl"),
    "cron": ("cron.csv", "csv"),
}


class EvidenceSource(Protocol):
    """Anything that can yield logical artifacts as lists of EvidenceRecords."""

    def load(self) -> dict[str, list[EvidenceRecord]]:
        """Return {artifact_name: [EvidenceRecord, ...]} (read-only)."""
        ...

    @property
    def label(self) -> str:
        ...


# ---------------------------------------------------------------------------
# helpers shared by both sources
# ---------------------------------------------------------------------------

def _load_jsonl(name: str, fname: str, path: str) -> list[EvidenceRecord]:
    out: list[EvidenceRecord] = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            row = int(obj.get("row", i))
            obj.setdefault("row", row)
            out.append(EvidenceRecord(ref=f"{fname}:{row}", artifact=name,
                                      source_file=fname, row=row, data=obj))
    return out


def _load_csv(name: str, fname: str, path: str,
              colmap: dict[str, str] | None = None) -> list[EvidenceRecord]:
    out: list[EvidenceRecord] = []
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for i, r in enumerate(reader, start=1):
            data = dict(r)
            if colmap:
                for src, dst in colmap.items():
                    if src in data and dst not in data:
                        data[dst] = data[src]
            row = int(data.get("row", i))
            data.setdefault("row", row)
            out.append(EvidenceRecord(ref=f"{fname}:{row}", artifact=name,
                                      source_file=fname, row=row, data=data))
    return out


# ---------------------------------------------------------------------------
# Synthetic (default, offline)
# ---------------------------------------------------------------------------

@dataclass
class SyntheticSource:
    """Offline loader over the synthetic evidence artifacts of one case."""

    case_dir: str

    @property
    def label(self) -> str:
        return "synthetic"

    def load(self) -> dict[str, list[EvidenceRecord]]:
        records: dict[str, list[EvidenceRecord]] = {}
        for name, (fname, fmt) in ARTIFACTS.items():
            path = os.path.join(self.case_dir, fname)
            if not os.path.exists(path):
                records[name] = []
                continue
            records[name] = (_load_jsonl(name, fname, path) if fmt == "jsonl"
                             else _load_csv(name, fname, path))
        return records


# ---------------------------------------------------------------------------
# Live triage collection (KAPE / Velociraptor / SIFT-style output)
# ---------------------------------------------------------------------------

# For each logical artifact, candidate filenames a real triage tool emits, plus
# a column-name map normalising the tool's headers to our schema field names.
# (KAPE's EvtxECmd / Registry / PECmd / AmcacheParser / MFTECmd outputs.)
_LIVE_PROBES: dict[str, list[tuple[str, str, dict[str, str]]]] = {
    "sysmon": [
        ("sysmon.evtx.jsonl", "jsonl", {}),
        ("Microsoft-Windows-Sysmon%4Operational.json", "jsonl",
         {"Image": "image", "ParentImage": "parent_image",
          "CommandLine": "cmdline", "ProcessId": "pid",
          "ParentProcessId": "parent_pid", "DestinationIp": "dest_ip",
          "DestinationPort": "dest_port", "DestinationHostname": "dest_host",
          "TargetFilename": "target_file", "TargetObject": "target_object",
          "Details": "details", "User": "user", "EventID": "event_id",
          "UtcTime": "time_utc"}),
    ],
    "security": [
        ("security.evtx.jsonl", "jsonl", {}),
        ("Security.json", "jsonl",
         {"EventID": "event_id", "IpAddress": "source_ip",
          "TargetUserName": "account", "LogonType": "logon_type",
          "TimeCreated": "time_utc"}),
    ],
    "powershell": [
        ("powershell.evtx.jsonl", "jsonl", {}),
        ("Microsoft-Windows-PowerShell%4Operational.json", "jsonl",
         {"EventID": "event_id", "ScriptBlockText": "script_block",
          "TimeCreated": "time_utc"}),
    ],
    "prefetch": [
        ("prefetch.csv", "csv", {}),
        ("*_PECmd_Output.csv", "csv",
         {"ExecutableName": "executable", "LastRun": "last_run_utc",
          "RunCount": "run_count", "SourceFilename": "prefetch_file"}),
    ],
    "amcache": [
        ("amcache.csv", "csv", {}),
        ("*_Amcache_*.csv", "csv",
         {"FullPath": "path", "SHA1": "sha1", "FileKeyLastWriteTimestamp": "first_seen_utc"}),
    ],
    "mft": [
        ("mft_timeline.csv", "csv", {}),
        ("*_MFTECmd_*.csv", "csv",
         {"ParentPath": "path", "FileName": "path",
          "Created0x10": "created_utc", "LastModified0x10": "modified_utc",
          "FileSize": "size_bytes"}),
    ],
    "registry_run": [("registry_run.csv", "csv", {})],
    "scheduled_tasks": [("scheduled_tasks.csv", "csv", {})],
    "services": [("services.csv", "csv", {})],
    "wmi": [("wmi.csv", "csv", {})],
    "netflow": [("netflow.csv", "csv", {})],
    "usb": [("usb.csv", "csv", {})],
    "filemod": [("filemod.csv", "csv", {})],
    "threat_intel": [("threat_intel.csv", "csv", {})],
    "auth_log": [("auth_log.jsonl", "jsonl", {})],
    "bash_history": [("bash_history.csv", "csv", {})],
    "web_access": [("web_access.jsonl", "jsonl", {})],
    "linux_proc": [("linux_proc.jsonl", "jsonl", {})],
    "cron": [("cron.csv", "csv", {})],
}


@dataclass
class LiveTriageSource:
    """Read a real KAPE/Velociraptor/SIFT-style triage directory, read-only.

    The directory is walked once; for each logical artifact the first matching
    candidate file (exact name or ``*glob*``) is loaded and its columns are
    normalised into our schema. Threat-intel is read from a local
    ``threat_intel.csv`` if present (offline OSINT export) so scoring still
    works without network access.
    """

    live_dir: str
    _index: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"live:{self.live_dir}"

    def _build_index(self) -> None:
        """Map basename -> absolute path for every file under live_dir."""
        for root, _dirs, files in os.walk(self.live_dir):
            for fn in files:
                # first occurrence wins; deeper KAPE trees rarely collide
                self._index.setdefault(fn, os.path.join(root, fn))

    def _find(self, pattern: str) -> str | None:
        if not self._index:
            self._build_index()
        if "*" not in pattern:
            return self._index.get(pattern)
        import fnmatch
        for name, path in self._index.items():
            if fnmatch.fnmatch(name, pattern):
                return path
        return None

    def load(self) -> dict[str, list[EvidenceRecord]]:
        if not os.path.isdir(self.live_dir):
            raise FileNotFoundError(f"live triage dir not found: {self.live_dir}")
        records: dict[str, list[EvidenceRecord]] = {}
        for name in ARTIFACTS:
            records[name] = []
            for fname, fmt, colmap in _LIVE_PROBES.get(name, [(ARTIFACTS[name][0], ARTIFACTS[name][1], {})]):
                path = self._find(fname)
                if not path:
                    continue
                disk_name = os.path.basename(path)
                if fmt == "jsonl":
                    recs = _load_jsonl(name, disk_name, path)
                    if colmap:  # normalise nested EVTX field names
                        recs = [_apply_colmap(rec, colmap) for rec in recs]
                else:
                    recs = _load_csv(name, disk_name, path, colmap)
                records[name] = recs
                break
        return records


def _apply_colmap(rec: EvidenceRecord, colmap: dict[str, str]) -> EvidenceRecord:
    data = dict(rec.data)
    for src, dst in colmap.items():
        if src in data and dst not in data:
            data[dst] = data[src]
    return EvidenceRecord(ref=rec.ref, artifact=rec.artifact,
                          source_file=rec.source_file, row=rec.row, data=data)


# ---------------------------------------------------------------------------
# selector
# ---------------------------------------------------------------------------

def make_source(case_dir: str) -> EvidenceSource:
    """Return the live triage source if ``FIND_EVIL_LIVE_DIR`` is set,
    otherwise the offline synthetic source. This is the one-line switch the
    agent uses; nothing else in the pipeline changes between modes."""
    live = os.environ.get("FIND_EVIL_LIVE_DIR")
    if live:
        return LiveTriageSource(live)
    return SyntheticSource(case_dir)
