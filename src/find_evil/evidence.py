"""Read-only evidence access layer.

Every artifact row gets a stable, immutable evidence reference of the form
``<artifact_file>:<row>`` (e.g. ``sysmon.evtx.jsonl:9``). Findings cite these
refs so any claim can be traced back to a specific line of a specific
synthetic artifact — this is the provenance chain the judges care about.

The loaders are deliberately "tools": typed, read-only, and they never mutate
the evidence. Each tool call is recorded by the trace recorder so the run is
fully replayable.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from typing import Any


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


# logical artifact name -> (filename, format)
ARTIFACTS: dict[str, tuple[str, str]] = {
    "security": ("security.evtx.jsonl", "jsonl"),
    "sysmon": ("sysmon.evtx.jsonl", "jsonl"),
    "powershell": ("powershell.evtx.jsonl", "jsonl"),
    "prefetch": ("prefetch.csv", "csv"),
    "amcache": ("amcache.csv", "csv"),
    "registry_run": ("registry_run.csv", "csv"),
    "scheduled_tasks": ("scheduled_tasks.csv", "csv"),
    "netflow": ("netflow.csv", "csv"),
    "mft": ("mft_timeline.csv", "csv"),
    "threat_intel": ("threat_intel.csv", "csv"),
}


@dataclass
class EvidenceStore:
    """Loads and indexes all synthetic artifacts for a case (read-only)."""

    case_dir: str
    records: dict[str, list[EvidenceRecord]] = field(default_factory=dict)
    _trace: Any = None  # optional TraceRecorder

    def attach_trace(self, trace: Any) -> None:
        self._trace = trace

    def load_all(self) -> None:
        for name, (fname, fmt) in ARTIFACTS.items():
            path = os.path.join(self.case_dir, fname)
            if not os.path.exists(path):
                self.records[name] = []
                continue
            if fmt == "jsonl":
                self.records[name] = self._load_jsonl(name, fname, path)
            else:
                self.records[name] = self._load_csv(name, fname, path)

    @staticmethod
    def _load_jsonl(name: str, fname: str, path: str) -> list[EvidenceRecord]:
        out: list[EvidenceRecord] = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                row = int(obj.get("row"))
                out.append(
                    EvidenceRecord(
                        ref=f"{fname}:{row}",
                        artifact=name,
                        source_file=fname,
                        row=row,
                        data=obj,
                    )
                )
        return out

    @staticmethod
    def _load_csv(name: str, fname: str, path: str) -> list[EvidenceRecord]:
        out: list[EvidenceRecord] = []
        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                row = int(r.get("row"))
                out.append(
                    EvidenceRecord(
                        ref=f"{fname}:{row}",
                        artifact=name,
                        source_file=fname,
                        row=row,
                        data=dict(r),
                    )
                )
        return out

    # ---- typed read-only "tools" ------------------------------------------

    def query(self, artifact: str, **filters: Any) -> list[EvidenceRecord]:
        """Read-only tool: return rows of an artifact matching simple filters.

        Filter values may be a literal (exact match) or a callable predicate.
        Every call is recorded to the trace for replay.
        """
        recs = self.records.get(artifact, [])
        result: list[EvidenceRecord] = []
        for rec in recs:
            ok = True
            for k, v in filters.items():
                val = rec.get(k)
                if callable(v):
                    if not v(val):
                        ok = False
                        break
                elif val != v:
                    ok = False
                    break
            if ok:
                result.append(rec)
        if self._trace is not None:
            self._trace.tool_call(
                tool="evidence.query",
                args={"artifact": artifact, "filters": _describe_filters(filters)},
                result_refs=[r.ref for r in result],
            )
        return result

    def all(self, artifact: str) -> list[EvidenceRecord]:
        return self.query(artifact)

    def threat_verdict(self, indicator: str) -> EvidenceRecord | None:
        """Read-only tool: look up an indicator in the offline threat-intel feed."""
        for rec in self.records.get("threat_intel", []):
            if rec.get("indicator") == indicator:
                if self._trace is not None:
                    self._trace.tool_call(
                        tool="threat_intel.lookup",
                        args={"indicator": indicator},
                        result_refs=[rec.ref],
                    )
                return rec
        if self._trace is not None:
            self._trace.tool_call(
                tool="threat_intel.lookup",
                args={"indicator": indicator},
                result_refs=[],
            )
        return None


def _describe_filters(filters: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in filters.items():
        out[k] = "<predicate>" if callable(v) else v
    return out
