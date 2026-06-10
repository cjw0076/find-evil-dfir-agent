"""Read-only evidence access layer.

Every artifact row gets a stable, immutable evidence reference of the form
``<artifact_file>:<row>`` (e.g. ``sysmon.evtx.jsonl:9``). Findings cite these
refs so any claim can be traced back to a specific line of a specific
artifact — this is the provenance chain the judges care about.

The ``EvidenceStore`` is a thin, typed, read-only query surface over whatever
``EvidenceSource`` produced the records (synthetic by default, live triage
when ``FIND_EVIL_LIVE_DIR`` is set — see ``backends.py``). It never mutates the
evidence, and every tool call is recorded by the trace recorder so the run is
fully replayable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .backends import ARTIFACTS, EvidenceRecord, EvidenceSource, make_source

__all__ = ["EvidenceRecord", "EvidenceStore", "ARTIFACTS"]


@dataclass
class EvidenceStore:
    """Loads and indexes all artifacts for a case via an EvidenceSource."""

    case_dir: str
    source: EvidenceSource | None = None
    records: dict[str, list[EvidenceRecord]] = field(default_factory=dict)
    _trace: Any = None  # optional TraceRecorder

    def attach_trace(self, trace: Any) -> None:
        self._trace = trace

    def load_all(self) -> None:
        src = self.source or make_source(self.case_dir)
        self.source = src
        self.records = src.load()
        # guarantee every known artifact key exists (empty list if absent)
        for name in ARTIFACTS:
            self.records.setdefault(name, [])

    @property
    def source_label(self) -> str:
        return self.source.label if self.source else "uninitialised"

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

    def ref_index(self) -> dict[str, EvidenceRecord]:
        """All records keyed by their provenance ref (for citation resolution)."""
        return {rec.ref: rec for recs in self.records.values() for rec in recs}


def _describe_filters(filters: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in filters.items():
        out[k] = "<predicate>" if callable(v) else v
    return out
