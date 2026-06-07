"""Smoke + accuracy tests for the FIND EVIL! triage agent.

Run: PYTHONPATH=src python3 -m pytest tests/ -q
 or: PYTHONPATH=src python3 tests/test_agent.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from find_evil.agent import TriageAgent  # noqa: E402

CASE_DIR = os.path.join(ROOT, "data", "synthetic", "case-lab-01")


def _run():
    agent = TriageAgent(case_id="case-lab-01", case_dir=CASE_DIR)
    summary = agent.run()
    return agent, summary


def test_perfect_recall_and_decoy_rejected():
    _, summary = _run()
    acc = summary["accuracy"]
    assert acc["scored"]
    assert acc["recall"] == 1.0, f"recall {acc['recall']}, missed {acc['missed']}"
    assert acc["precision"] == 1.0
    assert acc["decoy_rejected"] is True


def test_every_alert_has_evidence_refs():
    agent, _ = _run()
    alerts = [r for r in agent.ledger.records if r["event_type"] == "alert"]
    assert alerts
    for r in alerts:
        assert r["evidence_refs"], f"{r['evidence_id']} missing evidence_refs"
        assert r["evidence_pointer"]


def test_evidence_refs_resolve_to_real_rows():
    agent, _ = _run()
    valid = {rec.ref for recs in agent.es.records.values() for rec in recs}
    for r in agent.ledger.records:
        for ref in r["evidence_refs"]:
            assert ref in valid, f"{r['evidence_id']} cites non-existent {ref}"


def test_self_correction_present_in_trace():
    agent, _ = _run()
    kinds = [s["kind"] for s in agent.trace.steps]
    assert "hypothesis" in kinds
    assert "contradiction" in kinds
    assert "self_correction" in kinds


def test_ledger_schema_required_fields():
    agent, _ = _run()
    required = {"evidence_id", "case_id", "event_time_utc", "event_type",
               "source", "summary", "severity", "owner", "status", "notes"}
    for r in agent.ledger.records:
        assert required.issubset(r.keys()), r["evidence_id"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\nAll {len(fns)} tests passed.")
