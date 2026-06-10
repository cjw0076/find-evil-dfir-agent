"""Rigorous evaluation harness for the FIND EVIL! DFIR triage agent.

Runs the SAME agent across every synthetic case and reports a real benchmark
table from real runs - no hardcoded numbers. For each case it measures:

* recall          - fraction of ground-truth MITRE techniques the agent detected
* precision       - fraction of the agent's MITRE detections that map to a
                    ground-truth technique
* decoy_rejected  - did the agent form the planted decoy hypothesis and then
                    self-correct away from it (evidence-justified)?
* mitre_coverage  - matched vs expected techniques (e.g. "4/4")
* steps_to_root   - mean-steps-to-root-cause: the number of read-only evidence
                    tool calls the agent ran up to and including the
                    self-correction (when the true vector is established)

Aggregates are macro-averaged across cases. Output: a console table plus a
machine-readable JSON report (``eval/report.json`` by default). Exits non-zero
if any case regresses below perfect recall/precision/decoy, so the eval doubles
as a CI gate.

Usage:
    PYTHONPATH=src python3 eval/run_eval.py [--json eval/report.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from find_evil.agent import TriageAgent  # noqa: E402

DATA_DIR = os.path.join(ROOT, "data", "synthetic")


def discover_cases() -> list[str]:
    out = []
    for name in sorted(os.listdir(DATA_DIR)):
        d = os.path.join(DATA_DIR, name)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "manifest.json")):
            out.append(name)
    return out


def _steps_to_root(agent: TriageAgent) -> int:
    """Read-only evidence tool calls up to and including self-correction.

    An honest proxy for mean-time-to-root-cause: how many evidence queries the
    agent needed before it locked onto the true attack vector.
    """
    calls = 0
    for step in agent.trace.steps:
        if step["kind"] == "tool_call":
            calls += 1
        if step["kind"] == "self_correction":
            return calls
    return calls


def eval_case(case_id: str) -> dict:
    case_dir = os.path.join(DATA_DIR, case_id)
    agent = TriageAgent(case_id=case_id, case_dir=case_dir)
    summary = agent.run()
    acc = summary["accuracy"]
    total_calls = sum(1 for s in agent.trace.steps if s["kind"] == "tool_call")
    return {
        "case_id": case_id,
        "title": summary["title"],
        "platform": summary["platform"],
        "attack_class": summary["attack_class"],
        "recall": acc["recall"],
        "precision": acc["precision"],
        "decoy_rejected": acc["decoy_rejected"],
        "expected_techniques": acc["expected_techniques"],
        "detected_techniques": acc["detected_techniques"],
        "mitre_coverage": f"{len(acc['matched'])}/{acc['expected_techniques']}",
        "matched": acc["matched"],
        "missed": acc["missed"],
        "steps_to_root": _steps_to_root(agent),
        "total_tool_calls": total_calls,
        "detections": summary["detections"],
        "analyzers": summary["analyzers"],
        "ledger_records": summary["ledger_records"],
        "trace_steps": summary["trace_steps"],
        "evidence_source": agent.es.source_label,
    }


def aggregate(results: list[dict]) -> dict:
    n = len(results)

    def avg(key):
        return round(sum(r[key] for r in results) / n, 3) if n else 0.0

    all_tech = sorted({t for r in results for t in r["detected_techniques"]})
    return {
        "cases": n,
        "macro_recall": avg("recall"),
        "macro_precision": avg("precision"),
        "decoy_rejection_rate": round(
            sum(1 for r in results if r["decoy_rejected"]) / n, 3) if n else 0.0,
        "mean_steps_to_root_cause": avg("steps_to_root"),
        "distinct_mitre_techniques": all_tech,
        "distinct_mitre_count": len(all_tech),
    }


_C = {"h": "\033[1;36m", "ok": "\033[1;32m", "bad": "\033[1;31m",
      "dim": "\033[2m", "x": "\033[0m"}


def _color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(key, text):
    return f"{_C[key]}{text}{_C['x']}" if _color() else text


def print_table(results: list[dict], agg: dict) -> None:
    print(c("h", "\n== FIND EVIL! - EVALUATION ACROSS ALL CASES ==\n"))
    hdr = (f"{'case':<20}{'class':<20}{'plat':<8}{'recall':>7}{'prec':>6}"
           f"{'decoy':>7}{'mitre':>7}{'steps':>7}")
    print(c("dim", hdr))
    print(c("dim", "-" * len(hdr)))
    for r in results:
        print(f"{r['case_id']:<20}{r['attack_class']:<20}{r['platform']:<8}"
              f"{r['recall']:>7}{r['precision']:>6}"
              f"{('yes' if r['decoy_rejected'] else 'NO'):>7}"
              f"{r['mitre_coverage']:>7}{r['steps_to_root']:>7}")
    print(c("dim", "-" * len(hdr)))
    print(f"{'AGGREGATE (macro avg)':<48}"
          f"{agg['macro_recall']:>7}{agg['macro_precision']:>6}"
          f"{int(agg['decoy_rejection_rate']*100):>6}%"
          f"{'':>7}{agg['mean_steps_to_root_cause']:>7}")
    print()
    print(f"  cases evaluated            : {agg['cases']}")
    print(f"  macro recall / precision   : {agg['macro_recall']} / {agg['macro_precision']}")
    print(f"  decoy rejection rate       : {int(agg['decoy_rejection_rate']*100)}%")
    print(f"  mean steps-to-root-cause   : {agg['mean_steps_to_root_cause']} (evidence tool calls)")
    print(f"  distinct MITRE techniques  : {agg['distinct_mitre_count']} "
          f"({', '.join(agg['distinct_mitre_techniques'])})")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Evaluate the agent across all cases.")
    p.add_argument("--json", default=os.path.join(ROOT, "eval", "report.json"),
                   help="path to write the JSON benchmark report")
    args = p.parse_args(argv)

    cases = discover_cases()
    results = [eval_case(cid) for cid in cases]
    agg = aggregate(results)
    print_table(results, agg)

    report = {
        "schema": "find_evil_eval/1.0",
        "synthetic": True,
        "aggregate": agg,
        "cases": results,
    }
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(c("ok", f"JSON report written: {args.json}"))

    ok = all(r["recall"] == 1.0 and r["precision"] == 1.0 and r["decoy_rejected"]
             for r in results)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
