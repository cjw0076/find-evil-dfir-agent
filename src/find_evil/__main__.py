"""CLI: run the FIND EVIL! triage agent on a synthetic case and emit artifacts.

Usage:
    python -m find_evil --case-dir data/synthetic/case-lab-01 --out out
    python -m find_evil --replay out/trace.json     # replay a recorded run
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .agent import TriageAgent

# ANSI colors (auto-disabled when not a TTY)
_C = {
    "h": "\033[1;36m", "ok": "\033[1;32m", "warn": "\033[1;33m",
    "bad": "\033[1;31m", "dim": "\033[2m", "x": "\033[0m",
}


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(key: str, text: str) -> str:
    if not _color_enabled():
        return text
    return f"{_C[key]}{text}{_C['x']}"


def _rule(title: str) -> None:
    print()
    print(c("h", f"== {title} " + "=" * max(0, 56 - len(title))))


def run_demo(case_dir: str, out_dir: str) -> int:
    case_id = os.path.basename(os.path.normpath(case_dir))
    os.makedirs(out_dir, exist_ok=True)

    print(c("h", "FIND EVIL! — Evidence-Linked DFIR Triage Agent"))
    print(c("dim", "SYNTHETIC DATA ONLY — no real host, no malware, no secrets."))
    print(c("dim", f"Case: {case_id}   Evidence dir: {case_dir}"))

    agent = TriageAgent(case_id=case_id, case_dir=case_dir)
    summary = agent.run()

    _rule("REASONING (hypothesis -> contradiction -> self-correction)")
    for s in agent.trace.steps:
        if s["kind"] == "hypothesis":
            print(c("warn", f"  [HYPOTHESIS {s['hypothesis_id']}] (conf={s['confidence']})"))
            print(f"    {s['statement']}")
        elif s["kind"] == "contradiction":
            print(c("bad", f"  [CONTRADICTION on {s['hypothesis_id']}]"))
            print(f"    reason: {s['reason']}")
            print(c("dim", f"    evidence: {', '.join(s['evidence_refs'])}"))
        elif s["kind"] == "self_correction":
            print(c("ok", f"  [SELF-CORRECT {s['from_hypothesis']} -> new]"))
            print(f"    {s['to_statement']}")
            print(c("dim", f"    rationale: {s['rationale']}"))

    _rule("EVIDENCE-LINKED FINDINGS (every claim cites artifact rows)")
    for rec in agent.ledger.records:
        if rec["event_type"] != "alert":
            continue
        sev = rec["severity"].upper()
        sev_c = "bad" if sev in ("CRITICAL", "HIGH") else "warn"
        print(c(sev_c, f"  [{sev}] {rec.get('mitre_attack','-')}  {rec['evidence_id']}"))
        print(f"    {rec['summary']}")
        print(c("dim", f"    evidence_refs: {rec['evidence_pointer']}"))
        if rec.get("iocs"):
            print(c("dim", f"    IOCs: {', '.join(rec['iocs'])}"))
        print(c("dim", f"    action: {rec['recommendation']}"))

    _rule("CONTAINMENT PLAYBOOK (recommendation-only)")
    for rec in agent.ledger.records:
        if rec["event_type"] == "containment":
            for line in rec["recommendation"].split("; "):
                print(c("ok", f"  - {line}"))

    _rule("FORENSIC ANALYZERS (breadth-of-analysis, evidence-cited)")
    for name, res in agent.analyzer_results.items():
        print(c("warn", f"  [{name}] {res.summary}"))

    _rule("ACCURACY SELF-CHECK (vs synthetic ground truth)")
    acc = summary["accuracy"]
    if acc.get("scored"):
        print(f"  techniques matched : {len(acc['matched'])}/{acc['expected_techniques']}")
        print(f"  recall             : {acc['recall']}")
        print(f"  precision          : {acc['precision']}")
        dr = acc["decoy_rejected"]
        print(f"  decoy rejected     : {c('ok','YES') if dr else c('bad','NO')}")
        if acc["missed"]:
            print(c("warn", f"  missed             : {', '.join(acc['missed'])}"))

    # write artifacts
    ledger_path = os.path.join(out_dir, "ledger.json")
    trace_path = os.path.join(out_dir, "trace.json")
    agent.ledger.write(ledger_path)
    agent.trace.write(trace_path)

    _rule("ARTIFACTS WRITTEN")
    print(f"  ledger : {ledger_path}  ({len(agent.ledger.records)} records)")
    print(f"  trace  : {trace_path}  ({len(agent.trace.steps)} steps, replayable)")
    print()
    print(c("ok", f"DONE — {summary['detections']} findings, final hypothesis "
                  f"{summary['final_hypothesis']}, decoy rejected via self-correction."))
    return 0


def replay(trace_path: str) -> int:
    with open(trace_path, encoding="utf-8") as fh:
        tr = json.load(fh)
    print(c("h", f"REPLAY — case {tr['case_id']} — {tr['total_steps']} steps"))
    for s in tr["steps"]:
        tag = s["kind"].upper()
        line = f"  #{s['step']:>2} [{tag}]"
        if s["kind"] == "tool_call":
            line += f" {s['tool']} args={s['args']} -> {s['result_count']} rows"
            if s["result_refs"]:
                line += c("dim", f"  refs={', '.join(s['result_refs'][:6])}")
        elif s["kind"] == "hypothesis":
            line += f" {s['hypothesis_id']} (conf={s['confidence']}): {s['statement']}"
        elif s["kind"] == "contradiction":
            line += f" {s['hypothesis_id']}: {s['reason']}"
        elif s["kind"] == "self_correction":
            line += f" {s['from_hypothesis']} -> {s['to_statement']}"
        elif s["kind"] == "finding":
            line += f" {s['evidence_id']} {s['label']} refs={', '.join(s['evidence_refs'])}"
        elif s["kind"] == "note":
            line += f" {s['text']}"
        print(line)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="find_evil",
                                description="Evidence-linked DFIR triage agent (synthetic).")
    p.add_argument("--case-dir", default="data/synthetic/case-lab-01",
                   help="directory of synthetic evidence artifacts")
    p.add_argument("--out", default="out", help="output directory for ledger/trace")
    p.add_argument("--replay", metavar="TRACE_JSON",
                   help="replay a previously recorded trace.json and exit")
    args = p.parse_args(argv)
    if args.replay:
        return replay(args.replay)
    return run_demo(args.case_dir, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
