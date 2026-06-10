"""FastAPI backend for the FIND EVIL! DFIR triage dashboard.

Runs a real investigation (the same case-agnostic ``TriageAgent`` over synthetic
evidence, zero credentials) and exposes its structured output so the single-page
frontend can visualise: the alert/trigger, the agent's hypothesis ->
contradiction -> self-correction narrative, each forensic analyzer's output, the
MITRE ATT&CK findings with clickable evidence-row citations, the reconstructed
process tree, the fused attack timeline, the IOC list, and the replayable trace.

Endpoints (all read-only, synthetic):
    GET  /                       -> the dashboard SPA
    GET  /api/cases              -> list of available synthetic cases
    GET  /api/investigate/{id}   -> full structured investigation result
    GET  /api/evidence/{id}/{ref}-> resolve a single evidence ref to its row
    GET  /api/health             -> liveness

Run:
    PYTHONPATH=src uvicorn webapp.server:app --port 8000
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402

from find_evil.agent import TriageAgent  # noqa: E402

DATA_DIR = os.path.join(ROOT, "data", "synthetic")
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="FIND EVIL! DFIR Triage", version="2.0.0")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _cases() -> list[dict]:
    out = []
    for name in sorted(os.listdir(DATA_DIR)):
        d = os.path.join(DATA_DIR, name)
        manifest = os.path.join(d, "manifest.json")
        if not (os.path.isdir(d) and os.path.exists(manifest)):
            continue
        with open(manifest, encoding="utf-8") as fh:
            m = json.load(fh)
        out.append({"id": name, "title": m.get("title", name),
                    "platform": m.get("platform", "windows"),
                    "attack_class": m.get("attack_class", "-")})
    return out


def _investigate(case_id: str) -> dict:
    case_dir = os.path.join(DATA_DIR, case_id)
    if not os.path.isdir(case_dir):
        raise HTTPException(status_code=404, detail=f"unknown case {case_id}")
    agent = TriageAgent(case_id=case_id, case_dir=case_dir)
    summary = agent.run()

    # artifact histogram for the ingest panel
    by_art = {k: len(v) for k, v in agent.es.records.items() if v}

    # reasoning narrative (hypothesis/contradiction/self-correction) from trace
    narrative = []
    for s in agent.trace.steps:
        if s["kind"] in ("hypothesis", "contradiction", "self_correction"):
            narrative.append(s)

    # full replayable trace (compact)
    trace = []
    for s in agent.trace.steps:
        e = {"step": s["step"], "kind": s["kind"], "ts": s["ts_wall_utc"]}
        for k in ("tool", "args", "result_count", "result_refs", "hypothesis_id",
                  "statement", "confidence", "reason", "evidence_refs", "from_hypothesis",
                  "to_statement", "rationale", "evidence_id", "label", "analyzer",
                  "summary", "text"):
            if k in s:
                e[k] = s[k]
        trace.append(e)

    findings = []
    for rec in agent.ledger.records:
        if rec["event_type"] != "alert":
            continue
        findings.append({
            "evidence_id": rec["evidence_id"],
            "mitre": rec.get("mitre_attack", "-"),
            "severity": rec["severity"],
            "summary": rec["summary"],
            "evidence_refs": rec["evidence_refs"],
            "iocs": rec.get("iocs", []),
            "recommendation": rec.get("recommendation", ""),
        })

    analyzers = {name: res.to_dict() for name, res in agent.analyzer_results.items()}

    containment = []
    for rec in agent.ledger.records:
        if rec["event_type"] == "containment" and rec.get("recommendation"):
            containment = rec["recommendation"].split("; ")

    return {
        "case_id": case_id,
        "title": summary["title"],
        "platform": summary["platform"],
        "attack_class": summary["attack_class"],
        "alert": agent.manifest.get("alert", {}),
        "artifacts": by_art,
        "evidence_rows": sum(by_art.values()),
        "evidence_source": agent.es.source_label,
        "narrative": narrative,
        "findings": findings,
        "analyzers": analyzers,
        "process_tree": analyzers.get("process_tree", {}),
        "timeline": analyzers.get("super_timeline", {}),
        "iocs": analyzers.get("extract_iocs", {}),
        "containment": containment,
        "accuracy": summary["accuracy"],
        "trace": trace,
        "ledger_records": summary["ledger_records"],
        "trace_steps": summary["trace_steps"],
    }


def _resolve_evidence(case_id: str, ref: str) -> dict:
    case_dir = os.path.join(DATA_DIR, case_id)
    if not os.path.isdir(case_dir):
        raise HTTPException(status_code=404, detail=f"unknown case {case_id}")
    from find_evil.evidence import EvidenceStore
    es = EvidenceStore(case_dir)
    es.load_all()
    rec = es.ref_index().get(ref)
    if not rec:
        raise HTTPException(status_code=404, detail=f"evidence ref not found: {ref}")
    return {"ref": rec.ref, "artifact": rec.artifact,
            "source_file": rec.source_file, "row": rec.row, "data": rec.data}


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "cases": len(_cases()), "synthetic": True}


@app.get("/api/cases")
def cases():
    return {"cases": _cases()}


@app.get("/api/investigate/{case_id}")
def investigate(case_id: str):
    return JSONResponse(_investigate(case_id))


@app.get("/api/evidence/{case_id}/{ref}")
def evidence(case_id: str, ref: str):
    return JSONResponse(_resolve_evidence(case_id, ref))


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as fh:
        return fh.read()
