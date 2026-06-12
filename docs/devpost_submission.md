# Devpost submission — FIND EVIL! Evidence-Linked DFIR Triage Agent

> SYNTHETIC DATA ONLY. No real host, no malware samples, no secrets. All IPs /
> domains / hashes are RFC 5737 / EICAR-style placeholders, safe to publish.
> Evidence is read-only; the agent is recommendation-only (no auto-execution).

## Inspiration

In a real intrusion, the bottleneck is not collecting artifacts — it is
**reasoning** over them under time pressure without fooling yourself. The
dangerous moment in DFIR is the *plausible-but-wrong* first story: the auth log
is full of failed root logins, so you "know" it was an internet brute-force —
and you miss the leaked key that actually got in. We wanted an agent that
reasons out loud, **cites the exact evidence row for every claim**, and is built
to *catch itself* when the obvious story contradicts the evidence.

## What it does

Given a triage collection, one case-agnostic agent:

1. **Ingests forensic artifacts** (Sysmon/EVTX, auth logs, web logs, USB/registry
   artifacts) read-only and builds a super-timeline.
2. **Forms a first hypothesis** and then **tries to refute it** with real
   read-only analyzers — finding the contradiction and **self-correcting** to the
   true attack chain. **100% decoy-rejection across 5 cases.**
3. **Runs 7 genuine forensic analyzers**: super-timeline fusion, process-tree
   reconstruction, persistence sweep, LOLBin detection, encoded-PowerShell
   decoding, IOC extraction + threat-intel correlation, lateral-movement graph.
4. **Emits an evidence-linked finding ledger** — every finding carries
   `evidence_refs` like `sysmon.evtx.jsonl:9`, traceable to one line of one
   artifact; the web console makes each ref clickable to the raw row.
5. **Maps each finding to MITRE ATT&CK** and self-scores against ground truth.

## How we built it

- Core agent / detectors / analyzers / eval are **stdlib Python 3.10+** (no pip
  for the core) — maximally reproducible for judges. Only the web console needs
  fastapi/uvicorn.
- A per-case `manifest.json` drives one **case-agnostic** agent across five
  distinct intrusion classes (Windows + Linux), each with `ground_truth.json`
  and a **planted, mechanically-refutable decoy**.
- An **append-only ledger + replayable execution trace** give forensic
  auditability; a real **eval harness** (`eval/run_eval.py`) scores recall,
  precision, decoy-rejection, MITRE coverage and steps-to-root-cause, and exits
  non-zero on any regression (doubles as a CI gate).
- A **live seam** (`src/find_evil/backends.py`): point `FIND_EVIL_LIVE_DIR` at a
  real KAPE/Velociraptor/SIFT collection and the *same* agent runs unchanged.

## Accomplishments / results (real numbers from real runs)

`PYTHONPATH=src python3 eval/run_eval.py` over the whole 5-case library:

| metric | value |
|---|---|
| macro recall / precision | **1.0 / 1.0** |
| decoy-rejection rate | **100%** (5/5) |
| distinct MITRE techniques exercised | **16** |
| mean steps-to-root-cause | 6.4 evidence tool-calls |
| cases (Windows + Linux) | 5 |

## Challenges we ran into

Making self-correction *real* rather than theatrical: each decoy is engineered to
be mechanically refutable from evidence alone (no successful logon from a
benign-rated scanner IP; an EICAR test file; a sanctioned helpdesk/cloud-backup
host), so the correction is evidence-justified, not scripted.

## What we learned

Provenance is the product. Once every claim must cite a single artifact line, the
agent stops hand-waving and the analysis becomes defensible in an incident review.

## Try it (judges)

```bash
./run_demo.sh data/synthetic/case-ransom-02     # one case end-to-end, stdlib only
PYTHONPATH=src python3 eval/run_eval.py          # whole-library benchmark
./run_dashboard.sh                               # web triage console → :8000
PYTHONPATH=src python3 -m pytest tests/ -q        # 34 tests
```

## Devpost form fields
- **Project name**: FIND EVIL! — Evidence-Linked DFIR Triage Agent
- **Tagline**: An autonomous DFIR triage agent that triages Windows & Linux intrusions, cites the exact evidence row for every finding, and self-corrects past planted decoys — 1.0/1.0 recall/precision, 100% decoy rejection across 5 cases.
- **Tags**: dfir, incident-response, forensics, mitre-attack, evidence-provenance, self-correction, security, python
- **Built with**: python, fastapi, mitre-attack, sysmon, evtx
