# 5-Minute Terminal Demo Script — FIND EVIL! DFIR Triage Agent

This script matches the **real, runnable** synthetic MVP. Every command below
works as-is with stdlib Python 3.10+; no network, no secrets, no real forensic
image. Record a <5-min screencast following these beats.

## Prep (off-camera)

```bash
cd find_evil_2026
ls data/synthetic/case-lab-01/          # synthetic forensic artifacts
cat data/synthetic/case-lab-01/README.md
```

## 0:00 – 0:30 | Frame the problem

Say: "FIND EVIL wants an *autonomous* DFIR agent whose every finding is
evidence-linked and that *self-corrects*. We run a full synthetic Windows
intrusion case end-to-end. Synthetic data only — but the schema and detectors
run unchanged on a real SIFT read-only mount."

Show the evidence directory:

```bash
ls -1 data/synthetic/case-lab-01/
```

## 0:30 – 1:15 | One command, full run

```bash
./run_demo.sh
```

Narrate as it prints: ingest → reasoning → findings → containment → accuracy.

## 1:15 – 2:30 | Self-correction (the differentiator)

Point at the REASONING block on screen:

- `[HYPOTHESIS H1]` — the agent's tempting first read: "external brute-force
  from 198.51.100.77 compromised Administrator."
- `[CONTRADICTION on H1]` — *from the evidence*: all logons from that IP are
  4625 failures (zero success) and threat intel rates the IP benign. Cites
  `security.evtx.jsonl:2,3` and `threat_intel.csv:4`.
- `[SELF-CORRECT H1 -> new]` — pivots to H2: phishing macro doc spawned an
  encoded PowerShell cradle (`sysmon.evtx.jsonl:2`).

Say: "The agent rejected the obvious-but-wrong story using evidence, not vibes."

## 2:30 – 3:45 | Evidence-linked findings

Point at the FINDINGS block. For each finding highlight:

- a MITRE technique (T1566.001 … T1021.002),
- a severity,
- `evidence_refs` pointing at exact artifact rows,
- IOCs and a concrete recommended action.

Then prove provenance is real, not decorative:

```bash
python3 -c "import json;d=json.load(open('out/ledger.json'));\
r=[x for x in d['records'] if x['event_type']=='alert'][5];\
print(r['summary']);print('refs:',r['evidence_pointer'])"
```

…then open the cited row directly:

```bash
sed -n '9p' data/synthetic/case-lab-01/sysmon.evtx.jsonl   # the comsvcs LSASS dump
```

Say: "Finding → ref → raw evidence line. That's the provenance chain."

## 3:45 – 4:30 | Audit trail / replay

```bash
PYTHONPATH=src python3 -m find_evil --replay out/trace.json | head -25
```

Say: "Every tool call and reasoning step is recorded with a step index, so the
whole investigation is replayable and auditable — Audit Trail Quality."

## 4:30 – 5:00 | Accuracy + honest scope

Point at ACCURACY SELF-CHECK: `7/7 techniques, recall=1.0, precision=1.0,
decoy rejected: YES`, scored against `ground_truth.json`.

```bash
PYTHONPATH=src python3 tests/test_agent.py
```

Close: "Synthetic today; the read-only loader is the only thing that changes for
a live SIFT / Protocol SIFT evidence mount. Recommendation-only — no action is
auto-executed; an analyst approves containment."

## Reset between takes

```bash
rm -rf out && ./run_demo.sh >/dev/null && echo "ready"
```
