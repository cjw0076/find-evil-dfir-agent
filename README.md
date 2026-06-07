# FIND EVIL! — Evidence-Linked DFIR Triage Agent

- status: working synthetic MVP (demo-ready)
- official_url: https://findevil.devpost.com/
- rules_url: https://findevil.devpost.com/rules
- deadline: 2026-06-15 23:45 EDT (internal freeze 2026-06-13 KST)
- prize: $22,000+ cash plus SANS benefits
- domain: cybersecurity / autonomous incident response (DFIR)
- license: MIT (see `LICENSE`)

## What this is

An **autonomous DFIR triage agent** that ingests synthetic Windows forensic
artifacts, reasons over them, and produces an **evidence-linked finding ledger**
where every claim cites the exact artifact row that justifies it. It
demonstrates the things SANS' FIND EVIL! judges reward:

- **Evidence provenance** — every finding carries `evidence_refs` like
  `sysmon.evtx.jsonl:9`, traceable to a single line of a single artifact.
- **Self-correction** — the agent forms a tempting-but-wrong first hypothesis
  ("internet brute-force got in"), finds a contradiction in the evidence, and
  corrects itself to the real phishing-macro execution chain.
- **Analytical reasoning, not command transcripts** — hypothesis →
  contradiction → self-correction → findings → containment → verification.
- **Tool sequencing** — typed, read-only evidence "tools" (the MCP/SIFT analog),
  every call recorded for replay.
- **Forensic auditability** — append-only ledger + a replayable execution trace.
- **Accuracy validation** — self-scores against a synthetic ground truth
  (recall / precision / decoy-rejected).

> **Synthetic data only.** No real host, no malware samples, no secrets. All
> IPs/domains/hashes are RFC 5737 / placeholder values, safe to publish. When a
> real SIFT / Protocol SIFT read-only evidence mount is available, the same
> schema and detectors run unchanged — only the loaders in
> `src/find_evil/evidence.py` point at live artifacts.

## Run the demo (one command, stdlib Python only)

```bash
./run_demo.sh
# or explicitly:
PYTHONPATH=src python3 -m find_evil --case-dir data/synthetic/case-lab-01 --out out
```

Requires only Python 3.10+ (no pip installs). Outputs:

- `out/ledger.json` — the evidence-linked finding ledger (schema below)
- `out/trace.json` — the replayable execution trace (tool calls + reasoning)

Replay the recorded reasoning:

```bash
PYTHONPATH=src python3 -m find_evil --replay out/trace.json
```

Run the tests:

```bash
PYTHONPATH=src python3 tests/test_agent.py      # or: python3 -m pytest tests/ -q
```

## The synthetic case (case-lab-01)

Finance workstation `WIN-ACCT-07`. A phishing `.docm` opened by `acct.jlee`
spawns an encoded PowerShell download cradle that pulls a second-stage implant,
establishes persistence (Run key + scheduled task), dumps LSASS for credentials,
beacons to C2, and starts lateral movement to a file server. A decoy
internet brute-force burst is planted to test self-correction.

Mapped MITRE ATT&CK chain: T1566.001 → T1059.001 → T1071.001 → T1547.001 →
T1053.005 → T1003.001 → T1021.002.

Dataset + ground truth: `data/synthetic/case-lab-01/` (see its `README.md`).

## Architecture

```
data/synthetic/case-lab-01/*.{jsonl,csv}     synthetic forensic artifacts
        │  (read-only loaders = the SIFT/MCP tool layer)
        ▼
src/find_evil/evidence.py     EvidenceStore: typed read-only "tools",
                              stable provenance refs "<file>:<row>"
        ▼
src/find_evil/agent.py        TriageAgent loop:
   ingest → hypothesis(H1, wrong) → contradiction → self-correct(H2)
          → detectors → findings → containment → verification
        │            │
        │            ▼  src/find_evil/detections.py  (MITRE-mapped rules)
        ▼
src/find_evil/ledger.py       append-only evidence ledger (schema-conformant)
src/find_evil/trace.py        append-only replayable execution trace
        ▼
out/ledger.json   out/trace.json
```

## Ledger schema

Records conform to `docs/agent_evidence_ledger_schema.json`. Each finding adds
`evidence_refs` (full provenance chain), `mitre_attack`, `iocs`, and
`recommendation`. Records are append-only and never edited.

## Status / blockers

- Working synthetic MVP: end-to-end run, 7/7 MITRE techniques recovered,
  decoy rejected, recall=precision=1.0 on the synthetic ground truth.
- Founder-only gates (NOT done by the build agent): register on Devpost,
  publish the public repo, record the demo video, attach real SIFT/Protocol
  SIFT evidence if/when access is granted.

## Immediate Tasks (remaining)

1. (founder) Register on Devpost; publish repo under MIT.
2. (founder) Record <5-min demo video from `docs/demo_script_5min_terminal.md`.
3. (eng, optional) Swap synthetic loaders for a live SIFT read-only mount.
