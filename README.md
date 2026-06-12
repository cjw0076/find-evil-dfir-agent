# FIND EVIL! — Evidence-Linked DFIR Triage Agent

> **▶ Demo video:** [find_evil_demo.mp4](https://github.com/cjw0076/find-evil-dfir-agent/releases/download/demo-v1/find_evil_demo.mp4) — terminal triage walkthrough (hypothesis → contradiction → self-correction → evidence-linked findings).

- status: prize-caliber build (5-case library, web UI, eval harness, live-ready)
- official_url: https://findevil.devpost.com/
- rules_url: https://findevil.devpost.com/rules
- deadline: 2026-06-16
- prize: $22,000+ cash plus SANS benefits
- domain: cybersecurity / autonomous incident response (DFIR)
- license: MIT (see `LICENSE`)

## Devpost required components

All eight FIND EVIL! required submission components are present:

| # | Required component | Where judges can verify it |
|---|---|---|
| 1 | Public open-source repository | This GitHub repo, MIT license in `LICENSE` |
| 2 | Demo video under 5 minutes | [`find_evil_demo.mp4`](https://github.com/cjw0076/find-evil-dfir-agent/releases/download/demo-v1/find_evil_demo.mp4), live terminal screencast with self-correction |
| 3 | Architecture diagram | [`architecture_diagram.md`](architecture_diagram.md) |
| 4 | Written project description | This README and [`docs/devpost_submission.md`](docs/devpost_submission.md) |
| 5 | Dataset documentation | [`data/synthetic/`](data/synthetic/) case library and the case table below |
| 6 | Accuracy report | [`eval/report.json`](eval/report.json) plus the evaluation table below |
| 7 | Try-it-out instructions | [Quick start](#quick-start-stdlib-python-only-for-the-core) |
| 8 | Agent execution logs | [`out/trace.json`](out/trace.json) and [`out/ledger.json`](out/ledger.json) |

## What this is

An **autonomous DFIR triage agent** that ingests forensic artifacts, reasons
over them, and produces an **evidence-linked finding ledger** where every claim
cites the exact artifact row that justifies it. One case-agnostic agent triages
a whole library of distinct intrusion classes (Windows and Linux), runs a suite
of real read-only forensic analyzers, and self-scores against ground truth.

What SANS' FIND EVIL! judges reward, and where it lives here:

- **Evidence provenance** — every finding carries `evidence_refs` like
  `sysmon.evtx.jsonl:9`, traceable to a single line of a single artifact. The
  web UI makes every ref clickable → shows the raw evidence row.
- **Self-correction** — the agent forms a tempting-but-wrong first hypothesis
  (e.g. "internet brute-force got in"), finds a contradiction in the evidence,
  and corrects to the real attack chain. **100% decoy-rejection across 5 cases.**
- **Breadth of analysis** — 7 genuine forensic analyzers: super-timeline
  fusion, process-tree reconstruction, persistence sweep, LOLBin detection,
  encoded-PowerShell decoding, IOC extraction + threat-intel correlation, and a
  lateral-movement graph (`src/find_evil/analyzers.py`).
- **Analytical reasoning, not command transcripts** — hypothesis →
  contradiction → self-correction → detectors + analyzers → containment →
  verification, every step recorded.
- **Forensic auditability** — append-only ledger + a replayable execution trace.
- **Accuracy validation** — a rigorous eval harness (`eval/`) scores recall,
  precision, decoy-rejection, MITRE coverage and steps-to-root-cause across
  every case, from real runs.

> **Synthetic by default, live-ready.** No real host, no malware samples, no
> secrets. All IPs/domains/hashes are RFC 5737 / EICAR-style placeholders, safe
> to publish. Evidence is handled **read-only** and the agent is
> **recommendation-only** (no auto-execution). Point `FIND_EVIL_LIVE_DIR` at a
> real KAPE/Velociraptor/SIFT triage collection and the *same* agent, detectors,
> analyzers and eval run unchanged (`src/find_evil/backends.py`).

## Quick start (stdlib Python only for the core)

```bash
# 1. Run a single case end-to-end (no pip installs needed)
./run_demo.sh data/synthetic/case-ransom-02

# 2. Evaluate the agent across the WHOLE case library (real benchmark)
PYTHONPATH=src python3 eval/run_eval.py

# 3. Launch the web triage console (needs fastapi+uvicorn; auto-installed)
./run_dashboard.sh           # → http://127.0.0.1:8000

# 4. Tests
PYTHONPATH=src python3 -m pytest tests/ -q
```

Core agent/detectors/analyzers/eval require only Python 3.10+. Only the web
dashboard needs `fastapi`/`uvicorn` (`webapp/requirements.txt`).

## Case library (`data/synthetic/`)

One case-agnostic agent, driven by a per-case `manifest.json`, triages five
distinct intrusion classes — each a coherent multi-artifact case with a
`ground_truth.json` and a **planted decoy** to test self-correction:

| Case | Class | Platform | Attack chain (MITRE) |
|---|---|---|---|
| `case-lab-01` | targeted intrusion | Windows | phishing macro → encoded PS cradle → C2 → Run-key + task persistence → LSASS dump → SMB pivot (T1566.001·T1059.001·T1071.001·T1547.001·T1053.005·T1003.001·T1021.002) |
| `case-ransom-02` | ransomware operator | Windows | macro → shadow-copy/backup deletion → mass `.locky` encryption → C2 (T1566.001·T1059.001·T1490·T1486·T1071.001) |
| `case-lotl-03` | living-off-the-land espionage | Windows | Outlook→mshta HTA → certutil/regsvr32 squiblydoo → WMI persistence → WMI lateral → slow exfil (T1566.001·T1071.001·T1546.003·T1047) |
| `case-linux-web-04` | web-server compromise | **Linux** | upload.php → PHP webshell → bash reverse shell → cron persistence → SSH pivot (T1505.003·T1059.004·T1053.003) |
| `case-insider-05` | insider USB exfil | Windows | share collection (robocopy) → encrypted 7-Zip staging → USB copy (T1074.001·T1052.001) |

Each case's planted decoy is mechanically refutable from evidence (no successful
logon from a benign-rated scanner IP; an EICAR test file; a sanctioned helpdesk
host or cloud-backup endpoint), and the agent rejects it via an
evidence-justified self-correction.

## Evaluation (real numbers from real runs)

`PYTHONPATH=src python3 eval/run_eval.py` produces this table and
`eval/report.json` (it exits non-zero on any regression, so it doubles as a CI
gate):

```
case                class               plat     recall  prec  decoy  mitre  steps
----------------------------------------------------------------------------------
case-insider-05     insider_usb_exfil   windows     1.0   1.0    yes    2/2      5
case-lab-01         targeted_intrusion  windows     1.0   1.0    yes    7/7      5
case-linux-web-04   webshell_pivot      linux       1.0   1.0    yes    3/3     10
case-lotl-03        lotl_espionage      windows     1.0   1.0    yes    4/4      5
case-ransom-02      ransomware          windows     1.0   1.0    yes    5/5      7
----------------------------------------------------------------------------------
AGGREGATE (macro avg)                               1.0   1.0   100%           6.4

  macro recall / precision   : 1.0 / 1.0
  decoy rejection rate       : 100%
  mean steps-to-root-cause   : 6.4 (evidence tool calls)
  distinct MITRE techniques  : 16
```

## Web triage console (`webapp/`)

FastAPI + a single vanilla-JS page (no heavy frameworks). It runs a real
investigation live and visually shows the alert, the hypothesis →
contradiction → self-correction narrative, MITRE findings with **clickable
evidence-row citations** (each resolves to the raw artifact row), the
reconstructed process tree, the fused attack timeline, the IOC + threat-intel
table, the analyzer output, the containment playbook, and the replayable trace.

```bash
./run_dashboard.sh                 # http://127.0.0.1:8000
# endpoints: GET /api/cases · GET /api/investigate/{id}
#            GET /api/evidence/{id}/{ref} · GET /api/health
```

## Architecture

```
data/synthetic/<case>/{manifest.json, ground_truth.json, *.{jsonl,csv}}
        │
        ▼   src/find_evil/backends.py   EvidenceSource seam:
            SyntheticSource (default)  |  LiveTriageSource (FIND_EVIL_LIVE_DIR →
            KAPE/Velociraptor/SIFT dir, columns normalised, read-only)
        ▼
src/find_evil/evidence.py   EvidenceStore: typed read-only "tools",
                            stable provenance refs "<file>:<row>"
        ▼
src/find_evil/agent.py      TriageAgent (manifest-driven, case-agnostic):
   ingest → hypothesis(H1, decoy) → contradiction → self-correct(H2)
          → detectors → analyzers → containment → verification
        │            │                 │
        │            │                 └ src/find_evil/analyzers.py (7 forensic analyzers)
        │            └ src/find_evil/detections.py (16 MITRE-mapped, case-agnostic rules)
        ▼
src/find_evil/ledger.py     append-only evidence ledger (schema-conformant)
src/find_evil/trace.py      append-only replayable execution trace
        ▼
out/ledger.json   out/trace.json        eval/report.json
```

## Live-forensics path

`make_source(case_dir)` returns the live adapter when `FIND_EVIL_LIVE_DIR` is
set, else the synthetic source. `LiveTriageSource` walks a real triage
collection, discovers KAPE module CSVs (`*_PECmd_Output.csv`,
`*_Amcache_*.csv`, `*_MFTECmd_*.csv`) and EVTX-derived JSON
(`Microsoft-Windows-Sysmon%4Operational.json`, `Security.json`,
`...PowerShell%4Operational.json`), and normalises their tool column names into
the agent's logical schema. It is unit-tested against a KAPE-style fixture
(`tests/test_backends.py`) without needing a real image; the agent, detectors,
analyzers and eval run unchanged across sources.

```bash
FIND_EVIL_LIVE_DIR=/mnt/triage/HOST01 ./run_demo.sh   # reads a real triage dir
```

## Ledger schema

Records conform to `docs/agent_evidence_ledger_schema.json`. Each finding adds
`evidence_refs` (full provenance chain), `mitre_attack`, `iocs`, and
`recommendation`. Records are append-only and never edited.

## Status / founder-only gates

- Prize-caliber build complete: 5-case library, 16 detectors, 7 analyzers,
  web console, eval harness (macro recall = precision = 1.0, 100% decoy
  rejection, 16 distinct MITRE techniques), live-forensics adapter. Full test
  suite green.
- Public repo and demo video are published. Remaining external action is
  Devpost form finalization.
