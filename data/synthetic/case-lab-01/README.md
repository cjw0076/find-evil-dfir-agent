# Synthetic Evidence Dataset — case-lab-01

SYNTHETIC DATA ONLY. No real host, no real malware, no secrets. All
indicators (IPs, hashes, domains) are RFC 5737 / EICAR-style placeholders
crafted to tell a coherent attack story. Safe to publish.

## Host

- Hostname: `WIN-ACCT-07` (simulated workstation, Finance dept)
- User: `acct.jlee` (standard user), `WIN-ACCT-07\Administrator` (local admin)
- Collection: simulated read-only triage mount (`/mnt/evidence` analog)

## Artifact files (forensic-analog formats)

| File | Forensic analog | What it represents |
|---|---|---|
| `security.evtx.jsonl` | Windows Security event log (EVTX) | logons, account events |
| `sysmon.evtx.jsonl` | Sysmon operational log | process create, network, file, registry |
| `powershell.evtx.jsonl` | PowerShell Script Block log (4104) | decoded script blocks |
| `prefetch.csv` | Prefetch (.pf) | program execution evidence + run count |
| `amcache.csv` | Amcache.hve | program presence + SHA1 |
| `registry_run.csv` | Registry Run/RunOnce keys | autorun persistence |
| `scheduled_tasks.csv` | Task Scheduler XML | scheduled-task persistence |
| `netflow.csv` | Network connection log / firewall | egress connections |
| `mft_timeline.csv` | $MFT / filesystem timeline | file create/modify times |
| `threat_intel.csv` | OSINT/IOC feed (local, offline) | known-bad indicators |

## Case manifest

See `manifest.json`. The manifest drives the (case-agnostic) agent: the alert
trigger, the decoy hypothesis, the corrected hypothesis, the refutation hints,
and the containment playbook. The same agent triages every case in
`data/synthetic/` from its manifest — nothing is hardcoded to this case.

## Ground truth (for accuracy scoring)

See `ground_truth.json`. The real story is a phishing-delivered PowerShell
download cradle that establishes persistence and beacons to C2. A decoy
"failed brute-force from the internet" event is present to test the agent's
ability to reject a tempting-but-wrong first hypothesis and self-correct.

## Timezone

All timestamps are UTC (`Z`). Incident window: 2026-06-06 01:00–01:20 UTC.
