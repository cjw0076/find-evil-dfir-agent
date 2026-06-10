# Synthetic Evidence Dataset — case-lotl-03 (Living-off-the-land espionage)

SYNTHETIC DATA ONLY. All indicators are RFC 5737-style placeholders.

## Story (ground truth)

On `RND-WS-11`, Outlook launched a malicious HTA via `mshta.exe` (T1566.001 /
beacon T1071.001). The actor chained signed LOLBins — `certutil` download+decode
then `regsvr32 /i:scrobj.dll` squiblydoo — to run `winsync.dll`, established
**WMI event-subscription persistence** (T1546.003), moved laterally with
`wmic /node:RND-FS-03 process call create` (T1047), and exfiltrated R&D data
**low-and-slow** over HTTPS (large periodic `bytes_out` on `regsvr32`).

## Planted decoy

An internet scanner brute-forced the local Administrator (all 4625, benign), and
the **IT helpdesk** ran `PsExec gpupdate` + a `SYSVOL$` `net use`. Both look like
the intrusion, but the brute-force never succeeded and the helpdesk jump host is
a sanctioned asset (`threat_intel.csv:4`). The lateral-movement detector
deliberately excludes `SYSVOL$`/`NETLOGON$` so sanctioned admin tooling is not
flagged. The agent must self-correct to the LOLBin chain.

## Artifacts

`sysmon.evtx.jsonl`, `wmi.csv` (WMI subscriptions), `security.evtx.jsonl`,
`netflow.csv`, `threat_intel.csv`. Incident window 2026-06-14 ~09:14–14:05 UTC.
