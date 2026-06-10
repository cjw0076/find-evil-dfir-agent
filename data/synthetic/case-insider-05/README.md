# Synthetic Evidence Dataset — case-insider-05 (Insider USB exfil)

SYNTHETIC DATA ONLY. All indicators are RFC 5737-style placeholders.

## Story (ground truth)

After hours on `ENG-WS-22`, the engineer `d.coleman` — using **valid
credentials** — `robocopy`d the entire `\\ENG-FS-01\IP_Designs` share to a local
staging folder, packed it into a **password-protected 7-Zip archive** (T1074.001),
connected a personal **SanDisk USB drive**, and `xcopy`d the archive plus raw
CAD/firmware files to `E:\` (T1052.001). No external compromise — a trusted
insider exfiltrating IP on removable media.

## Planted decoy

An internet scanner brute-forced the local Administrator (benign, no success)
and a **sanctioned cloud-backup agent** made outbound HTTPS to `52.95.110.10`.
Together they look like an external breach exfiltrating to the cloud, but the
brute-force never authenticated and `52.95.110.10` is the approved corporate
backup endpoint (`threat_intel.csv:2`). The agent must self-correct to the
insider-USB theory. The legitimate share access (no `$` admin share) is
intentionally NOT flagged as lateral movement.

## Artifacts

`sysmon.evtx.jsonl`, `usb.csv` (USBSTOR / removable-media), `filemod.csv`,
`security.evtx.jsonl`, `netflow.csv`, `threat_intel.csv`.
Incident window 2026-06-13 ~18:42–19:12 UTC.
