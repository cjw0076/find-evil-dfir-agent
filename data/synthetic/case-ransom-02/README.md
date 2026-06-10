# Synthetic Evidence Dataset — case-ransom-02 (Ransomware operator)

SYNTHETIC DATA ONLY. All indicators are RFC 5737 / EICAR-style placeholders.

## Story (ground truth)

A macro in `Invoice_April.xlsm` opened by `m.reyes` on `FIN-WS-07` spawned an
encoded PowerShell stager that **inhibited recovery** (`vssadmin`/`wbadmin`/
`bcdedit` shadow-copy + backup deletion → T1490), then downloaded and ran
`svch0st.exe` to **encrypt 8 finance documents** to `.locky` and drop a ransom
note (T1486), while beaconing to a known Locky C2 (T1071.001). Entry was the
Office macro (T1566.001 / T1059.001).

## Planted decoy

An **EICAR antivirus test file** was downloaded via `certutil` on `IT-LAB-02`
and lit up AV dashboards, plus a benign internet scanner produced failed logons.
It looks like patient zero — but EICAR is the benign standard AV test artifact
(`threat_intel.csv:2`) and `IT-LAB-02` shows zero shadow deletion or encryption.
The agent must self-correct to `FIN-WS-07`.

## Artifacts

`sysmon.evtx.jsonl`, `powershell.evtx.jsonl`, `security.evtx.jsonl`,
`filemod.csv` (file-integrity monitor), `netflow.csv`, `mft_timeline.csv`,
`amcache.csv`, `threat_intel.csv`. Incident window 2026-06-12 ~13:58–14:03 UTC.
Manifest: `manifest.json`. Ground truth: `ground_truth.json`.
