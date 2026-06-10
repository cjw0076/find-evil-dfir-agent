"""Detection rules over the evidence store.

Each detector is a read-only analytic that returns zero or more Detection
objects, each carrying a MITRE technique, a severity, a human summary, and the
evidence_refs that justify it. Detectors are case-AGNOSTIC: every detector runs
against every case and simply returns nothing when its pattern is absent, so the
same rule set triages a phishing intrusion, a ransomware operator, a
living-off-the-land espionage actor, a Linux webshell pivot, and an insider USB
exfil. Detectors do NOT touch the ledger; the agent decides what to promote to
findings after the self-correction loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .evidence import EvidenceStore


@dataclass
class Detection:
    rule_id: str
    mitre: str
    label: str
    severity: str
    summary: str
    event_time_utc: str
    evidence_refs: list[str]
    iocs: list[str] = field(default_factory=list)
    recommendation: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Windows: phishing / execution / cred-access / persistence / C2 / lateral
# ---------------------------------------------------------------------------

def detect_phishing_doc_exec(es: EvidenceStore) -> list[Detection]:
    out = []
    office = es.query("sysmon", type="ProcessCreate",
                      parent_image=lambda v: v and any(
                          o in v.upper() for o in ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE")))
    for rec in office:
        doc = None
        for m in es.query("mft", path=lambda v: v and (v.lower().endswith(".docm")
                                                        or v.lower().endswith(".xlsm"))):
            doc = m
            break
        refs = [rec.ref] + ([doc.ref] if doc else [])
        out.append(Detection(
            rule_id="R-PHISH-001", mitre="T1566.001",
            label="Phishing attachment execution (Office spawned child process)",
            severity="high",
            summary=f"{rec.get('parent_image','Office').split(chr(92))[-1]} spawned "
                    f"{rec.get('image')} - macro-enabled document executed code.",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[doc.get("path")] if doc else [],
            recommendation="Quarantine the macro doc, disable Office macros via GPO, reset the user's mailbox rules.",
            detail={"child_cmdline": rec.get("cmdline")},
        ))
    return out


def detect_encoded_powershell(es: EvidenceStore) -> list[Detection]:
    out = []
    susp = es.query("sysmon", type="ProcessCreate",
                    image=lambda v: v and "powershell.exe" in v.lower(),
                    cmdline=lambda v: v and ("-enc" in v.lower() or "-encodedcommand" in v.lower()))
    decoded = es.query("powershell", event_id=4104)
    for rec in susp:
        refs = [rec.ref] + [d.ref for d in decoded
                            if str(d.get("pid")) == str(rec.get("pid"))
                            and ("DownloadString" in (d.get("script_block") or "")
                                 or "DownloadFile" in (d.get("script_block") or ""))]
        out.append(Detection(
            rule_id="R-PS-001", mitre="T1059.001",
            label="Encoded PowerShell download cradle",
            severity="critical",
            summary="Hidden, encoded PowerShell invoked a web download cradle (IEX/DownloadString).",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            recommendation="Kill the PowerShell tree, enable Constrained Language Mode + script-block logging enforcement.",
            detail={"cmdline": rec.get("cmdline")},
        ))
    return out


def detect_c2_beacon(es: EvidenceStore) -> list[Detection]:
    out = []
    conns = es.query("sysmon", type="NetworkConnect")
    seen_hosts: set[str] = set()
    for rec in conns:
        ip = rec.get("dest_ip")
        host = rec.get("dest_host")
        ti_ip = es.threat_verdict(ip) if ip else None
        ti_host = es.threat_verdict(host) if host else None
        malicious = (ti_ip and ti_ip.get("verdict") == "malicious") or \
                    (ti_host and ti_host.get("verdict") == "malicious")
        if not malicious:
            continue
        key = host or ip
        if key in seen_hosts:
            continue
        seen_hosts.add(key)
        nf = [n.ref for n in es.query("netflow", dest_ip=ip)]
        refs = [rec.ref] + nf
        if ti_ip:
            refs.append(ti_ip.ref)
        if ti_host:
            refs.append(ti_host.ref)
        out.append(Detection(
            rule_id="R-C2-001", mitre="T1071.001",
            label="C2 communication to known-bad host",
            severity="critical",
            summary=f"Repeated egress to {host or ip} ({ip}:{rec.get('dest_port')}) flagged malicious by threat intel.",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[x for x in (ip, host) if x],
            recommendation="Block the C2 indicator at the egress firewall; isolate the host.",
            detail={"port": rec.get("dest_port")},
        ))
    return out


def detect_registry_run_persistence(es: EvidenceStore) -> list[Detection]:
    out = []
    for rec in es.query("registry_run",
                        value_data=lambda v: v and "AppData\\Roaming" in v):
        sysmon_set = es.query("sysmon", type="RegistrySet",
                              details=lambda v: v and "AppData\\Roaming" in v)
        ps_set = es.query("powershell",
                          script_block=lambda v: v and "CurrentVersion\\Run" in v)
        refs = [rec.ref] + [s.ref for s in sysmon_set] + [p.ref for p in ps_set]
        out.append(Detection(
            rule_id="R-PERSIST-001", mitre="T1547.001",
            label="Registry Run key persistence (AppData payload)",
            severity="high",
            summary=f"HKCU Run value '{rec.get('value_name')}' autoruns a binary from user AppData.",
            event_time_utc=rec.get("last_write_utc"),
            evidence_refs=refs,
            iocs=[rec.get("value_data")],
            recommendation="Delete the Run value and the referenced binary; hunt for the same value on peers.",
        ))
    return out


def detect_scheduled_task_persistence(es: EvidenceStore) -> list[Detection]:
    out = []
    for rec in es.query("scheduled_tasks",
                        action=lambda v: v and "AppData\\Roaming" in v):
        sysmon = es.query("sysmon", type="ProcessCreate",
                          image=lambda v: v and "schtasks.exe" in v.lower())
        refs = [rec.ref] + [s.ref for s in sysmon]
        out.append(Detection(
            rule_id="R-PERSIST-002", mitre="T1053.005",
            label="Scheduled task persistence (masquerading name)",
            severity="high",
            summary=f"Task '{rec.get('task_name')}' runs an AppData binary on a short interval - name mimics a system task.",
            event_time_utc=rec.get("created_utc"),
            evidence_refs=refs,
            iocs=[rec.get("task_name"), rec.get("action")],
            recommendation="Remove the scheduled task; alert on schtasks spawned by non-system parents.",
        ))
    return out


def detect_lsass_dump(es: EvidenceStore) -> list[Detection]:
    out = []
    dumps = es.query("sysmon", type="ProcessCreate",
                     cmdline=lambda v: v and "comsvcs.dll" in v.lower() and "minidump" in v.lower())
    for rec in dumps:
        ps = es.query("powershell", script_block=lambda v: v and "comsvcs.dll" in (v or "").lower())
        dmp = es.query("mft", path=lambda v: v and v.lower().endswith("lsass.dmp"))
        refs = [rec.ref] + [p.ref for p in ps] + [d.ref for d in dmp]
        out.append(Detection(
            rule_id="R-CRED-001", mitre="T1003.001",
            label="LSASS credential dump via comsvcs MiniDump",
            severity="critical",
            summary="comsvcs.dll MiniDump used to dump LSASS memory to lsass.dmp (credential theft).",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[d.get("path") for d in dmp] or ["lsass.dmp"],
            recommendation="Force-reset credentials cached on host; enable Credential Guard; treat all local secrets as compromised.",
        ))
    return out


def detect_lateral_movement(es: EvidenceStore) -> list[Detection]:
    out = []
    # Admin/hidden-share access for hands-on-keyboard movement. SYSVOL$ /
    # NETLOGON$ are read by routine gpupdate and are NOT lateral movement, so
    # they are excluded to avoid flagging sanctioned helpdesk activity.
    def _admin_share(v: str | None) -> bool:
        if not (v and "net use" in v.lower() and "$" in v):
            return False
        low = v.lower()
        if "sysvol$" in low or "netlogon$" in low:
            return False
        return any(s in low for s in ("c$", "admin$", "ipc$")) or "\\\\" in v
    net = es.query("sysmon", type="ProcessCreate", cmdline=_admin_share)
    for rec in net:
        nf = es.query("netflow", dest_port="445")
        sec = es.query("security", msg=lambda v: v and "lateral" in v.lower())
        refs = [rec.ref] + [n.ref for n in nf] + [s.ref for s in sec]
        target = "remote share"
        import re
        m = re.search(r"\\\\([A-Za-z0-9_.-]+)", rec.get("cmdline") or "")
        if m:
            target = m.group(1)
        out.append(Detection(
            rule_id="R-LAT-001", mitre="T1021.002",
            label="Lateral movement to file server over SMB",
            severity="high",
            summary=f"Implant ran 'net use' to an admin share on {target} and a successful SMB logon followed.",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[i for i in (target,) if i],
            recommendation="Isolate the target server for triage; review SMB access logs; reset the implicated account everywhere.",
        ))
    return out


# ---------------------------------------------------------------------------
# Ransomware: recovery inhibition + mass encryption
# ---------------------------------------------------------------------------

def detect_shadow_copy_deletion(es: EvidenceStore) -> list[Detection]:
    out = []
    procs = es.query("sysmon", type="ProcessCreate",
                     cmdline=lambda v: v and (
                         ("vssadmin" in v.lower() and "delete" in v.lower())
                         or ("wbadmin" in v.lower() and "delete" in v.lower())
                         or ("bcdedit" in v.lower() and "recoveryenabled" in v.lower().replace(" ", ""))))
    if not procs:
        return out
    refs = [p.ref for p in procs]
    first = procs[0]
    cmds = "; ".join((p.get("cmdline") or "")[:80] for p in procs[:3])
    out.append(Detection(
        rule_id="R-RANSOM-001", mitre="T1490",
        label="Inhibit system recovery (shadow-copy / backup deletion)",
        severity="critical",
        summary=f"Recovery inhibited via {len(procs)} command(s): {cmds}",
        event_time_utc=first.get("time_utc"),
        evidence_refs=refs,
        recommendation="Restore from offsite/immutable backups (local shadow copies are gone); isolate the host immediately.",
    ))
    return out


def detect_mass_encryption(es: EvidenceStore) -> list[Detection]:
    out = []
    mods = es.query("filemod", action=lambda v: v and "encrypt" in str(v).lower()) \
        or es.query("filemod", path=lambda v: v and (".locky" in str(v).lower()
                    or ".crypt" in str(v).lower() or ".enc" in str(v).lower()))
    # fall back to sysmon FileCreate of ransom-extension files
    if not mods:
        mods = es.query("sysmon", type="FileCreate",
                        target_file=lambda v: v and (".locky" in str(v).lower()
                        or "_to_decrypt" in str(v).lower() or "readme" in str(v).lower()))
    if len(mods) < 3:
        return out
    refs = [m.ref for m in mods]
    note = next((m for m in mods if "decrypt" in str(m.get("path") or m.get("target_file") or "").lower()), None)
    out.append(Detection(
        rule_id="R-RANSOM-002", mitre="T1486",
        label="Data encrypted for impact (mass file encryption)",
        severity="critical",
        summary=f"Mass-encryption burst: {len(mods)} files rewritten to a ransom extension"
                + (f"; ransom note {note.get('path') or note.get('target_file')} dropped." if note else "."),
        event_time_utc=mods[0].get("time_utc") or mods[0].get("modified_utc"),
        evidence_refs=refs,
        iocs=[note.get("path") or note.get("target_file")] if note else [],
        recommendation="Network-isolate the host, preserve volatile memory, restore files from immutable backups.",
    ))
    return out


# ---------------------------------------------------------------------------
# Living-off-the-land: WMI persistence + WMI lateral exec
# ---------------------------------------------------------------------------

def detect_wmi_persistence(es: EvidenceStore) -> list[Detection]:
    out = []
    subs = es.query("wmi")
    for rec in subs:
        out.append(Detection(
            rule_id="R-PERSIST-003", mitre="T1546.003",
            label="WMI event-subscription persistence",
            severity="high",
            summary=f"WMI permanent event subscription '{rec.get('name') or rec.get('filter_name')}' "
                    f"runs '{rec.get('consumer') or rec.get('command')}' on a trigger.",
            event_time_utc=rec.get("created_utc") or rec.get("time_utc"),
            evidence_refs=[rec.ref],
            iocs=[rec.get("consumer") or rec.get("command")],
            recommendation="Remove the __FilterToConsumerBinding via Get-WMIObject; baseline WMI subscriptions fleet-wide.",
        ))
    return out


def detect_wmic_remote_exec(es: EvidenceStore) -> list[Detection]:
    out = []
    procs = es.query("sysmon", type="ProcessCreate",
                     cmdline=lambda v: v and "wmic" in v.lower()
                     and ("/node:" in v.lower() and "process call create" in v.lower()))
    for rec in procs:
        import re
        m = re.search(r"/node:([A-Za-z0-9_.-]+)", rec.get("cmdline") or "", re.IGNORECASE)
        target = m.group(1) if m else "?"
        nf = es.query("netflow", dest_port="135")
        refs = [rec.ref] + [n.ref for n in nf]
        out.append(Detection(
            rule_id="R-LAT-002", mitre="T1047",
            label="WMI remote process creation (lateral movement)",
            severity="high",
            summary=f"wmic /node:{target} process call create - remote execution via WMI over RPC.",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[target],
            recommendation="Restrict WMI/RPC (135) between workstations; alert on wmic /node usage.",
        ))
    return out


# ---------------------------------------------------------------------------
# Linux: webshell + reverse shell + cron persistence
# ---------------------------------------------------------------------------

def detect_webshell(es: EvidenceStore) -> list[Detection]:
    out = []
    # webshell write: a server process creating a script under a web root
    writes = es.query("filemod",
                      path=lambda v: v and ("/var/www" in str(v) or "/srv/www" in str(v))
                      and str(v).rsplit(".", 1)[-1] in ("php", "jsp", "aspx", "asp"))
    # corroborating web access POST to the dropped shell
    web_posts = es.query("web_access", method="POST")
    for w in writes:
        path = w.get("path")
        shell_name = path.rsplit("/", 1)[-1] if path else ""
        hits = [r for r in web_posts if shell_name and shell_name in str(r.get("path", ""))]
        refs = [w.ref] + [h.ref for h in hits]
        out.append(Detection(
            rule_id="R-WEB-001", mitre="T1505.003",
            label="Web shell deployed to web root",
            severity="critical",
            summary=f"Server process wrote a webshell at {path}"
                    + (f"; {len(hits)} subsequent POST(s) executed it." if hits else "."),
            event_time_utc=w.get("time_utc") or w.get("modified_utc"),
            evidence_refs=refs,
            iocs=[path],
            recommendation="Remove the webshell, rotate web-app credentials, audit the web root for additional implants.",
        ))
    return out


def detect_reverse_shell(es: EvidenceStore) -> list[Detection]:
    out = []
    REV = ("bash -i", "/dev/tcp/", "nc -e", "ncat -e", "python -c", "mkfifo")
    procs = es.query("linux_proc",
                     cmdline=lambda v: v and any(tok in str(v) for tok in REV))
    hist = es.query("bash_history",
                    command=lambda v: v and any(tok in str(v) for tok in REV))
    for rec in procs:
        refs = [rec.ref] + [h.ref for h in hist
                            if str(h.get("command", ""))[:20] in str(rec.get("cmdline", ""))]
        out.append(Detection(
            rule_id="R-LIN-001", mitre="T1059.004",
            label="Reverse shell (Unix shell over TCP)",
            severity="critical",
            summary=f"Reverse shell spawned: {rec.get('cmdline')}",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[rec.get("cmdline")],
            recommendation="Kill the shell process, block the callback IP, and image the host for forensics.",
        ))
    return out


def _suspicious_cron(v: str | None) -> bool:
    if not v:
        return False
    s = str(v)
    if any(tok in s for tok in ("/tmp/", "/dev/shm", "curl", "wget", "bash -i",
                                "nc ", "python -c", "/dev/tcp/")):
        return True
    # hidden-dotfile payload anywhere on the path (e.g. /usr/local/sbin/.update)
    return any(part.startswith(".") and len(part) > 1 for part in s.split("/"))


def detect_cron_persistence(es: EvidenceStore) -> list[Detection]:
    out = []
    for rec in es.query("cron", command=_suspicious_cron):
        out.append(Detection(
            rule_id="R-PERSIST-004", mitre="T1053.003",
            label="Cron job persistence (suspicious payload)",
            severity="high",
            summary=f"Cron entry for {rec.get('user')} runs '{rec.get('command')}'.",
            event_time_utc=rec.get("created_utc") or rec.get("time_utc"),
            evidence_refs=[rec.ref],
            iocs=[rec.get("command")],
            recommendation="Remove the crontab entry; audit /etc/cron* and per-user crontabs across the fleet.",
        ))
    return out


# ---------------------------------------------------------------------------
# Insider / USB exfil
# ---------------------------------------------------------------------------

def detect_usb_mass_storage(es: EvidenceStore) -> list[Detection]:
    out = []
    devs = es.query("usb")
    for rec in devs:
        out.append(Detection(
            rule_id="R-INS-001", mitre="T1052.001",
            label="Removable-media (USB) mass-storage device connected",
            severity="medium",
            summary=f"USB mass-storage device '{rec.get('friendly_name')}' "
                    f"(serial {rec.get('serial')}) connected at {rec.get('first_connect_utc') or rec.get('time_utc')}.",
            event_time_utc=rec.get("first_connect_utc") or rec.get("time_utc"),
            evidence_refs=[rec.ref],
            iocs=[rec.get("serial")],
            recommendation="Correlate device serial against approved-asset inventory; review DLP for files copied to it.",
        ))
    return out


def detect_data_staging(es: EvidenceStore) -> list[Detection]:
    """Collected data packed into an archive (often password-protected) prior
    to exfil - distinct from the exfil transfer itself."""
    out = []
    archives = es.query("filemod",
                        path=lambda v: v and (str(v).lower().endswith(".zip")
                        or str(v).lower().endswith(".7z") or str(v).lower().endswith(".rar")))
    # require an archiver process or a robocopy/share-collection nearby to avoid
    # flagging ordinary user zips
    archiver = es.query("sysmon", type="ProcessCreate",
                        image=lambda v: v and any(a in v.lower() for a in
                        ("7z.exe", "winrar.exe", "rar.exe", "makecab.exe")))
    if not archives or not archiver:
        return out
    refs = [c.ref for c in archives] + [a.ref for a in archiver]
    out.append(Detection(
        rule_id="R-INS-002", mitre="T1074.001",
        label="Local data staging (archive of collected files)",
        severity="high",
        summary=f"{len(archives)} archive(s) created by {archiver[0].get('image','').split(chr(92))[-1]} "
                f"staging collected data prior to exfil.",
        event_time_utc=archives[0].get("time_utc") or archives[0].get("modified_utc"),
        evidence_refs=refs,
        iocs=[c.get("path") for c in archives[:3]],
        recommendation="Preserve the archives as evidence; review what was collected and whether it left the host.",
    ))
    return out


def detect_usb_exfil(es: EvidenceStore) -> list[Detection]:
    """Sensitive files copied to a removable drive letter (D:..K:)."""
    out = []
    copies = es.query("filemod",
                      path=lambda v: v and len(str(v)) > 3 and str(v)[1:3] == ":\\"
                      and str(v)[0].upper() in "DEFGHIJK")
    if len(copies) < 2:
        return out
    refs = [c.ref for c in copies]
    out.append(Detection(
        rule_id="R-INS-003", mitre="T1052.001",
        label="Data exfiltration over USB removable media",
        severity="high",
        summary=f"{len(copies)} file(s) copied to a removable drive ({copies[0].get('path','')[0:2]}).",
        event_time_utc=copies[0].get("time_utc") or copies[0].get("modified_utc"),
        evidence_refs=refs,
        iocs=[c.get("path") for c in copies[:3]],
        recommendation="Block USB mass-storage write via GPO; pursue HR/legal hold; quantify exfiltrated data.",
    ))
    return out


ALL_DETECTORS = [
    detect_phishing_doc_exec,
    detect_encoded_powershell,
    detect_c2_beacon,
    detect_registry_run_persistence,
    detect_scheduled_task_persistence,
    detect_lsass_dump,
    detect_lateral_movement,
    detect_shadow_copy_deletion,
    detect_mass_encryption,
    detect_wmi_persistence,
    detect_wmic_remote_exec,
    detect_webshell,
    detect_reverse_shell,
    detect_cron_persistence,
    detect_usb_mass_storage,
    detect_data_staging,
    detect_usb_exfil,
]


def run_all(es: EvidenceStore) -> list[Detection]:
    out: list[Detection] = []
    for det in ALL_DETECTORS:
        out.extend(det(es))
    return out
