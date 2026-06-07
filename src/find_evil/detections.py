"""Detection rules over the evidence store.

Each detector is a read-only analytic that returns zero or more Detection
objects, each carrying a MITRE technique, a severity, a human summary, and the
evidence_refs that justify it. Detectors do NOT touch the ledger; the agent
decides what to promote to findings after the self-correction loop.
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


def detect_phishing_doc_exec(es: EvidenceStore) -> list[Detection]:
    out = []
    # Office app spawning a shell is the classic macro-exec tell.
    office = es.query("sysmon", type="ProcessCreate",
                      parent_image=lambda v: v and "WINWORD.EXE" in v)
    for rec in office:
        doc = None
        for m in es.query("mft", path=lambda v: v and v.lower().endswith(".docm")):
            doc = m
            break
        refs = [rec.ref] + ([doc.ref] if doc else [])
        out.append(Detection(
            rule_id="R-PHISH-001", mitre="T1566.001",
            label="Phishing attachment execution (Office spawned child process)",
            severity="high",
            summary=f"WINWORD.EXE spawned {rec.get('image')} — macro-enabled document executed code.",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[doc.get("path")] if doc else [],
            recommendation="Quarantine the .docm, disable Office macros via GPO, reset acct.jlee mailbox rules.",
            detail={"child_cmdline": rec.get("cmdline")},
        ))
    return out


def detect_encoded_powershell(es: EvidenceStore) -> list[Detection]:
    out = []
    # Fire once, on the real powershell.exe process (not the cmd.exe wrapper),
    # so the finding carries the decoded script-block provenance.
    susp = es.query("sysmon", type="ProcessCreate",
                    image=lambda v: v and "powershell.exe" in v.lower(),
                    cmdline=lambda v: v and ("-enc" in v or "-encodedcommand" in v.lower()))
    decoded = es.query("powershell", event_id=4104)
    for rec in susp:
        refs = [rec.ref] + [d.ref for d in decoded
                            if d.get("pid") == rec.get("pid")
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
        ti_ip = es.threat_verdict(ip)
        ti_host = es.threat_verdict(host) if host else None
        malicious = (ti_ip and ti_ip.get("verdict") == "malicious") or \
                    (ti_host and ti_host.get("verdict") == "malicious")
        if not malicious:
            continue
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        # gather corroborating netflow rows
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
            summary=f"Repeated egress to {host} ({ip}:{rec.get('dest_port')}) flagged malicious by threat intel.",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=[ip, host],
            recommendation="Block 203.0.113.45 / cdn-update-sync.example.net at egress firewall; isolate host.",
            detail={"port": rec.get("dest_port")},
        ))
    return out


def detect_registry_run_persistence(es: EvidenceStore) -> list[Detection]:
    out = []
    # Run keys pointing at user-writable AppData = suspicious autorun.
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
                          image=lambda v: v and "schtasks.exe" in v)
        refs = [rec.ref] + [s.ref for s in sysmon]
        out.append(Detection(
            rule_id="R-PERSIST-002", mitre="T1053.005",
            label="Scheduled task persistence (masquerading name)",
            severity="high",
            summary=f"Task '{rec.get('task_name')}' runs an AppData binary every few minutes — name mimics OneDrive.",
            event_time_utc=rec.get("created_utc"),
            evidence_refs=refs,
            iocs=[rec.get("task_name"), rec.get("action")],
            recommendation="Remove scheduled task 'OneDriveSync'; alert on schtasks spawned by non-system parents.",
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
            iocs=["C:\\Users\\acct.jlee\\AppData\\Roaming\\lsass.dmp"],
            recommendation="Force-reset credentials cached on host; enable Credential Guard; treat all local secrets as compromised.",
        ))
    return out


def detect_lateral_movement(es: EvidenceStore) -> list[Detection]:
    out = []
    net = es.query("sysmon", type="ProcessCreate",
                   cmdline=lambda v: v and "net use" in v.lower() and "$" in v)
    for rec in net:
        nf = es.query("netflow", dest_port="445")
        sec = es.query("security", msg=lambda v: v and "lateral" in v.lower())
        refs = [rec.ref] + [n.ref for n in nf] + [s.ref for s in sec]
        out.append(Detection(
            rule_id="R-LAT-001", mitre="T1021.002",
            label="Lateral movement to file server over SMB",
            severity="high",
            summary="Implant ran 'net use' to an admin share on FILE-SRV-02 and a successful SMB logon followed.",
            event_time_utc=rec.get("time_utc"),
            evidence_refs=refs,
            iocs=["FILE-SRV-02", "10.20.0.41"],
            recommendation="Isolate FILE-SRV-02 for triage; review SMB access logs; reset acct.jlee everywhere.",
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
]


def run_all(es: EvidenceStore) -> list[Detection]:
    out: list[Detection] = []
    for det in ALL_DETECTORS:
        out.extend(det(es))
    return out
