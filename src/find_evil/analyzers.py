"""Read-only forensic analyzers.

These are the breadth-of-analysis tools a DFIR analyst reaches for. Each is a
pure, read-only function over the ``EvidenceStore`` that returns a structured
result whose every claim cites exact evidence ``ref``s. They never mutate
evidence and never touch the network. The agent runs them to enrich findings;
the web UI renders their output; the eval harness leaves them untouched.

Analyzers:

* ``super_timeline``        — fuse MFT + EVTX (sysmon/security/powershell) +
                              prefetch + amcache + netflow into one ordered,
                              evidence-cited activity timeline.
* ``process_tree``          — reconstruct the parent/child process tree from
                              Sysmon ProcessCreate (pid/parent_pid + cmdlines).
* ``persistence_sweep``     — Run keys, scheduled tasks, services, WMI subs.
* ``lolbin_scan``           — living-off-the-land binary abuse (rundll32,
                              mshta, regsvr32, certutil, bitsadmin, wmic, ...).
* ``decode_powershell``     — decode -EncodedCommand base64 into UTF-16 text.
* ``extract_iocs``          — pull IPs/domains/hashes/paths and correlate each
                              against the offline threat-intel feed.
* ``lateral_movement_graph``— host->host edges from SMB/RDP/WinRM + netflow.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any

from .evidence import EvidenceRecord, EvidenceStore


@dataclass
class AnalyzerResult:
    name: str
    title: str
    summary: str
    items: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "title": self.title, "summary": self.summary,
                "items": self.items, "evidence_refs": self.evidence_refs}


# ---------------------------------------------------------------------------
# super-timeline (artifact fusion)
# ---------------------------------------------------------------------------

_TIME_KEYS = ("time_utc", "created_utc", "last_run_utc", "last_write_utc",
              "first_seen_utc", "modified_utc")


def _row_time(rec: EvidenceRecord) -> str | None:
    for k in _TIME_KEYS:
        v = rec.get(k)
        if v:
            return str(v)
    return None


def _row_action(rec: EvidenceRecord) -> str:
    a = rec.artifact
    if a == "sysmon":
        t = rec.get("type") or rec.get("event_id")
        if rec.get("cmdline"):
            return f"sysmon/{t}: {rec.get('image') or ''} {rec.get('cmdline')}".strip()
        if rec.get("dest_ip"):
            return (f"sysmon/NetworkConnect: {rec.get('image')} -> "
                    f"{rec.get('dest_host') or rec.get('dest_ip')}:{rec.get('dest_port')}")
        if rec.get("target_file"):
            return f"sysmon/FileCreate: {rec.get('target_file')}"
        if rec.get("target_object"):
            return f"sysmon/RegistrySet: {rec.get('target_object')}"
        return f"sysmon/{t}"
    if a == "security":
        return f"security/{rec.get('event_id')}: {rec.get('msg') or rec.get('account')}"
    if a == "powershell":
        sb = (rec.get("script_block") or "")[:90]
        return f"powershell/4104: {sb}"
    if a == "prefetch":
        return f"prefetch: {rec.get('executable')} (run_count={rec.get('run_count')})"
    if a == "amcache":
        return f"amcache: {rec.get('path')} (signed={rec.get('signed')})"
    if a == "mft":
        return f"mft: {rec.get('path')}"
    if a == "netflow":
        return (f"netflow: {rec.get('src_host')} -> "
                f"{rec.get('dest_host') or rec.get('dest_ip')}:{rec.get('dest_port')} "
                f"out={rec.get('bytes_out')}")
    if a == "auth_log":
        return f"auth: {rec.get('msg') or rec.get('event')}"
    if a == "web_access":
        return f"web: {rec.get('method','')} {rec.get('path','')} {rec.get('status','')}"
    if a == "linux_proc":
        return f"proc: {rec.get('cmdline') or rec.get('comm')}"
    if a == "bash_history":
        return f"bash: {rec.get('command')}"
    if a == "usb":
        return f"usb: {rec.get('friendly_name')} ({rec.get('serial')})"
    if a == "filemod":
        return f"filemod: {rec.get('path')} ({rec.get('action')})"
    return f"{a}: {rec.data}"


def super_timeline(es: EvidenceStore, limit: int | None = None) -> AnalyzerResult:
    """Fuse every timestamped artifact into one chronologically-ordered view."""
    rows: list[dict[str, Any]] = []
    for artifact in es.records:
        if artifact == "threat_intel":
            continue
        for rec in es.records[artifact]:
            t = _row_time(rec)
            if not t:
                continue
            rows.append({"time_utc": t, "artifact": artifact,
                         "action": _row_action(rec), "ref": rec.ref})
    rows.sort(key=lambda r: r["time_utc"])
    if limit:
        rows = rows[:limit]
    return AnalyzerResult(
        name="super_timeline",
        title="Super-timeline (MFT + EVTX + prefetch + amcache + netflow fusion)",
        summary=f"Fused {len(rows)} timestamped events across "
                f"{len({r['artifact'] for r in rows})} artifact types into one timeline.",
        items=rows,
        evidence_refs=[r["ref"] for r in rows],
    )


# ---------------------------------------------------------------------------
# process-tree reconstruction
# ---------------------------------------------------------------------------

def process_tree(es: EvidenceStore) -> AnalyzerResult:
    """Reconstruct parent/child process tree from Sysmon ProcessCreate events."""
    procs = es.query("sysmon", type="ProcessCreate")
    if not procs:  # Linux fallback (linux_proc carries ppid)
        procs = es.query("linux_proc", event=lambda v: v in (None, "exec", "process"))
    by_pid: dict[str, EvidenceRecord] = {}
    for p in procs:
        pid = str(p.get("pid"))
        by_pid[pid] = p
    nodes: list[dict[str, Any]] = []
    for p in procs:
        pid = str(p.get("pid"))
        ppid = str(p.get("parent_pid") if p.get("parent_pid") is not None else p.get("ppid"))
        parent = by_pid.get(ppid)
        image = p.get("image") or p.get("comm") or "?"
        nodes.append({
            "pid": pid, "parent_pid": ppid,
            "image": image,
            "cmdline": p.get("cmdline"),
            "user": p.get("user"),
            "time_utc": p.get("time_utc"),
            "parent_image": p.get("parent_image") or (parent.get("image") if parent else None),
            "ref": p.ref,
            "parent_ref": parent.ref if parent else None,
            "depth": 0,
        })
    # compute depth by walking parent links (capped to avoid cycles)
    index = {n["pid"]: n for n in nodes}
    for n in nodes:
        d, cur = 0, n
        seen = set()
        while cur["parent_pid"] in index and cur["pid"] not in seen and d < 32:
            seen.add(cur["pid"])
            cur = index[cur["parent_pid"]]
            d += 1
        n["depth"] = d
    nodes.sort(key=lambda n: (n.get("time_utc") or "", int(n["pid"]) if n["pid"].isdigit() else 0))
    roots = [n["pid"] for n in nodes if n["parent_pid"] not in index]
    return AnalyzerResult(
        name="process_tree",
        title="Process-tree reconstruction (Sysmon parent/child + command lines)",
        summary=f"Reconstructed {len(nodes)} processes, {len(roots)} root(s); "
                f"max depth {max((n['depth'] for n in nodes), default=0)}.",
        items=nodes,
        evidence_refs=[n["ref"] for n in nodes],
    )


# ---------------------------------------------------------------------------
# persistence sweep
# ---------------------------------------------------------------------------

_USER_WRITABLE = ("appdata", "\\temp\\", "\\users\\public", "/tmp/", "/dev/shm")


def _suspicious_path(val: str | None) -> bool:
    if not val:
        return False
    low = val.lower()
    return any(tok in low for tok in _USER_WRITABLE)


def persistence_sweep(es: EvidenceStore) -> AnalyzerResult:
    """Sweep Run keys, scheduled tasks, services, WMI subs and cron for
    autostart entries that point at user-writable / unsigned payloads."""
    items: list[dict[str, Any]] = []

    for rec in es.query("registry_run"):
        susp = _suspicious_path(rec.get("value_data"))
        items.append({"mechanism": "registry_run", "name": rec.get("value_name"),
                      "target": rec.get("value_data"), "suspicious": susp,
                      "mitre": "T1547.001", "ref": rec.ref})
    for rec in es.query("scheduled_tasks"):
        susp = _suspicious_path(rec.get("action"))
        items.append({"mechanism": "scheduled_task", "name": rec.get("task_name"),
                      "target": rec.get("action"), "suspicious": susp,
                      "mitre": "T1053.005", "ref": rec.ref})
    for rec in es.query("services"):
        susp = _suspicious_path(rec.get("image_path")) or \
            (str(rec.get("signed", "")).lower() in ("unsigned", "false", "no"))
        items.append({"mechanism": "service", "name": rec.get("service_name"),
                      "target": rec.get("image_path"), "suspicious": susp,
                      "mitre": "T1543.003", "ref": rec.ref})
    for rec in es.query("wmi"):
        items.append({"mechanism": "wmi_subscription",
                      "name": rec.get("name") or rec.get("filter_name"),
                      "target": rec.get("consumer") or rec.get("command"),
                      "suspicious": True, "mitre": "T1546.003", "ref": rec.ref})
    for rec in es.query("cron"):
        cmd = str(rec.get("command") or "")
        susp = (_suspicious_path(cmd)
                or any(tok in cmd for tok in ("curl", "wget", "bash -i", "/dev/tcp/", "nc "))
                or any(part.startswith(".") and len(part) > 1 for part in cmd.split("/")))
        items.append({"mechanism": "cron", "name": rec.get("user"),
                      "target": rec.get("command"), "suspicious": susp,
                      "mitre": "T1053.003", "ref": rec.ref})

    susp_n = sum(1 for i in items if i["suspicious"])
    return AnalyzerResult(
        name="persistence_sweep",
        title="Persistence sweep (Run keys, tasks, services, WMI, cron)",
        summary=f"Enumerated {len(items)} autostart entries; "
                f"{susp_n} flagged suspicious (user-writable / unsigned / WMI).",
        items=items,
        evidence_refs=[i["ref"] for i in items if i["suspicious"]],
    )


# ---------------------------------------------------------------------------
# LOLBin scan
# ---------------------------------------------------------------------------

# binary -> (typical-abuse note, MITRE technique for the abuse)
_LOLBINS: dict[str, tuple[str, str]] = {
    "rundll32.exe": ("proxy-exec / comsvcs MiniDump", "T1218.011"),
    "mshta.exe": ("HTA / remote scriptlet execution", "T1218.005"),
    "regsvr32.exe": ("scriptlet (squiblydoo) execution", "T1218.010"),
    "certutil.exe": ("download / base64 decode of payloads", "T1140"),
    "bitsadmin.exe": ("background download / persistence", "T1197"),
    "wmic.exe": ("remote process create / recon", "T1047"),
    "msbuild.exe": ("inline C# task execution", "T1127.001"),
    "installutil.exe": ("uninstall-method code execution", "T1218.004"),
    "cscript.exe": ("WSH script execution", "T1059.005"),
    "wscript.exe": ("WSH script execution", "T1059.005"),
    "vssadmin.exe": ("shadow-copy deletion (recovery inhibition)", "T1490"),
    "wbadmin.exe": ("backup-catalog deletion", "T1490"),
    "bcdedit.exe": ("recovery options disabled", "T1490"),
    "schtasks.exe": ("scheduled-task persistence", "T1053.005"),
    "net.exe": ("admin-share / recon", "T1021.002"),
    "curl.exe": ("download of remote payload", "T1105"),
}


def lolbin_scan(es: EvidenceStore) -> AnalyzerResult:
    """Flag living-off-the-land binaries used in suspicious ways."""
    items: list[dict[str, Any]] = []
    procs = es.query("sysmon", type="ProcessCreate")
    for p in procs:
        image = (p.get("image") or "").lower()
        cmd = (p.get("cmdline") or "")
        for binname, (note, mitre) in _LOLBINS.items():
            if image.endswith(binname) or binname.split(".")[0] + " " in cmd.lower():
                # net.exe is only interesting with admin shares ($) or recon verbs
                if binname == "net.exe" and ("$" not in cmd and " view" not in cmd.lower()):
                    continue
                items.append({"binary": binname, "abuse": note, "mitre": mitre,
                              "image": p.get("image"), "cmdline": cmd,
                              "parent_image": p.get("parent_image"), "ref": p.ref})
                break
    return AnalyzerResult(
        name="lolbin_scan",
        title="LOLBin abuse detection (signed-binary proxy execution)",
        summary=f"Flagged {len(items)} living-off-the-land binary invocation(s).",
        items=items,
        evidence_refs=[i["ref"] for i in items],
    )


# ---------------------------------------------------------------------------
# encoded-PowerShell decode
# ---------------------------------------------------------------------------

_ENC_RE = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE)


def _decode_b64_ps(blob: str) -> str | None:
    """Decode a PowerShell -EncodedCommand value (base64 of UTF-16LE)."""
    try:
        pad = blob + "=" * (-len(blob) % 4)
        raw = base64.b64decode(pad)
    except Exception:
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(enc)
            if text.isprintable() or "\n" in text:
                return text
        except Exception:
            continue
    return None


def decode_powershell(es: EvidenceStore) -> AnalyzerResult:
    """Decode every -EncodedCommand PowerShell invocation found in Sysmon
    process-create command lines and pair it with the logged 4104 script block."""
    items: list[dict[str, Any]] = []
    procs = es.query("sysmon", type="ProcessCreate",
                     cmdline=lambda v: v and "powershell" in v.lower()
                     and ("-enc" in v.lower()))
    scripts = es.query("powershell", event_id=4104)
    for p in procs:
        m = _ENC_RE.search(p.get("cmdline") or "")
        decoded = _decode_b64_ps(m.group(1)) if m else None
        # correlate to the logged decoded script-block by pid
        sb_recs = [s for s in scripts if str(s.get("pid")) == str(p.get("pid"))]
        sb_text = sb_recs[0].get("script_block") if sb_recs else None
        refs = [p.ref] + [s.ref for s in sb_recs]
        items.append({
            "pid": p.get("pid"),
            "encoded_cmdline": p.get("cmdline"),
            "decoded_from_cmdline": decoded,
            "logged_script_block": sb_text,
            "refs": refs, "ref": p.ref,
        })
    n_dec = sum(1 for i in items if i["decoded_from_cmdline"] or i["logged_script_block"])
    return AnalyzerResult(
        name="decode_powershell",
        title="Encoded-PowerShell decoding (-EncodedCommand base64 -> UTF-16)",
        summary=f"Found {len(items)} encoded PowerShell invocation(s); "
                f"recovered plaintext for {n_dec}.",
        items=items,
        evidence_refs=[r for i in items for r in i["refs"]],
    )


# ---------------------------------------------------------------------------
# IOC extraction + threat-intel correlation
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_PRIVATE_NETS = ("10.", "192.168.", "127.", "169.254.", "0.0.0.0")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_NETS):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def extract_iocs(es: EvidenceStore) -> AnalyzerResult:
    """Extract IPs / domains / hashes / payload paths from all artifacts and
    correlate each against the offline threat-intel feed."""
    found: dict[tuple[str, str], dict[str, Any]] = {}

    def _add(value: str, ioc_type: str, ref: str) -> None:
        key = (ioc_type, value)
        if key not in found:
            ti = es.threat_verdict(value)
            found[key] = {"indicator": value, "type": ioc_type,
                          "verdict": ti.get("verdict") if ti else "unknown",
                          "ti_note": ti.get("note") if ti else None,
                          "ti_ref": ti.ref if ti else None,
                          "refs": []}
        found[key]["refs"].append(ref)

    for artifact, recs in es.records.items():
        if artifact in ("threat_intel",):
            continue
        for rec in recs:
            blob = " ".join(str(v) for v in rec.data.values())
            for ip in set(_IP_RE.findall(blob)):
                if ip in ("0.0.0.0",) or _is_private_ip(ip):
                    continue
                _add(ip, "ipv4", rec.ref)
            for h in set(_SHA256_RE.findall(blob)):
                _add(h.lower(), "sha256", rec.ref)
            for h in set(_SHA1_RE.findall(blob)):
                if not _SHA256_RE.fullmatch(h):
                    _add(h.lower(), "sha1", rec.ref)
            # domains: only from explicit host/domain-ish fields to cut noise
            for field_name in ("dest_host", "domain", "host"):
                v = rec.get(field_name)
                if v and _DOMAIN_RE.fullmatch(str(v)) and not _IP_RE.fullmatch(str(v)):
                    _add(str(v), "domain", rec.ref)

    items = sorted(found.values(),
                   key=lambda d: (d["verdict"] != "malicious", d["type"], d["indicator"]))
    malicious = [i for i in items if i["verdict"] == "malicious"]
    return AnalyzerResult(
        name="extract_iocs",
        title="IOC extraction + offline threat-intel correlation",
        summary=f"Extracted {len(items)} distinct indicators; "
                f"{len(malicious)} correlate to known-malicious threat intel.",
        items=items,
        evidence_refs=[r for i in malicious for r in i["refs"]]
        + [i["ti_ref"] for i in malicious if i["ti_ref"]],
    )


# ---------------------------------------------------------------------------
# lateral-movement graph
# ---------------------------------------------------------------------------

_LATERAL_PORTS = {"445": "SMB", "3389": "RDP", "5985": "WinRM", "5986": "WinRM",
                  "22": "SSH", "135": "RPC/WMI"}


def lateral_movement_graph(es: EvidenceStore) -> AnalyzerResult:
    """Build host->host lateral-movement edges from netflow on remote-admin
    ports plus Sysmon 'net use'/PsExec/WinRM command lines."""
    edges: list[dict[str, Any]] = []

    for nf in es.query("netflow"):
        port = str(nf.get("dest_port"))
        if port in _LATERAL_PORTS:
            src = nf.get("src_host") or nf.get("src_ip")
            dst = nf.get("dest_host") or nf.get("dest_ip")
            if src and dst and src != dst:
                edges.append({"src": src, "dst": dst, "proto": _LATERAL_PORTS[port],
                              "port": port, "via": "netflow",
                              "process": nf.get("process"), "ref": nf.ref})

    for p in es.query("sysmon", type="ProcessCreate"):
        cmd = (p.get("cmdline") or "").lower()
        if any(tok in cmd for tok in ("net use", "psexec", "winrm",
                                      "wmic /node", "invoke-command", "enter-pssession")):
            edges.append({"src": p.get("user") or "host", "dst": _extract_target(cmd),
                          "proto": "remote-exec", "port": "-", "via": "process",
                          "process": p.get("image"), "cmdline": p.get("cmdline"),
                          "ref": p.ref})

    hosts = sorted({e["src"] for e in edges} | {e["dst"] for e in edges if e["dst"]})
    return AnalyzerResult(
        name="lateral_movement_graph",
        title="Lateral-movement graph (SMB/RDP/WinRM/SSH edges)",
        summary=f"Derived {len(edges)} lateral-movement edge(s) across "
                f"{len(hosts)} host/identity node(s).",
        items=edges,
        evidence_refs=[e["ref"] for e in edges],
    )


def _extract_target(cmd: str) -> str:
    m = re.search(r"\\\\([a-z0-9_.-]+)", cmd, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"/node:([a-z0-9_.-]+)", cmd, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"-computername\s+([a-z0-9_.-]+)", cmd, re.IGNORECASE)
    return m.group(1) if m else "?"


ALL_ANALYZERS = [
    super_timeline,
    process_tree,
    persistence_sweep,
    lolbin_scan,
    decode_powershell,
    extract_iocs,
    lateral_movement_graph,
]


def run_all(es: EvidenceStore) -> dict[str, AnalyzerResult]:
    return {fn.__name__: fn(es) for fn in ALL_ANALYZERS}
