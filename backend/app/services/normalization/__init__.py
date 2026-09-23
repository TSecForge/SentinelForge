"""Event normalization: source-specific records -> NormalizedEvent.

Supported sources: windows (Security/System/Sysmon event records), linux (simple JSON + sshd syslog lines),
docker (Engine events API), kubernetes (audit.k8s.io events), generic (already-normalized JSON).
Plugins can add or replace parsers via app.plugins.registry.event_parsers.
"""

import re
from datetime import datetime, timezone
from typing import Any

from app.plugins import registry
from app.schemas.event import EventIn, NormalizedEvent
from app.services.profiling import normalize_image
from app.utils import stable_hash


class NormalizationError(ValueError):
    pass


def basename(path: Any) -> str | None:
    if not path:
        return None
    return re.split(r"[\\/]", str(path))[-1].lower() or None


def _int(v: Any) -> int | None:
    if v in (None, "", "-"):
        return None
    try:
        s = str(v)
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _ts(v: Any) -> datetime:
    if isinstance(v, dict):
        v = v.get("SystemTime")
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1e9 if v > 1e12 else v, tz=timezone.utc)
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _clean(v: Any) -> str | None:
    return None if v in (None, "", "-") else str(v)


def _user(domain: Any, name: Any) -> tuple[str | None, str | None]:
    name = _clean(name)
    if name and "\\" in name:
        domain, name = name.split("\\", 1)
    return (name.lower() if name else None), _clean(domain)


# --------------------------------------------------------------------------- windows

_TASK_CMD = re.compile(r"<Command>(.*?)</Command>(?:\s*<Arguments>(.*?)</Arguments>)?", re.S | re.I)


def parse_windows(d: dict) -> dict:
    ed = d.get("EventData") or {}
    eid = _int(d.get("EventID"))
    channel = str(d.get("Channel", "")).lower()
    sysmon = "sysmon" in channel or "sysmon" in str(d.get("Provider", "")).lower()
    out: dict[str, Any] = {"host": d.get("Computer") or d.get("host"), "timestamp": _ts(d.get("TimeCreated")),
                           "raw_reference": f"{d.get('Channel', 'windows')}/{eid}/{d.get('EventRecordID', '')}".strip("/")}
    user, domain = _user(ed.get("SubjectDomainName"), ed.get("SubjectUserName") or ed.get("User"))
    out["actor"] = {"user": user, "domain": domain}

    if (sysmon and eid == 1) or (not sysmon and eid == 4688):
        img = ed.get("Image") or ed.get("NewProcessName")
        parent = ed.get("ParentImage") or ed.get("ParentProcessName")
        hashes = str(ed.get("Hashes", ""))
        m = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes)
        out["event_type"] = "process_creation"
        # 4688: NewProcessId is the child, ProcessId the creator. Sysmon 1: ProcessId / ParentProcessId.
        pid, ppid = (ed.get("ProcessId"), ed.get("ParentProcessId")) if sysmon else (ed.get("NewProcessId"), ed.get("ProcessId"))
        out["process"] = {"name": basename(img), "path": _clean(img), "pid": _int(pid),
                          "command_line": _clean(ed.get("CommandLine")), "parent_name": basename(parent),
                          "parent_pid": _int(ppid),
                          "parent_command_line": _clean(ed.get("ParentCommandLine")), "hash_sha256": m.group(1).lower() if m else None}
    elif sysmon and eid == 3:
        out["event_type"] = "network_connection"
        out["process"] = {"name": basename(ed.get("Image")), "path": _clean(ed.get("Image"))}
        out["network"] = {"src_ip": _clean(ed.get("SourceIp")), "src_port": _int(ed.get("SourcePort")),
                          "dst_ip": _clean(ed.get("DestinationIp")), "dst_port": _int(ed.get("DestinationPort")),
                          "dst_domain": _clean(ed.get("DestinationHostname")), "protocol": _clean(ed.get("Protocol")),
                          "direction": "outbound" if str(ed.get("Initiated", "true")).lower() == "true" else "inbound",
                          "outcome": "allowed"}
    elif sysmon and eid == 22:
        out["event_type"] = "dns_query"
        out["process"] = {"name": basename(ed.get("Image")), "path": _clean(ed.get("Image"))}
        out["network"] = {"dst_domain": _clean(ed.get("QueryName")), "protocol": "dns", "direction": "outbound"}
    elif eid in (4624, 4625):
        tu, td = _user(ed.get("TargetDomainName"), ed.get("TargetUserName"))
        out["event_type"] = "authentication"
        out["actor"] = {"user": tu, "domain": td}
        out["auth"] = {"outcome": "success" if eid == 4624 else "failure", "logon_type": _int(ed.get("LogonType")),
                       "method": _clean(ed.get("AuthenticationPackageName"))}
        out["network"] = {"src_ip": _clean(ed.get("IpAddress")), "src_port": _int(ed.get("IpPort")), "direction": "inbound"}
        out["process"] = {"name": basename(ed.get("ProcessName"))}
    elif eid == 4720:
        out["event_type"] = "user_account_created"
        out["actor"]["target_user"] = (_clean(ed.get("TargetUserName")) or "").lower() or None
    elif eid in (4732, 4733, 4728, 4756):
        member = _clean(ed.get("MemberName")) or _clean(ed.get("MemberSid"))
        if member and member.upper().startswith("CN="):
            member = member.split(",")[0][3:]
        out["event_type"] = "user_group_change"
        out["group"] = {"name": _clean(ed.get("TargetUserName")), "member": member.lower() if member else None,
                        "action": "removed" if eid == 4733 else "added"}
        out["actor"]["target_user"] = member.lower() if member else None
    elif eid == 7045:
        out["event_type"] = "service_creation"
        out["service"] = {"name": _clean(ed.get("ServiceName")), "path": _clean(ed.get("ImagePath")),
                          "start_type": _clean(ed.get("StartType")), "account": _clean(ed.get("AccountName"))}
        out["process"] = {"command_line": _clean(ed.get("ImagePath"))}
    elif eid == 4698:
        content = str(ed.get("TaskContent", ""))
        m = _TASK_CMD.search(content)
        cmd = " ".join(x for x in (m.group(1), m.group(2)) if x).strip() if m else None
        out["event_type"] = "scheduled_task_creation"
        out["task"] = {"name": _clean(ed.get("TaskName")), "command": cmd, "author": user}
        out["process"] = {"command_line": cmd}
    elif eid in (5156, 5157):
        direction = {"%%14592": "inbound", "%%14593": "outbound"}.get(str(ed.get("Direction")), "unknown")
        out["event_type"] = "network_connection"
        out["process"] = {"name": basename(ed.get("Application")), "path": _clean(ed.get("Application"))}
        out["network"] = {"src_ip": _clean(ed.get("SourceAddress")), "src_port": _int(ed.get("SourcePort")),
                          "dst_ip": _clean(ed.get("DestAddress")), "dst_port": _int(ed.get("DestPort")),
                          "protocol": {"6": "tcp", "17": "udp"}.get(str(ed.get("Protocol")), _clean(ed.get("Protocol"))),
                          "direction": direction, "outcome": "blocked" if eid == 5157 else "allowed"}
    elif eid == 5154:
        out["event_type"] = "network_listen"
        out["process"] = {"name": basename(ed.get("Application")), "path": _clean(ed.get("Application"))}
        out["network"] = {"src_ip": _clean(ed.get("SourceAddress")), "src_port": _int(ed.get("SourcePort")),
                          "dst_port": _int(ed.get("SourcePort")),
                          "protocol": {"6": "tcp", "17": "udp"}.get(str(ed.get("Protocol")), "tcp"), "direction": "listen"}
    else:
        out["event_type"] = f"windows_event_{eid}" if eid else "windows_event"
        out["message"] = _clean(d.get("Message"))
    return out


# --------------------------------------------------------------------------- linux

_SSH_FAIL = re.compile(r"Failed \S+ for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_SSH_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")


def parse_linux(d: dict) -> dict:
    out: dict[str, Any] = {"host": d.get("hostname") or d.get("host"), "timestamp": _ts(d.get("timestamp")),
                           "raw_reference": _clean(d.get("raw_reference"))}
    kind = d.get("type")
    if kind == "process":
        out["event_type"] = "process_creation"
        out["actor"] = {"user": _clean(d.get("user"))}
        out["process"] = {"name": basename(d.get("exe") or d.get("comm")), "path": _clean(d.get("exe")), "pid": _int(d.get("pid")),
                          "command_line": _clean(d.get("cmdline")), "parent_name": basename(d.get("parent_exe") or d.get("parent_comm")),
                          "parent_pid": _int(d.get("ppid"))}
        return out
    msg = str(d.get("message", ""))
    if m := _SSH_FAIL.search(msg):
        out.update(event_type="authentication", actor={"user": m.group(1).lower()},
                   auth={"outcome": "failure", "method": "ssh"},
                   network={"src_ip": m.group(2), "src_port": int(m.group(3)), "dst_port": 22, "direction": "inbound"})
    elif m := _SSH_OK.search(msg):
        out.update(event_type="authentication", actor={"user": m.group(2).lower()},
                   auth={"outcome": "success", "method": f"ssh-{m.group(1)}"},
                   network={"src_ip": m.group(3), "src_port": int(m.group(4)), "dst_port": 22, "direction": "inbound"})
    else:
        out["event_type"] = "syslog"
    out["message"] = msg[:8192] or None
    return out


# --------------------------------------------------------------------------- docker

def parse_docker(d: dict) -> dict:
    actor = d.get("Actor") or {}
    attrs = actor.get("Attributes") or {}
    action = str(d.get("Action") or d.get("action") or "").split(":")[0]
    event_type = {"start": "container_start", "create": "container_start", "exec_start": "container_exec",
                  "exec_create": "container_exec"}.get(action, f"container_{action or 'event'}")
    ports = d.get("host_ports") or attrs.get("host_ports") or []
    if isinstance(ports, str):
        ports = [p for p in re.split(r"[,\s]+", ports) if p]
    image = attrs.get("image") or d.get("image")
    return {
        "host": d.get("host") or attrs.get("host"),
        "timestamp": _ts(d.get("timeNano") or d.get("time")),
        "event_type": event_type,
        "container": {"id": _clean(actor.get("ID"))[:12] if actor.get("ID") else None, "name": _clean(attrs.get("name")),
                      "image": normalize_image(image) if image else None, "host_ports": [p for p in (_int(x) for x in ports) if p],
                      "privileged": bool(d.get("privileged", attrs.get("privileged", False))), "action": action or None},
        "process": {"command_line": _clean(attrs.get("execCommand") or d.get("command"))},
        "actor": {"user": _clean(d.get("user"))},
    }


# --------------------------------------------------------------------------- kubernetes

def parse_kubernetes(d: dict) -> dict:
    ref = d.get("objectRef") or {}
    req = d.get("requestObject") or {}
    spec = req.get("spec") or {}
    containers = [*(spec.get("containers") or []), *(spec.get("initContainers") or [])]
    privileged = any(((c.get("securityContext") or {}).get("privileged") is True) for c in containers if isinstance(c, dict))
    src = (d.get("sourceIPs") or [None])[0]
    image = next((c.get("image") for c in containers if isinstance(c, dict) and c.get("image")), None)
    return {
        "host": d.get("host") or (d.get("annotations") or {}).get("cluster") or "kubernetes",
        "timestamp": _ts(d.get("stageTimestamp") or d.get("requestReceivedTimestamp")),
        "event_type": "k8s_audit",
        "actor": {"user": _clean((d.get("user") or {}).get("username"))},
        "network": {"src_ip": _clean(src), "direction": "inbound"},
        "k8s": {"verb": _clean(d.get("verb")), "resource": _clean(ref.get("resource")), "subresource": _clean(ref.get("subresource")),
                "namespace": _clean(ref.get("namespace")), "name": _clean(ref.get("name")), "privileged": privileged,
                "role": _clean((req.get("roleRef") or {}).get("name"))},
        "container": {"image": normalize_image(image) if image else None},
        "raw_reference": _clean(d.get("auditID")),
    }


def parse_generic(d: dict) -> dict:
    return dict(d)


registry.event_parsers.update(windows=parse_windows, linux=parse_linux, docker=parse_docker,
                              kubernetes=parse_kubernetes, generic=parse_generic)


def _prune(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def normalize(item: EventIn) -> NormalizedEvent:
    parser = registry.event_parsers.get(item.source)
    if not parser:
        raise NormalizationError(f"no parser for source {item.source!r}")
    try:
        out = parser(item.data)
    except (TypeError, AttributeError, KeyError) as e:
        raise NormalizationError(f"{item.source} parser could not read record: {e}") from e
    for k in ("actor", "process", "network", "auth", "service", "task", "group", "container", "k8s", "file"):
        if isinstance(out.get(k), dict):
            out[k] = _prune(out[k])
    out["source"] = item.source
    out["simulated"] = bool(item.simulated or item.data.get("simulated") or out.get("simulated"))
    if not out.get("host"):
        raise NormalizationError("event has no host")
    out["event_id"] = str(item.data.get("event_id") or out.get("event_id") or f"evt-{stable_hash([item.source, item.data])[:24]}")
    out.setdefault("timestamp", datetime.now(timezone.utc))
    try:
        return NormalizedEvent.model_validate(out)
    except ValueError as e:
        raise NormalizationError(f"normalized event invalid: {e}") from e
