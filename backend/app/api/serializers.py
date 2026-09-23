from app.models import Detection, Event
from app.utils import iso


def event_out(e: Event, full: bool = False) -> dict:
    out = {"id": e.id, "event_id": e.event_id, "timestamp": iso(e.timestamp), "received_at": iso(e.received_at),
           "source": e.source, "host": e.host, "event_type": e.event_type, "environment_id": e.environment_id,
           "simulated": e.simulated, "matched": e.matched, "max_severity": e.max_severity}
    d = e.data
    out["summary"] = (d.get("process", {}).get("command_line") or d.get("message") or d.get("container", {}).get("image")
                      or " ".join(str(v) for v in [d.get("actor", {}).get("user"), d.get("network", {}).get("src_ip"),
                                                    d.get("network", {}).get("dst_ip"), d.get("network", {}).get("dst_port")] if v) or "")[:240]
    if full:
        out["data"] = d
    return out


def detection_out(d: Detection, full: bool = False) -> dict:
    out = {"id": d.id, "detection_id": d.detection_id, "timestamp": iso(d.timestamp), "created_at": iso(d.created_at),
           "host": d.host, "environment_id": d.environment_id, "rule_id": d.rule_id, "rule_name": d.rule_name,
           "rule_version": d.rule_version, "severity": d.severity, "confidence": d.confidence, "event_type": d.event_type,
           "description": d.description, "mitre_tactic": d.mitre_tactic, "mitre_technique": d.mitre_technique,
           "simulated": d.simulated, "delivery_status": d.delivery_status,
           "observables": [{"type": o.type, "value": o.value} for o in d.observables]}
    if full:
        out["payload"] = d.payload
    return out
