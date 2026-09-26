"""Enrichment: turn (event, matched rule, environment context) into a sentinelforge.detection.v1 document."""

import ipaddress
import uuid
from typing import Any

from sentinelforge.ioc import extract_observables
from sentinelforge.rules.evaluator import CompiledRule, render_summary
from sentinelforge._util import get_path

# Deterministic, documented confidence: it is the rule author's fidelity rating, nothing learned.
FIDELITY_CONFIDENCE = {"high": 0.9, "medium": 0.7, "low": 0.5}
NO_PROFILE_PENALTY = 0.1


def _classify_ip(value: str, internal: list[str]) -> str | None:
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return None
    for c in internal:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if ip.version == n.version and ip in n:
            return "internal"
    return "external"


def build_detection(event: dict, rule: CompiledRule, env: dict | None, assignment: dict | None) -> dict[str, Any]:
    """env: {"id", "profile"} for known hosts, None for events from hosts SentinelForge has not profiled."""
    d = rule.definition
    profile = (env or {}).get("profile") or {}
    params = profile.get("parameters", {})
    base = FIDELITY_CONFIDENCE[d.fidelity]
    confidence = round(base - (0 if env else NO_PROFILE_PENALTY), 2)
    basis = f"rule fidelity '{d.fidelity}' = {base}" + ("" if env else f"; -{NO_PROFILE_PENALTY} host has no environment profile")

    observables = extract_observables(event)
    internal = params.get("internal_cidrs", [])
    for o in observables:
        if o["type"] in ("ipv4", "ipv6") and internal:
            o["context"] = f"{o['context']}; {_classify_ip(o['value'], internal)} to host's internal ranges"

    port = get_path(event, "network.dst_port")
    related = [s for s in profile.get("exposed_services", []) if port and s.get("port") == port]
    evidence = {f: get_path(event, f) for f in rule.fields}
    if d.threshold:
        evidence.update({g: get_path(event, g) for g in d.threshold.group_by})
        evidence["threshold"] = d.threshold.model_dump()

    return {
        "schema": "sentinelforge.detection.v1",
        "detection_id": f"det-{uuid.uuid4().hex[:16]}",
        "timestamp": event["timestamp"],
        "host": event["host"],
        "rule": {"id": d.id, "name": d.name, "version": d.version, "source": d.source, "author": d.author},
        "severity": d.severity,
        "confidence": max(0.0, confidence),
        "confidence_basis": basis,
        "event_type": event["event_type"],
        "description": d.description,
        "summary": render_summary(d.summary, event) if d.summary else d.name,
        "mitre": d.mitre.model_dump() if d.mitre else None,
        "observables": observables,
        "evidence": evidence,
        "context": {
            "environment_id": (env or {}).get("id"),
            "environment_profiled": env is not None,
            "environment_type": profile.get("environment_type", []),
            "technologies": profile.get("technologies", []),
            "host_ips": profile.get("network", {}).get("ip_addresses", []),
            "related_exposed_services": related,
            "rule_selected_because": (assignment or {}).get("reason", "baseline rule (host not profiled)"),
            "tags": d.tags,
            "false_positives": d.false_positives,
        },
        "source": {"type": event["source"], "event_id": event["event_id"], "raw_reference": event.get("raw_reference")},
        "simulated": bool(event.get("simulated")),
        "event": event,
    }
