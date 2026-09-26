import json

from app.services import discovery, environments, rules
from app.services.discovery import parse_inventory
from sentinelforge.profiling import build_profile, normalize_image


def _profile(name):
    return build_profile(discovery.load_demo_inventory(name))


def _statuses(db, template):
    env = environments.upsert_environment(db, discovery.load_demo_inventory(template), "demo")
    rules.generate_rules(db, env)
    return {a["rule_id"]: a["status"] for a in environments.assignments(db, env.id)}


def test_web_server_profile():
    p = _profile("windows-web-server")
    assert {"IIS", "RDP", "WinRM", "Docker", "PowerShell"} <= set(p.technologies)
    assert {"windows", "server", "web_server", "remote_access", "container_host"} <= set(p.environment_type)
    assert p.risk_context.remote_access and p.risk_context.containerized
    assert not p.risk_context.internet_facing_indicator  # only private addresses
    assert "10.10.20.0/24" in p.network.cidrs
    assert {e.port for e in p.exposed_services} >= {80, 443, 3389, 5985}
    assert 2375 not in {e.port for e in p.exposed_services}  # loopback-only listener is not "exposed"
    assert "nginx:1.25" in p.parameters.approved_images
    assert p.parameters.container_ports == [8080, 8443, 9100, 15672]
    assert "backup-admin" in p.parameters.known_admins
    assert p.evidence["IIS"]  # every conclusion carries evidence


def test_workstation_has_no_server_technologies():
    p = _profile("windows-workstation")
    assert "workstation" in p.environment_type
    assert not {"IIS", "RDP", "Docker", "WinRM"} & set(p.technologies)


def test_docker_present_enables_docker_rules(db):
    s = _statuses(db, "windows-web-server")
    assert s["DET-DOCKER-001"] == s["DET-DOCKER-002"] == s["DET-DOCKER-003"] == "active"


def test_docker_absent_disables_docker_rules(db):
    s = _statuses(db, "windows-workstation")
    assert s["DET-DOCKER-001"] == "not_applicable"
    assert s["DET-WIN-001"] == "active"  # PowerShell still exists on a workstation


def test_rdp_present_enables_rdp_rules(db):
    assert _statuses(db, "windows-web-server")["DET-WIN-007"] == "active"


def test_rdp_absent_disables_rdp_rules(db):
    assert _statuses(db, "windows-workstation")["DET-WIN-007"] == "not_applicable"


def test_iis_rule_only_on_iis_hosts(db):
    assert _statuses(db, "windows-web-server")["DET-WIN-011"] == "active"
    assert _statuses(db, "windows-workstation")["DET-WIN-011"] == "not_applicable"


def test_kubernetes_rules_follow_kubernetes(db):
    s = _statuses(db, "linux-k8s-node")
    assert s["DET-K8S-001"] == "active" and s["DET-LNX-001"] == "active"
    assert s["DET-WIN-001"] == "not_applicable"
    assert _statuses(db, "windows-web-server")["DET-K8S-001"] == "not_applicable"


def test_generated_rule_is_environment_specific(db):
    env = environments.upsert_environment(db, discovery.load_demo_inventory("windows-web-server"), "demo")
    rules.generate_rules(db, env)
    gen = {a["rule_id"]: a["generated"] for a in environments.assignments(db, env.id)}
    assert "nginx:1.25" in gen["DET-DOCKER-001"]["selection"]["container.image|not_in"]
    assert "$profile" not in json.dumps(gen["DET-NET-002"])


def test_regeneration_is_versioned_not_overwritten(db):
    env = environments.upsert_environment(db, discovery.load_demo_inventory("windows-web-server"), "demo")
    first = rules.generate_rules(db, env)
    again = rules.generate_rules(db, env)
    assert first["new_or_updated"] == len(rules.current_templates(db)) and again["new_or_updated"] == 0
    # re-discover with an extra image: only the image rule gets a new assignment version
    inv = discovery.load_demo_inventory("windows-web-server")
    inv.containers.images.append("busybox:1.36")
    env = environments.upsert_environment(db, inv, "demo")
    third = rules.generate_rules(db, env)
    assert third["new_or_updated"] == 1


def test_normalize_image():
    assert normalize_image("NGINX") == "nginx:latest"
    assert normalize_image("registry.example.net:5000/app") == "registry.example.net:5000/app:latest"
    assert normalize_image("redis:7") == "redis:7"


def test_live_style_inventory_profiles():
    raw = json.loads((discovery.DEMO_DIR / "windows-web-server.json").read_text(encoding="utf-8"))
    raw["remote_access"]["rdp_enabled"] = False
    raw["network"]["listening_ports"] = [p for p in raw["network"]["listening_ports"] if p["port"] != 3389]
    assert "RDP" not in build_profile(parse_inventory(raw)).technologies
