from datetime import datetime, timedelta, timezone

from sentinelforge.schemas.event import EventIn
from app.services import discovery, environments, rules
from app.services.detection.engine import engine
from app.services.detection.pipeline import ingest
from sentinelforge.rules.evaluator import compile_node
from app.services.simulation import CRADLE, ENCODED, SCENARIOS, benign_events, proc, scenario_events, win

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
HOST = "WEB-SRV-01"


def _setup(db, template="windows-web-server"):
    env = environments.upsert_environment(db, discovery.load_demo_inventory(template), "demo")
    rules.generate_rules(db, env)
    return env


def _fired(db, items):
    from app.models import Detection

    ingest(db, items)
    return {d.rule_id for d in db.query(Detection).all()}


def test_office_to_powershell_triggers(db):
    _setup(db)
    ev = proc(HOST, datetime.now(timezone.utc), PS, f"{PS} -nop -c \"{CRADLE}\"", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
    fired = _fired(db, [ev])
    assert "DET-WIN-001" in fired and "DET-WIN-010" in fired


def test_normal_powershell_does_not_trigger(db):
    _setup(db)
    ev = proc(HOST, datetime.now(timezone.utc), PS, "powershell.exe -NoProfile -File C:\\Ops\\healthcheck.ps1", "C:\\Windows\\explorer.exe")
    assert _fired(db, [ev]) == set()


def test_encoded_command(db):
    _setup(db)
    ev = win(HOST, 4688, datetime.now(timezone.utc), {"NewProcessName": PS, "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                                                       "CommandLine": f"powershell.exe -enc {ENCODED}"})
    assert _fired(db, [ev]) == {"DET-WIN-002"}
    # "-ExecutionPolicy Bypass" must not look like an encoded command
    ev2 = win(HOST, 4688, datetime.now(timezone.utc), {"NewProcessName": PS, "ParentProcessName": "C:\\Windows\\explorer.exe",
                                                        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\Ops\\x.ps1"})
    assert _fired(db, [ev2]) == {"DET-WIN-002"}  # unchanged: no new detection


def test_every_scenario_fires_its_expected_rules(db):
    env = _setup(db)
    names = [n for n, s in SCENARIOS.items() if s.platform in ("windows", "network", "docker")]
    fired = _fired(db, scenario_events(names, env.hostname))
    for n in names:
        assert set(SCENARIOS[n].expected_rules) <= fired, n


def test_benign_workload_is_filtered(db):
    env = _setup(db)
    items = benign_events(env.hostname, env.platform, env.profiles[-1].profile, 1500, seed=7)
    res = ingest(db, items)
    assert res.accepted == 1500 and res.matched == 0


def test_inactive_rules_do_not_fire(db):
    env = _setup(db, "windows-workstation")  # no Docker, no IIS
    fired = _fired(db, scenario_events(["unapproved_image", "iis_webshell"], env.hostname))
    assert fired == set()


def test_threshold_rule_fires_once_per_burst(db):
    _setup(db)
    t = datetime.now(timezone.utc)
    fails = [win(HOST, 4625, t + timedelta(seconds=i), {"TargetUserName": "a", "LogonType": 3, "IpAddress": "203.0.113.9"}) for i in range(4)]
    assert _fired(db, fails) == set()
    # 5th failure fires and resets the window; the following 4 stay below the threshold again
    more = [win(HOST, 4625, t + timedelta(seconds=10 + i), {"TargetUserName": "a", "LogonType": 3, "IpAddress": "203.0.113.9"}) for i in range(5)]
    from app.models import Detection
    ingest(db, more)
    assert db.query(Detection).filter_by(rule_id="DET-WIN-008").count() == 1


def test_threshold_window_expires(db):
    _setup(db)
    t = datetime.now(timezone.utc) - timedelta(hours=2)
    spread = [win(HOST, 4625, t + timedelta(minutes=10 * i), {"TargetUserName": "a", "LogonType": 3, "IpAddress": "203.0.113.9"}) for i in range(6)]
    assert _fired(db, spread) == set()


def test_unknown_host_uses_baseline_rules(db):
    _setup(db)
    ev = proc("UNKNOWN-HOST", datetime.now(timezone.utc), PS, "powershell.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE")
    from app.models import Detection
    ingest(db, [ev])
    det = db.query(Detection).filter_by(rule_id="DET-WIN-001").one()
    assert det.environment_id is None and det.confidence == 0.8  # 0.9 fidelity - 0.1 no-profile penalty


def test_disabled_rule_stops_firing(api):
    env = api.post("/api/v1/demo/environment", json={}).json()
    api.post(f"/api/v1/profiles/{env['id']}/generate-rules")
    rows = {a["rule_id"]: a for a in api.get(f"/api/v1/environments/{env['id']}").json()["rules"]}
    r = api.patch(f"/api/v1/environments/{env['id']}/rules/{rows['DET-WIN-011']['assignment_id']}", json={"status": "disabled"})
    assert r.status_code == 200
    res = api.post("/api/v1/demo/simulate", json={"environment_id": env["id"], "scenarios": ["iis_webshell"]}).json()
    assert res["result"]["detections"] == 0
    # regeneration keeps the analyst's decision
    api.post(f"/api/v1/profiles/{env['id']}/generate-rules")
    rows = {a["rule_id"]: a for a in api.get(f"/api/v1/environments/{env['id']}").json()["rules"]}
    assert rows["DET-WIN-011"]["status"] == "disabled"


def test_duplicate_events_are_not_reevaluated(db):
    _setup(db)
    ev = scenario_events(["iis_webshell"], HOST)
    assert ingest(db, ev).detections == 1
    again = ingest(db, ev)
    assert again.duplicates == 1 and again.detections == 0


def test_operator_semantics():
    ev = {"network": {"src_ip": "203.0.113.5", "dst_port": 4444}, "container": {"host_ports": [8080, 4444]}, "process": {"name": "CMD.EXE"}}
    assert compile_node({"process.name": "cmd.exe"})(ev)  # case-insensitive
    assert compile_node({"network.src_ip|not_cidr": ["10.0.0.0/8"]})(ev)
    assert not compile_node({"network.src_ip|cidr": ["10.0.0.0/8"]})(ev)
    assert compile_node({"container.host_ports|not_in": [8080]})(ev)  # any element outside the set
    assert not compile_node({"container.host_ports|not_in": [8080, 4444]})(ev)
    assert compile_node({"network.dst_port|gte": 4444})(ev)
    assert not compile_node({"network.dst_ip|not_cidr": ["10.0.0.0/8"]})(ev)  # missing field never matches
    assert compile_node({"network.dst_ip|exists": False})(ev)
    assert not compile_node({"network.src_ip|not_cidr": ["10.0.0.0/8"]})({"network": {"src_ip": "not-an-ip"}})


def test_engine_cache_invalidated_on_generation(db):
    env = _setup(db)
    assert engine.rules_for(db, env.id)
    rules.generate_rules(db, env)
    assert env.id not in engine._cache


def test_rejected_input_counts(db):
    bad = [EventIn(source="windows", data={"EventID": 4688}), EventIn(source="generic", data={"host": "h", "event_type": "Bad Type"})]
    res = ingest(db, bad)
    assert res.rejected == 2 and res.accepted == 0 and len(res.errors) == 2
