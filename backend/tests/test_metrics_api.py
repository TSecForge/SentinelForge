from pydantic import SecretStr

from app.services.metrics import reduction_percentage


def test_reduction_formula():
    assert reduction_percentage(10000, 37) == 99.63
    assert reduction_percentage(0, 0) == 0.0
    assert reduction_percentage(100, 100) == 0.0


def test_full_demo_metrics(api):
    r = api.post("/api/v1/demo/run", json={"benign_count": 500})
    assert r.status_code == 200
    res = r.json()["result"]
    m = api.get("/api/v1/metrics").json()
    assert m["events_received"] == res["received"]
    assert m["events_matched"] == res["matched"] and m["events_filtered"] == res["accepted"] - res["matched"]
    assert m["events_forwarded"] == res["matched"] and m["detections_created"] == res["detections"]
    assert 0 <= m["reduction_percentage"] <= 100


def test_multi_rule_event_does_not_make_reduction_negative(api):
    env = api.post("/api/v1/demo/environment", json={}).json()
    api.post(f"/api/v1/profiles/{env['id']}/generate-rules")
    r = api.post("/api/v1/demo/simulate", json={"environment_id": env["id"], "scenarios": ["office_powershell"]}).json()["result"]
    assert r["received"] == 1 and r["detections"] == 2  # one event, two rules
    m = api.get("/api/v1/metrics").json()
    assert m["events_forwarded"] == 1 and m["reduction_percentage"] == 0.0
    assert m["reduction_percentage"] == reduction_percentage(m["events_received"], m["events_forwarded"])
    assert "In this workload" in m["statement"]


def test_dashboard_and_views(api):
    api.post("/api/v1/demo/run", json={"benign_count": 200})
    s = api.get("/api/v1/dashboard/summary").json()
    assert s["hosts"] == 1 and s["active_rules"] > 0 and s["detections"] > 0 and s["recent_detections"]
    assert s["event_volume"] and s["severity_distribution"]
    det = s["recent_detections"][0]
    full = api.get(f"/api/v1/detections/{det['detection_id']}").json()
    p = full["payload"]
    for key in ("host", "timestamp", "rule", "description", "severity", "observables", "event", "confidence_basis"):
        assert key in p
    assert p["simulated"] is True and full["source_event"]["simulated"] is True
    evs = api.get("/api/v1/events", params={"matched": True, "host": "WEB-SRV-01"}).json()
    assert evs["total"] > 0 and all(e["matched"] for e in evs["items"])
    assert api.get("/api/v1/events", params={"severity": "critical"}).json()["total"] >= 1


def test_acceptance_flow_step_by_step(api):
    env = api.post("/api/v1/demo/environment", json={"template": "windows-web-server"}).json()
    assert env["simulated"] and env["profile"]["technologies"]
    gen = api.post(f"/api/v1/profiles/{env['id']}/generate-rules").json()
    assert gen["counts"]["active"] > 0 and gen["counts"]["not_applicable"] > 0
    sim = api.post("/api/v1/demo/simulate", json={"environment_id": env["id"], "scenarios": ["office_powershell"]}).json()
    assert sim["result"]["detections"] >= 1
    det = api.get("/api/v1/detections", params={"rule_id": "DET-WIN-001"}).json()["items"][0]
    assert det["severity"] == "high" and det["rule_name"] == "Office Application Spawning PowerShell"
    assert det["mitre_technique"] == "T1059.001" and det["observables"]


def test_input_validation(api):
    assert api.post("/api/v1/events", json={"source": "Bad Source!", "data": {}}).status_code == 422
    r = api.post("/api/v1/events", json={"source": "martian", "data": {"host": "h"}}).json()  # no parser registered
    assert r["rejected"] == 1 and "no parser" in r["errors"][0]
    assert api.post("/api/v1/events/batch", json={"events": []}).status_code == 422
    assert api.post("/api/v1/demo/simulate", json={"environment_id": 99999}).status_code == 404
    assert api.get("/api/v1/events", params={"limit": 100000}).status_code == 422


def test_batch_limit(api, settings):
    settings.max_batch_events = 2
    ev = {"source": "generic", "data": {"host": "H", "event_type": "x"}}
    assert api.post("/api/v1/events/batch", json={"events": [ev, ev, ev]}).status_code == 413


def test_api_key_enforced_when_configured(api, settings):
    settings.api_key = SecretStr("k-1")
    assert api.get("/api/v1/metrics").status_code == 401
    assert api.get("/api/v1/metrics", headers={"X-API-Key": "wrong"}).status_code == 401
    assert api.get("/api/v1/metrics", headers={"X-API-Key": "k-1"}).status_code == 200
    assert api.get("/api/v1/health").status_code == 200  # health and about stay public
    assert api.get("/api/v1/about").status_code == 200


def test_about_keeps_upstream_attribution_when_rebranded(api, settings):
    settings.project_name = "Acme SOC Platform"
    settings.organization_name = "Acme"
    a = api.get("/api/v1/about").json()
    assert a["branding"]["project_name"] == "Acme SOC Platform" and a["branding"]["customized"] is True
    assert a["upstream"]["name"] == "SentinelForge" and a["upstream"]["original_creator"] == "Sujhal Gurav"
