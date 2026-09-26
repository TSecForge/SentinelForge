"""Shipper-facing ingest endpoint and the record shapes common shippers emit."""

import json

WINLOGBEAT = {
    "@timestamp": "2026-09-23T10:22:11.000Z",
    "host": {"name": "WEB-SRV-01"},
    "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1, "record_id": 4411,
               "computer_name": "WEB-SRV-01.corp.example", "provider_name": "Microsoft-Windows-Sysmon",
               "event_data": {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami",
                              "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "User": "IIS APPPOOL\\web"}},
    "message": "Process Create",
}


def _env(api):
    env = api.post("/api/v1/demo/environment", json={}).json()
    api.post(f"/api/v1/profiles/{env['id']}/generate-rules")
    return env


def test_winlogbeat_json_array(api):
    _env(api)
    doc = dict(WINLOGBEAT, winlog=dict(WINLOGBEAT["winlog"], computer_name="WEB-SRV-01"))
    r = api.post("/api/v1/ingest/windows", content=json.dumps([doc])).json()
    assert r["accepted"] == 1 and r["detections"] == 1
    det = api.get("/api/v1/detections").json()["items"][0]
    assert det["rule_id"] == "DET-WIN-011" and det["host"] == "WEB-SRV-01"


def test_ndjson_with_host_override(api):
    _env(api)
    lines = [{"Type": "container", "Action": "start", "time": 1790000000,
              "Actor": {"ID": "a" * 64, "Attributes": {"image": "registry.example.net/tools/x:latest", "name": "x"}}},
             {"Type": "container", "Action": "start", "time": 1790000001,
              "Actor": {"ID": "b" * 64, "Attributes": {"image": "nginx:1.25", "name": "y"}}}]
    body = "\n".join(json.dumps(x) for x in lines)
    r = api.post("/api/v1/ingest/docker?host=WEB-SRV-01", content=body).json()
    assert r["accepted"] == 2 and r["detections"] == 1  # only the unapproved image


def test_fluent_bit_and_vector_syslog_shapes(api):
    records = [
        {"date": 1790000000.5, "host": "DOCKER-01", "ident": "sshd", "message": "Failed password for root from 203.0.113.4 port 5555 ssh2"},
        {"timestamp": "2026-09-23T10:00:00Z", "hostname": "DOCKER-01", "appname": "sshd",
         "message": "Accepted publickey for deploy from 10.10.60.5 port 51000 ssh2"},
        {"_HOSTNAME": "DOCKER-01", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "Failed password for admin from 203.0.113.4 port 5556 ssh2"},
    ]
    r = api.post("/api/v1/ingest/linux", content=json.dumps({"events": records})).json()
    assert r["accepted"] == 3 and r["rejected"] == 0
    evs = api.get("/api/v1/events", params={"source": "linux"}).json()["items"]
    assert {e["event_type"] for e in evs} == {"authentication"} and {e["host"] for e in evs} == {"DOCKER-01"}


def test_kubernetes_audit_webhook_eventlist_with_bearer(api, settings):
    from pydantic import SecretStr

    settings.api_key = SecretStr("k8s-key")
    body = {"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": [
        {"kind": "Event", "verb": "create", "user": {"username": "dev"}, "stageTimestamp": "2026-09-23T10:00:00Z",
         "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "prod", "name": "api-1"}}]}
    assert api.post("/api/v1/ingest/kubernetes?host=prod-cluster", json=body).status_code == 401
    r = api.post("/api/v1/ingest/kubernetes?host=prod-cluster", json=body, headers={"Authorization": "Bearer k8s-key"})
    assert r.status_code == 200 and r.json()["accepted"] == 1
    ev = api.get("/api/v1/events", params={"source": "kubernetes"}, headers={"X-API-Key": "k8s-key"}).json()["items"][0]
    assert ev["host"] == "prod-cluster" and ev["event_type"] == "k8s_audit"


def test_ingest_validation(api):
    assert api.post("/api/v1/ingest/Bad!", content="{}").status_code == 422
    assert api.post("/api/v1/ingest/linux", content="not json at all\nnope").status_code == 400
    assert api.post("/api/v1/ingest/linux", content="[1, 2]").status_code == 422
    assert api.post("/api/v1/ingest/linux?host=bad host", content="{}").status_code == 422
    assert api.post("/api/v1/ingest/linux", content="").json()["received"] == 0
