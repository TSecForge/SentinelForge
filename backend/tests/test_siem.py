from pydantic import SecretStr

from app.services.siem import gateway
from app.services.siem.adapters import ElasticAdapter, SplunkHecAdapter, WebhookAdapter, redact_url

DOC = {"schema": "sentinelforge.detection.v1", "detection_id": "det-1", "timestamp": "2026-09-23T10:22:11Z",
       "host": "WEB-SRV-01", "severity": "high", "rule": {"id": "DET-WIN-001"}}


def test_webhook_format(settings):
    settings.webhook_url = "https://siem.example.net/hook"
    url, headers, body = WebhookAdapter(settings).build(DOC)
    assert url == "https://siem.example.net/hook" and body == DOC and headers["Content-Type"] == "application/json"


def test_splunk_hec_format(settings):
    settings.splunk_hec_url = "https://splunk.example.net:8088/services/collector/event"
    settings.splunk_hec_token = SecretStr("tok-123")
    settings.splunk_index = "security"
    a = SplunkHecAdapter(settings)
    url, headers, body = a.build(DOC)
    assert headers["Authorization"] == "Splunk tok-123"
    assert body["event"] == DOC and body["index"] == "security" and body["sourcetype"] == "sentinelforge:detection"
    assert body["time"] == 1790158931.0 and body["host"] == "WEB-SRV-01"
    assert "tok-123" not in a.target()


def test_elastic_format(settings):
    settings.elastic_url = "https://es.example.net:9200/"
    settings.elastic_api_key = SecretStr("key")
    url, headers, body = ElasticAdapter(settings).build(DOC)
    assert url == "https://es.example.net:9200/sentinelforge-detections/_doc"
    assert headers["Authorization"] == "ApiKey key" and body["@timestamp"] == DOC["timestamp"]


def test_redact_url_hides_credentials():
    assert redact_url("https://user:pass@h.example.net:8443/p?token=abc") == "https://h.example.net:8443/p"


def test_forward_records_attempts(api, settings, monkeypatch):
    settings.siem_mode = "webhook"
    settings.webhook_url = "http://127.0.0.1:9/never"
    sent = []
    monkeypatch.setattr(WebhookAdapter, "send", lambda self, doc: (sent.append(doc), (True, 202, None))[1])
    env = api.post("/api/v1/demo/environment", json={}).json()
    api.post(f"/api/v1/profiles/{env['id']}/generate-rules")
    api.post("/api/v1/demo/simulate", json={"environment_id": env["id"], "scenarios": ["office_powershell"]})
    assert sent and all(d["schema"] == "sentinelforge.detection.v1" for d in sent)
    st = api.get("/api/v1/siem/status").json()
    assert st["delivered"] == len(sent) and st["mode"] == "webhook" and st["configured"]
    det = api.get("/api/v1/detections").json()["items"][0]
    assert det["delivery_status"] == "delivered"


def test_failed_delivery_keeps_detection(api, settings):
    settings.siem_mode = "webhook"
    settings.webhook_url = "http://127.0.0.1:9/unreachable"  # discard port: connection refused
    settings.siem_timeout_seconds = 1
    env = api.post("/api/v1/demo/environment", json={}).json()
    api.post(f"/api/v1/profiles/{env['id']}/generate-rules")
    api.post("/api/v1/demo/simulate", json={"environment_id": env["id"], "scenarios": ["iis_webshell"]})
    det = api.get("/api/v1/detections").json()["items"][0]
    assert det["delivery_status"] == "failed"
    assert api.get("/api/v1/siem/status").json()["failed"] >= 1


def test_disabled_mode_and_status_never_leaks_secrets(api, settings):
    settings.siem_mode = "splunk"
    settings.splunk_hec_url = "https://splunk.example.net:8088/services/collector/event?token=zzz"
    settings.splunk_hec_token = SecretStr("super-secret")
    st = api.get("/api/v1/siem/status").json()
    assert "super-secret" not in str(st) and "zzz" not in str(st)
    settings.siem_mode = "disabled"
    assert api.post("/api/v1/siem/test").json()["ok"] is False


def test_local_webhook_receiver(api):
    gateway.local_sink.clear()
    assert api.post("/api/v1/siem/events", json=DOC).status_code == 202
    assert api.get("/api/v1/siem/events").json()["items"][0]["document"]["detection_id"] == "det-1"
