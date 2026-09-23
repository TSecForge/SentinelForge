from app.core.config import REPO_ROOT
from app.plugins import load_plugins, registry


def test_example_plugin_registers_extensions(settings):
    settings.plugin_paths = str(REPO_ROOT / "plugins")
    settings.plugins = "stdout_siem,does_not_exist"  # a broken plugin must not break loading
    load_plugins()
    assert "stdout_siem" in registry.loaded_plugins and "does_not_exist" not in registry.loaded_plugins
    assert "stdout" in registry.siem_adapters and "simple_csv" in registry.event_parsers


def test_plugin_parser_accepts_new_source(api, settings):
    settings.plugin_paths = str(REPO_ROOT / "plugins")
    settings.plugins = "stdout_siem"
    load_plugins()
    r = api.post("/api/v1/events", json={"source": "simple_csv", "data": {"line": "HOST-9,csv_login,alice"}}).json()
    assert r["accepted"] == 1 and r["rejected"] == 0
    ev = api.get("/api/v1/events", params={"source": "simple_csv"}).json()["items"][0]
    assert ev["host"] == "HOST-9" and ev["event_type"] == "csv_login"


def test_plugin_adapter_used_by_gateway(api, settings, capsys):
    settings.plugin_paths = str(REPO_ROOT / "plugins")
    settings.plugins = "stdout_siem"
    load_plugins()
    settings.siem_mode = "stdout"
    env = api.post("/api/v1/demo/environment", json={}).json()
    api.post(f"/api/v1/profiles/{env['id']}/generate-rules")
    api.post("/api/v1/demo/simulate", json={"environment_id": env["id"], "scenarios": ["iis_webshell"]})
    assert '"sentinelforge.detection.v1"' in capsys.readouterr().out
    assert api.get("/api/v1/detections").json()["items"][0]["delivery_status"] == "delivered"
