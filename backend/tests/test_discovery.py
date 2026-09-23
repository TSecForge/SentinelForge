import json
import os
import platform

import pytest

from app.services import discovery
from app.services.discovery import DiscoveryError, parse_inventory


def _sample(name="windows-web-server"):
    return (discovery.DEMO_DIR / f"{name}.json").read_text(encoding="utf-8")


def test_parses_representative_inventory():
    inv = parse_inventory(_sample())
    assert inv.schema_version == "1.0"
    assert inv.host.hostname == "WEB-SRV-01"
    assert {p.port for p in inv.network.listening_ports} >= {80, 443, 3389, 5985}
    assert inv.containers.docker and len(inv.containers.containers) == 7
    assert inv.web_servers.iis and inv.remote_access.rdp_enabled


def test_tolerates_powershell_single_item_collapse_and_bom():
    raw = json.loads(_sample())
    raw["services"] = raw["services"][0]  # PS 5.1 ConvertTo-Json emits an object, not a 1-item array
    raw["network"]["interfaces"][0]["gateways"] = "10.10.20.1"
    inv = parse_inventory("﻿" + json.dumps(raw))
    assert len(inv.services) == 1 and inv.network.interfaces[0].gateways == ["10.10.20.1"]


def test_rejects_invalid_json_and_schema():
    with pytest.raises(DiscoveryError):
        parse_inventory("{not json")
    with pytest.raises(DiscoveryError):
        parse_inventory({"schema_version": "9.9", "collection_time": "2026-01-01T00:00:00Z", "host": {"hostname": "x"}})
    with pytest.raises(DiscoveryError):
        parse_inventory({"schema_version": "1.0", "collection_time": "2026-01-01T00:00:00Z", "host": {"hostname": ""}})


def test_unknown_fields_are_dropped_not_stored():
    raw = json.loads(_sample())
    raw["host"]["password"] = "hunter2"
    raw["unexpected"] = {"token": "abc"}
    dumped = parse_inventory(raw).model_dump_json()
    assert "hunter2" not in dumped and "unexpected" not in dumped


def test_demo_templates_are_allowlisted():
    assert "windows-web-server" in discovery.list_demo_templates()
    with pytest.raises(DiscoveryError):
        discovery.load_demo_inventory("../../backend/app/main")
    assert discovery.load_demo_inventory("docker-host").simulated is True


def test_live_discovery_is_opt_in(settings):
    settings.enable_live_discovery = False
    with pytest.raises(DiscoveryError, match="disabled"):
        discovery.run_powershell_collector()


def test_discovery_api_validates_remote_target(api):
    r = api.post("/api/v1/discovery/run", json={"mode": "remote", "target": "host; rm -rf /"})
    assert r.status_code == 422
    r = api.post("/api/v1/discovery/run", json={"mode": "remote", "target": "-EncodedCommand"})
    assert r.status_code == 422


def test_discovery_import_mode(api):
    r = api.post("/api/v1/discovery/run", json={"mode": "import", "inventory": json.loads(_sample("windows-workstation"))})
    assert r.status_code == 200
    body = r.json()
    assert body["hostname"] == "WKS-042" and body["profile"]["platform"] == "windows"


@pytest.mark.skipif(platform.system() != "Windows" or os.environ.get("SF_TEST_LIVE") != "1",
                    reason="live collector test: set SF_TEST_LIVE=1 on Windows")
def test_live_powershell_collector(settings):
    settings.enable_live_discovery = True
    inv = discovery.run_powershell_collector()
    assert inv.host.platform == "windows" and inv.host.hostname
    assert inv.services and inv.network.interfaces
