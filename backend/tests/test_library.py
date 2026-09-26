"""The sentinelforge library must work on its own: no server, database or web framework."""

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from sentinelforge import Engine, __version__
from sentinelforge.cli import main as cli
from sentinelforge.rules import builtin_rules_path
from sentinelforge.rules.loader import load_rule_paths

from app.core.config import REPO_ROOT

SYSMON = "Microsoft-Windows-Sysmon/Operational"
WORD_PS = {"source": "windows", "data": {"EventID": 1, "Channel": SYSMON, "Computer": "WS-1", "EventData": {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell -nop -c Get-Date",
    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "User": "CORP\\jdoe"}}}


def test_library_has_no_server_dependencies():
    code = "import sys, sentinelforge; sentinelforge.Engine.from_paths(['builtin']); " \
           "print([m for m in ('fastapi', 'sqlalchemy', 'starlette', 'httpx', 'app') if m in sys.modules])"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(REPO_ROOT / "src"), check=True)
    assert out.stdout.strip() == "[]"


def test_builtin_rules_resolve():
    rules = load_rule_paths(["builtin"])
    assert not rules.errors and len(rules.rules) >= 30
    assert builtin_rules_path().is_dir()


def test_engine_baseline_without_inventory():
    engine = Engine.from_paths(["builtin"])
    dets = engine.process(WORD_PS)
    assert [d["rule"]["id"] for d in dets] == ["DET-WIN-001"]
    assert dets[0]["schema"] == "sentinelforge.detection.v1" and dets[0]["host"] == "WS-1"
    assert "DET-DOCKER-001" in engine.skipped  # needs $profile values -> only with an inventory


def test_engine_with_inventory_is_environment_aware():
    web = Engine.from_paths(["builtin"], inventory=REPO_ROOT / "sample-data/environments/windows-web-server.json")
    wks = Engine.from_paths(["builtin"], inventory=REPO_ROOT / "sample-data/environments/windows-workstation.json")
    image = {"source": "docker", "data": {"host": "WEB-SRV-01", "Action": "start",
                                         "Actor": {"Attributes": {"image": "registry.example.net/x:1", "name": "x"}}}}
    assert [d["rule"]["id"] for d in web.process(image)] == ["DET-DOCKER-001"]
    assert wks.process(image) == [] and "Docker" in wks.skipped["DET-DOCKER-001"]
    ok = {"source": "docker", "data": {"host": "WEB-SRV-01", "Action": "start", "Actor": {"Attributes": {"image": "nginx:1.25"}}}}
    assert web.process(ok) == []


def test_cli_evaluate_sample_file(capsys):
    assert cli(["evaluate", str(REPO_ROOT / "sample-data/events/powershell.json")]) == 0
    out, err = capsys.readouterr()
    ids = {json.loads(line)["rule"]["id"] for line in out.splitlines()}
    assert {"DET-WIN-001", "DET-WIN-002"} <= ids and "detection(s)" in err


def test_cli_validate_and_coverage_summary(capsys):
    assert cli(["rules", "validate", "builtin"]) == 0
    assert cli(["coverage", "export", "--rules", "builtin", "--summary"]) == 0
    assert "MITRE ATT&CK coverage" in capsys.readouterr().out


def test_cli_forward_posts_batches(tmp_path):
    received = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            received.append((self.path, self.headers.get("X-API-Key"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            body = json.dumps({"accepted": 1, "detections": 0}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    f = tmp_path / "events.ndjson"
    f.write_text('{"Type":"container","Action":"start"}\n{"Type":"container","Action":"die"}\n', encoding="utf-8")
    import os
    os.environ["SF_TEST_KEY"] = "k-9"
    try:
        assert cli(["forward", str(f), "--url", f"http://127.0.0.1:{srv.server_port}", "--source", "docker",
                    "--host", "DOCKER-01", "--batch", "10", "--api-key-env", "SF_TEST_KEY"]) == 0
    finally:
        srv.shutdown()
        del os.environ["SF_TEST_KEY"]
    path, key, body = received[0]
    assert path == "/api/v1/ingest/docker?host=DOCKER-01" and key == "k-9" and len(body) == 2


def test_version():
    assert __version__ == "0.2.0"
