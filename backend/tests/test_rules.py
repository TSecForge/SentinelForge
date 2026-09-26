import textwrap

import pytest

from app.core.config import REPO_ROOT
from sentinelforge.rules.evaluator import RuleCompileError, compile_node, render_summary
from sentinelforge.rules.loader import load_rule_paths, validate_rule_text

GOOD = textwrap.dedent("""
    id: TEST-001
    name: Test Rule
    description: test
    version: "1.0"
    author: tests
    source: user
    platform: windows
    event_type: process_creation
    severity: high
    selection:
      process.name: powershell.exe
    condition:
      any:
        - process.parent_name: winword.exe
        - not:
            process.command_line|contains: safe
""")


def _with(**repl):
    text = GOOD
    for k, v in repl.items():
        text = text.replace(k, v)
    return text


def test_shipped_rule_packs_are_valid_and_complete():
    report = load_rule_paths([str(REPO_ROOT / "detection-rules"), str(REPO_ROOT / "custom-rules")])
    assert report.errors == {}
    builtin = [r for r in report.rules if r.definition.source == "builtin"]
    assert len(builtin) >= 15
    for r in builtin:
        d = r.definition
        assert d.id and d.name and d.description and d.platform and d.event_type and d.severity and d.version and d.tags
        assert d.mitre is not None
    assert any(r.definition.source == "organization" for r in report.rules)


def test_valid_rule():
    defn, res = validate_rule_text(GOOD)
    assert res.valid and defn.id == "TEST-001" and defn.version == "1.0"


@pytest.mark.parametrize("text, msg", [
    (_with(**{"severity: high": "severity: urgent"}), "severity"),
    (_with(**{"source: user": "source: user\nunexpected_key: 1"}), "unexpected_key"),
    (_with(**{"process.name: powershell.exe": "process.name|evals: x"}), "unknown operator"),
    (_with(**{"process.name: powershell.exe": "process.name|re: '(unclosed'"}), "invalid regex"),
    (_with(**{"process.name: powershell.exe": "__class__.__mro__: x"}), "invalid field path"),
    (_with(**{"process.name: powershell.exe": "process.name|not_in: $profile.secrets"}), "unknown profile reference"),
    (_with(**{"version: \"1.0\"": "version: latest"}), "version"),
    ("- just\n- a list\n", "mapping"),
    ("id: [unclosed", "YAML error"),
])
def test_invalid_rules_rejected(text, msg):
    defn, res = validate_rule_text(text)
    assert defn is None and not res.valid
    assert msg in " ".join(res.errors)


def test_yaml_python_tags_and_aliases_refused():
    _, res = validate_rule_text("id: !!python/object/apply:os.system ['echo pwned']\n")
    assert not res.valid
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n" + GOOD
    _, res = validate_rule_text(bomb)
    assert not res.valid and "aliases" in res.errors[0]


def test_rule_values_are_data_not_code():
    pred = compile_node({"process.name": "__import__('os').system('x')"})
    assert pred({"process": {"name": "__import__('os').system('x')"}}) is True
    assert pred({"process": {"name": "cmd.exe"}}) is False


def test_condition_limits():
    deep = {"process.name": "x"}
    for _ in range(12):
        deep = {"not": deep}
    with pytest.raises(RuleCompileError, match="deeper"):
        compile_node(deep)
    with pytest.raises(RuleCompileError):
        compile_node({"all": []})
    with pytest.raises(RuleCompileError):
        compile_node({"all": [{"a.b": 1}], "any": [{"a.b": 1}]})


def test_summary_template_is_not_format_string():
    ev = {"host": "H1", "process": {"name": "cmd.exe"}}
    assert render_summary("{process.name} on {host}", ev) == "cmd.exe on H1"
    assert render_summary("{process.__class__} {0.__globals__}", ev) == "{process.__class__} {0.__globals__}"


def test_validate_endpoint(api):
    r = api.post("/api/v1/rules/validate", json={"yaml": GOOD})
    assert r.json()["valid"] is True
    r = api.post("/api/v1/rules/validate", json={"yaml": _with(**{"severity: high": "severity: nope"})})
    assert r.json()["valid"] is False


def test_rules_endpoints(api):
    rows = api.get("/api/v1/rules").json()
    assert len(rows) >= 15
    one = api.get("/api/v1/rules/DET-WIN-001").json()
    assert "yaml" in one and one["definition"]["mitre"]["technique"] == "T1059.001"
    assert api.get("/api/v1/rules/NOPE-404").status_code == 404


def test_changed_rule_without_version_bump_is_not_overwritten(db, settings, tmp_path):
    from app.services.rules import sync_rule_store

    (tmp_path / "r.yml").write_text(GOOD.replace("TEST-001", "TEST-VER"), encoding="utf-8")
    settings.rule_paths = str(tmp_path)
    assert sync_rule_store(db)["new"] == 1
    (tmp_path / "r.yml").write_text(GOOD.replace("TEST-001", "TEST-VER").replace("severity: high", "severity: low"), encoding="utf-8")
    res = sync_rule_store(db)
    assert res["new"] == 0 and any("without a version bump" in e[0] for e in res["errors"].values())
    (tmp_path / "r.yml").write_text(GOOD.replace("TEST-001", "TEST-VER").replace('"1.0"', '"1.1"'), encoding="utf-8")
    assert sync_rule_store(db)["new"] == 1
