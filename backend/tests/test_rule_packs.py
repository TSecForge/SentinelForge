"""Detection-as-code gate: every rule in RULE_PATHS must have passing unit tests in rule-tests/."""

import pytest

from app.core.config import get_settings
from app.services.rules.loader import load_rule_paths
from app.services.rules.testing import RuleTestFile, load_test_files, run_all, run_rule_test

RULES = load_rule_paths(get_settings().split(get_settings().rule_paths)).rules
RESULTS, ERRORS = run_all(RULES)


def test_rule_test_files_are_valid():
    assert ERRORS == {}


@pytest.mark.parametrize("result", RESULTS, ids=lambda r: r.rule_id)
def test_rule(result):
    assert result.ok, "\n".join(result.failures)
    assert result.cases >= 2


def _rule(rule_id):
    return next(r for r in RULES if r.definition.id == rule_id)


def test_harness_catches_wrong_expectation():
    t, _ = load_test_files()[0]["DET-WIN-001"]
    swapped = RuleTestFile(rule_id=t.rule_id, match=t.no_match, no_match=t.match)
    assert not run_rule_test(_rule("DET-WIN-001"), swapped).ok


def test_harness_catches_misspelled_field():
    bad = RuleTestFile.model_validate({
        "rule_id": "DET-WIN-001",
        "match": [{"name": "typo", "event": {"event_type": "process_creation", "process": {"nmae": "powershell.exe"}}}],
        "no_match": [{"name": "x", "event": {"event_type": "process_creation"}}],
    })
    res = run_rule_test(_rule("DET-WIN-001"), bad)
    assert not res.ok and "invalid test event" in res.failures[0]
