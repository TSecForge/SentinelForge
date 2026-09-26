"""Detection-as-code: per-rule unit tests.

Every rule has a file in rule-tests/ (named anything, keyed by `rule_id`):

    rule_id: DET-WIN-001
    environment: windows-web-server      # demo template whose profile fills $profile.* refs (optional)
    match:
      - name: Word spawns PowerShell
        event: {event_type: process_creation, process: {name: powershell.exe, parent_name: winword.exe}}
    no_match:
      - name: PowerShell from Explorer
        event: {event_type: process_creation, process: {name: powershell.exe, parent_name: explorer.exe}}

Events are partial *normalized* events and are validated against NormalizedEvent, so a misspelled field
fails the test instead of silently never matching. `repeat: N` sends the event N times (1s apart) for
threshold rules. The test exercises rule logic only; applicability is covered by the profiling tests.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinelforge.inventory import load_inventory
from sentinelforge.profiling import build_profile
from sentinelforge.rules.evaluator import compile_rule
from sentinelforge.rules.loader import LoadedRule, _safe_yaml, resolve_template
from sentinelforge.schemas.event import NormalizedEvent

RULE_TESTS_DIR = Path("rule-tests")
# Where `environment: <name>` is looked up (after the test file's own folder).
DEFAULT_INVENTORY_DIRS = [Path("inventories"), Path("sample-data") / "environments"]


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    event: dict
    repeat: int = Field(1, ge=1, le=1000)
    host: str = "TEST-HOST"


class RuleTestFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str
    environment: str | None = None  # inventory JSON path (relative to this file) or a name in the inventory dirs
    match: list[Case] = Field(min_length=1)
    no_match: list[Case] = Field(min_length=1)


@dataclass
class RuleTestResult:
    rule_id: str
    path: str | None
    failures: list[str] = field(default_factory=list)
    cases: int = 0

    @property
    def ok(self) -> bool:
        return not self.failures


def load_test_files(directory: Path = RULE_TESTS_DIR) -> tuple[dict[str, tuple[RuleTestFile, str]], dict[str, list[str]]]:
    tests, errors = {}, {}
    for f in sorted([*directory.rglob("*.yml"), *directory.rglob("*.yaml")]):
        try:
            t = RuleTestFile.model_validate(_safe_yaml(f.read_text(encoding="utf-8")))
        except (ValidationError, ValueError) as e:
            errors[str(f)] = [str(e)[:500]]
            continue
        if t.rule_id in tests:
            errors[str(f)] = [f"duplicate tests for {t.rule_id} (also {tests[t.rule_id][1]})"]
            continue
        tests[t.rule_id] = (t, str(f))
    return tests, errors


_profiles: dict[Path, dict] = {}


def _find_inventory(env: str, test_path: str | None, inventory_dirs: list[Path]) -> Path:
    here = Path(test_path).parent if test_path else Path(".")
    candidates = [here / env, *[d / f"{env}.json" for d in [here, *inventory_dirs]], *[d / env for d in inventory_dirs]]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    raise FileNotFoundError(f"inventory {env!r} not found (looked in {here} and {[str(d) for d in inventory_dirs]})")


def _params(env: str | None, test_path: str | None, inventory_dirs: list[Path]) -> dict:
    if not env:
        return {"listening_ports": [], "approved_images": [], "container_ports": [], "internal_cidrs": [], "known_admins": []}
    path = _find_inventory(env, test_path, inventory_dirs)
    if path not in _profiles:
        _profiles[path] = build_profile(load_inventory(path)).parameters.model_dump()
    return _profiles[path]


def _fires(rule, case: Case, idx: int) -> bool:
    from sentinelforge.engine import DetectionEngine

    engine = DetectionEngine()  # fresh threshold state per case
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    hit = False
    for i in range(case.repeat):
        ts = t0 + timedelta(seconds=i)
        ev = NormalizedEvent.model_validate({"event_id": f"test-{idx}-{i}", "timestamp": ts, "source": "generic",
                                             "host": case.host, **case.event}).model_dump(mode="json", exclude_none=True)
        hit |= bool(engine.evaluate(ev, ts, [(rule, None)], None))
    return hit


def run_rule_test(loaded: LoadedRule, test: RuleTestFile, path: str | None = None,
                  inventory_dirs: list[Path] | None = None) -> RuleTestResult:
    res = RuleTestResult(loaded.definition.id, path)
    try:
        params = _params(test.environment, path, inventory_dirs or DEFAULT_INVENTORY_DIRS)
        rule = compile_rule(resolve_template(loaded.definition, params))
    except Exception as e:  # noqa: BLE001 - report, don't crash the suite
        res.failures.append(f"could not build rule: {e}")
        return res
    for expect, cases in ((True, test.match), (False, test.no_match)):
        for i, case in enumerate(cases):
            res.cases += 1
            try:
                fired = _fires(rule, case, i)
            except ValidationError as e:
                res.failures.append(f"{case.name}: invalid test event: {e.errors()[0]['loc']} {e.errors()[0]['msg']}")
                continue
            if fired != expect:
                res.failures.append(f"{case.name}: expected {'match' if expect else 'no match'}, got {'match' if fired else 'no match'}")
    return res


def run_all(rules: list[LoadedRule], directory: Path = RULE_TESTS_DIR, inventory_dirs: list[Path] | None = None,
            require_tests: bool = True) -> tuple[list[RuleTestResult], dict[str, list[str]]]:
    tests, errors = load_test_files(Path(directory))
    results = []
    for lr in rules:
        if lr.definition.id not in tests:
            if require_tests:
                results.append(RuleTestResult(lr.definition.id, None, [f"no tests (add a file in {directory})"]))
            continue
        t, p = tests[lr.definition.id]
        results.append(run_rule_test(lr, t, p, inventory_dirs))
    known = {lr.definition.id for lr in rules}
    for rid, (_, p) in tests.items():
        if rid not in known:
            errors[p] = [f"tests reference unknown rule {rid}"]
    return results, errors
