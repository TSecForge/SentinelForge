"""Detection engine.

`DetectionEngine` is the deterministic core (rule matching + threshold windows). `Engine` is the embeddable
pipeline most users want:

    from sentinelforge import Engine
    engine = Engine.from_paths(["builtin", "./my-rules"], inventory="host-inventory.json")
    for detection in engine.process({"source": "windows", "data": {...raw Sysmon/Security record...}}):
        send_somewhere(detection)          # sentinelforge.detection.v1 dict
"""

from collections import deque
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path

from sentinelforge._util import get_path
from sentinelforge.enrich import build_detection
from sentinelforge.inventory import load_inventory
from sentinelforge.normalize import NormalizationError, normalize
from sentinelforge.profiling import build_profile
from sentinelforge.rules.evaluator import CompiledRule, compile_rule, find_profile_refs
from sentinelforge.rules.loader import LoadedRule, load_rule_paths, resolve_template
from sentinelforge.rules.selection import applicability
from sentinelforge.schemas.event import EventIn
from sentinelforge.schemas.inventory import Inventory
from sentinelforge.schemas.profile import EnvironmentProfile
from sentinelforge.schemas.rule import RuleDefinition

MAX_THRESHOLD_KEYS = 100_000

RuleSet = list[tuple[CompiledRule, dict | None]]  # (rule, context such as {"id", "reason"} or None)


class DetectionEngine:
    """Evaluates compiled rules against normalized events, including `threshold` windows.

    ponytail: threshold windows live in process memory (lost on restart, not shared across processes);
    move them to Redis/DB for multi-worker deployments.
    """

    def __init__(self) -> None:
        self._windows: dict[tuple, deque] = {}

    def reset_state(self) -> None:
        self._windows.clear()

    def _threshold_hit(self, cr: CompiledRule, scope, event: dict, ts: datetime) -> bool:
        t = cr.definition.threshold
        key = (cr.definition.id, scope, tuple(str(get_path(event, g)) for g in t.group_by))
        if key not in self._windows and len(self._windows) >= MAX_THRESHOLD_KEYS:
            self._windows.pop(next(iter(self._windows)))
        dq = self._windows.setdefault(key, deque())
        dq.append(ts)
        cutoff = ts - timedelta(seconds=t.window_seconds)
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= t.count:
            dq.clear()  # fire once per burst, then start counting again
            return True
        return False

    def evaluate(self, event: dict, ts: datetime, rules: RuleSet, scope=None) -> RuleSet:
        hits: RuleSet = []
        for cr, ctx in rules:
            if not cr.matches(event):
                continue
            if cr.definition.threshold and not self._threshold_hit(cr, scope, event, ts):
                continue
            hits.append((cr, ctx))
        return hits


class Engine:
    """Normalize -> evaluate -> enrich, with no server or database.

    Without an inventory, only rules that need no environment facts ($profile.*) are active (baseline).
    With an inventory, rules are selected and parameterized for that environment, exactly as the server does.
    """

    def __init__(self, rules: list[LoadedRule], inventory: Inventory | None = None):
        self.profile: EnvironmentProfile | None = build_profile(inventory) if inventory else None
        self.rules: RuleSet = []
        self.skipped: dict[str, str] = {}
        params = self.profile.parameters.model_dump() if self.profile else None
        for lr in rules:
            d: RuleDefinition = lr.definition
            if self.profile:
                ok, reason = applicability(d, self.profile)
                if not ok:
                    self.skipped[d.id] = reason
                    continue
                self.rules.append((compile_rule(resolve_template(d, params)), {"reason": reason}))
            elif find_profile_refs({"s": d.selection, "c": d.condition}):
                self.skipped[d.id] = "needs an environment profile ($profile.* values); pass inventory="
            else:
                self.rules.append((compile_rule(d), None))
        self._core = DetectionEngine()
        self._env = {"id": None, "profile": self.profile.model_dump(mode="json")} if self.profile else None

    @classmethod
    def from_paths(cls, paths: Iterable[str | Path] = ("builtin",), inventory: Inventory | str | Path | None = None) -> "Engine":
        report = load_rule_paths([str(p) for p in paths])
        if report.errors:
            raise ValueError(f"invalid rules: {report.errors}")
        if isinstance(inventory, (str, Path)):
            inventory = load_inventory(inventory)
        return cls(report.rules, inventory)

    def process(self, item: EventIn | dict) -> list[dict]:
        """One raw record ({"source": ..., "data": {...}}) -> list of sentinelforge.detection.v1 dicts."""
        ev = normalize(item if isinstance(item, EventIn) else EventIn.model_validate(item))
        evd = ev.model_dump(mode="json", exclude_none=True)
        hits = self._core.evaluate(evd, ev.timestamp, self.rules)
        return [build_detection(evd, cr, self._env, ctx) for cr, ctx in hits]

    def process_many(self, items: Iterable[EventIn | dict], errors: list[str] | None = None) -> Iterable[dict]:
        for i, item in enumerate(items):
            try:
                yield from self.process(item)
            except (NormalizationError, ValueError) as e:
                if errors is not None:
                    errors.append(f"[{i}] {e}")
