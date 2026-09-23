"""Deterministic detection engine: compiled, validated rules evaluated against normalized events."""

from collections import deque
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import RuleAssignment
from app.schemas.rule import RuleDefinition
from app.services.rules.evaluator import CompiledRule, compile_rule, find_profile_refs
from app.utils import get_path

MAX_THRESHOLD_KEYS = 100_000

RuleSet = list[tuple[CompiledRule, dict | None]]  # (rule, assignment {"id","reason"} or None for baseline)


class DetectionEngine:
    def __init__(self) -> None:
        self._cache: dict[int | None, RuleSet] = {}
        # ponytail: threshold windows live in process memory (lost on restart, not shared across workers);
        # move to Redis/DB if running more than one worker.
        self._windows: dict[tuple, deque] = {}

    def invalidate(self, env_id: int | None = None) -> None:
        if env_id is None:
            self._cache.clear()
        else:
            self._cache.pop(env_id, None)

    def reset_state(self) -> None:
        self._cache.clear()
        self._windows.clear()

    def rules_for(self, db: Session, env_id: int | None) -> RuleSet:
        if env_id in self._cache:
            return self._cache[env_id]
        rules: RuleSet = []
        if env_id is not None:
            for a in db.scalars(select(RuleAssignment).where(RuleAssignment.environment_id == env_id, RuleAssignment.status == "active")):
                rules.append((compile_rule(RuleDefinition.model_validate(a.generated)), {"id": a.id, "reason": a.reason}))
        else:
            # Host not profiled: fall back to baseline rules that need no environment facts, instead of
            # silently dropping its events (a spoofed/unknown hostname must not mean "no detection").
            from app.services.rules import current_templates

            for t in current_templates(db):
                d = RuleDefinition.model_validate(t.definition)
                if not find_profile_refs({"s": d.selection, "c": d.condition}):
                    rules.append((compile_rule(d), None))
        self._cache[env_id] = rules
        return rules

    def _threshold_hit(self, cr: CompiledRule, env_id: int | None, event: dict, ts: datetime) -> bool:
        t = cr.definition.threshold
        key = (cr.definition.id, env_id, tuple(str(get_path(event, g)) for g in t.group_by))
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

    def evaluate(self, event: dict, ts: datetime, rules: RuleSet, env_id: int | None) -> RuleSet:
        hits: RuleSet = []
        for cr, a in rules:
            if not cr.matches(event):
                continue
            if cr.definition.threshold and not self._threshold_hit(cr, env_id, event, ts):
                continue
            hits.append((cr, a))
        return hits


engine = DetectionEngine()
