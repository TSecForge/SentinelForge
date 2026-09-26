"""Server-side engine: the library's DetectionEngine plus per-environment rule sets loaded from the database."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinelforge.engine import DetectionEngine as _CoreEngine
from sentinelforge.engine import RuleSet
from sentinelforge.rules.evaluator import compile_rule, find_profile_refs
from sentinelforge.schemas.rule import RuleDefinition

from app.models import RuleAssignment


class DetectionEngine(_CoreEngine):
    def __init__(self) -> None:
        super().__init__()
        self._cache: dict[int | None, RuleSet] = {}

    def invalidate(self, env_id: int | None = None) -> None:
        if env_id is None:
            self._cache.clear()
        else:
            self._cache.pop(env_id, None)

    def reset_state(self) -> None:
        super().reset_state()
        self._cache.clear()

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


engine = DetectionEngine()
