from __future__ import annotations

from itertools import combinations
from typing import Iterable, Optional
from uuid import uuid4

from .models import ActionType, AttackRecord, GuardianConfig, MitigationPlan, RiskAssessment
from .risk_engine import RiskEngine


class MitigationPlanner:
    """Replans whenever the verified attack set changes or an active plan is insufficient."""

    def __init__(self, config: GuardianConfig, risk_engine: RiskEngine) -> None:
        self.config = config
        self.risk_engine = risk_engine
        self._last_signature: Optional[tuple[str, ...]] = None
        self.current_plan: Optional[MitigationPlan] = None

    def _candidate_subsets(self, components: set[str]) -> Iterable[frozenset[str]]:
        ordered = sorted(components)
        for size in range(1, len(ordered) + 1):
            for subset in combinations(ordered, size):
                yield frozenset(subset)

    def plan(self, records: Iterable[AttackRecord], assessment: RiskAssessment, now: float) -> MitigationPlan:
        records = tuple(records)
        signature = tuple(sorted(f"{r.event.event_id}:{r.event.sequence}" for r in records))
        changed = signature != self._last_signature
        self._last_signature = signature

        if not records:
            self.current_plan = MitigationPlan("none", ActionType.NONE, frozenset(), now, now, "no active attacks", assessment.psi)
            return self.current_plan

        if assessment.delta == 1 and assessment.gamma == 1:
            self.current_plan = MitigationPlan("none", ActionType.NONE, frozenset(), now, now, "current mission remains resilient", assessment.psi)
            return self.current_plan

        if self.config.mitigatable_devices is None:
            eligible = set(self.config.tau) | set(self.config.epsilon)
        else:
            eligible = set(self.config.mitigatable_devices)
        mitigatable = {r.event.component for r in records if r.event.component in eligible}
        # In the new system every explicitly listed component is eligible for isolation;
        # a production deployment can replace this with a permissions-backed allow-list.
        if not mitigatable:
            self.current_plan = MitigationPlan(f"stop-{uuid4().hex[:8]}", ActionType.SAFE_STOP, frozenset(), now, now, "no component can be isolated safely", assessment.psi, True)
            return self.current_plan

        for subset in self._candidate_subsets(mitigatable):
            candidate = self.risk_engine.evaluate(records, now, excluded=subset)
            if candidate.delta == 1 and candidate.gamma == 1:
                action = ActionType.ISOLATE_COMPONENT
                reason = f"isolate {', '.join(sorted(subset))} and re-evaluate mission"
                # New attacks invalidate an old pending plan; activation is delayed to model enforcement.
                self.current_plan = MitigationPlan(
                    f"contain-{uuid4().hex[:8]}", action, subset, now,
                    now + self.config.mitigation_delay_sec, reason, candidate.psi,
                )
                return self.current_plan

        self.current_plan = MitigationPlan(
            f"stop-{uuid4().hex[:8]}", ActionType.SAFE_STOP, frozenset(), now,
            now, "no isolation subset restores mission invariants", assessment.psi, True,
        )
        return self.current_plan

    def should_replan(self, records: Iterable[AttackRecord]) -> bool:
        signature = tuple(sorted(f"{r.event.event_id}:{r.event.sequence}" for r in records))
        return signature != self._last_signature

