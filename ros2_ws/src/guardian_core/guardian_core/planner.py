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
        self._last_signature: Optional[tuple[str, tuple[tuple[str, str, int], ...]]] = None
        self.current_plan: Optional[MitigationPlan] = None

    def _candidate_subsets(self, components: set[str]) -> Iterable[frozenset[str]]:
        ordered = sorted(components)
        for size in range(1, len(ordered) + 1):
            for subset in combinations(ordered, size):
                yield frozenset(subset)

    @staticmethod
    def _signature(
        records: Iterable[AttackRecord], phase: str,
    ) -> tuple[str, tuple[tuple[str, str, int], ...]]:
        return (
            phase,
            tuple(sorted((r.event.source, r.event.event_id, r.event.sequence) for r in records)),
        )

    def _safe_stop(self, assessment: RiskAssessment, now: float, reason: str) -> MitigationPlan:
        self.current_plan = MitigationPlan(
            f"stop-{uuid4().hex[:8]}", ActionType.SAFE_STOP, frozenset(), now, now,
            reason, assessment.psi, True, False, 0.0,
        )
        return self.current_plan

    def plan(
        self,
        records: Iterable[AttackRecord],
        assessment: RiskAssessment,
        now: float,
        phase: str | None = None,
    ) -> MitigationPlan:
        records = tuple(records)
        phase = phase or self.config.task_phase or "default"
        signature = self._signature(records, phase)
        self._last_signature = signature

        if not records:
            self.current_plan = MitigationPlan("none", ActionType.NONE, frozenset(), now, now, "no active attacks", assessment.psi)
            return self.current_plan

        declared = set(self.config.tau) | set(self.config.epsilon)
        attacked = {record.event.component for record in records}
        unknown = attacked - declared
        if unknown:
            return self._safe_stop(
                assessment,
                now,
                f"unknown ROS 2 resources cannot be safely contained: {', '.join(sorted(unknown))}",
            )
        if self.config.mitigatable_devices is None:
            eligible = declared
        else:
            eligible = set(self.config.mitigatable_devices)
        non_isolatable = attacked - eligible
        if non_isolatable:
            return self._safe_stop(
                assessment,
                now,
                f"attacked ROS 2 resources are not isolatable: {', '.join(sorted(non_isolatable))}",
            )

        attack_types = tuple(record.event.attack_type for record in records)
        explicit_policy = self.config.explicit_containment_policy_for(attack_types, phase)
        policy = explicit_policy or self.config.default_containment_policy
        if policy.action == ActionType.SAFE_STOP:
            return self._safe_stop(
                assessment, now, "configured containment policy requires a safe stop",
            )
        if policy.action != ActionType.ISOLATE_COMPONENT:
            self.current_plan = MitigationPlan(
                f"contain-{uuid4().hex[:8]}",
                policy.action,
                frozenset(),
                now,
                now + self.config.mitigation_delay_sec,
                "configured containment policy applied",
                assessment.psi,
                False,
                policy.mission_allowed,
                policy.speed_limit,
            )
            return self.current_plan
        if explicit_policy is None and assessment.delta == 1 and assessment.gamma == 1:
            self.current_plan = MitigationPlan("none", ActionType.NONE, frozenset(), now, now, "current mission remains resilient", assessment.psi)
            return self.current_plan

        mitigatable = attacked & eligible
        if explicit_policy is not None and attacked - eligible:
            return self._safe_stop(assessment, now, "configured isolation includes an ineligible component")
        if not mitigatable:
            return self._safe_stop(assessment, now, "no component can be isolated safely")

        candidates = (
            (frozenset(mitigatable),)
            if explicit_policy is not None else self._candidate_subsets(mitigatable)
        )
        for candidate_index, subset in enumerate(candidates, start=1):
            if candidate_index > self.config.max_planner_candidates:
                return self._safe_stop(
                    assessment,
                    now,
                    f"containment planning budget exceeded after {self.config.max_planner_candidates} candidates",
                )
            candidate = self.risk_engine.evaluate(records, now, excluded=subset)
            if candidate.delta == 1 and candidate.gamma == 1:
                action = ActionType.ISOLATE_COMPONENT
                reason = f"isolate {', '.join(sorted(subset))} and re-evaluate mission"
                # New attacks invalidate an old pending plan; activation is delayed to model enforcement.
                self.current_plan = MitigationPlan(
                    f"contain-{uuid4().hex[:8]}", action, subset, now,
                    now + self.config.mitigation_delay_sec, reason, candidate.psi,
                    False, policy.mission_allowed, policy.speed_limit,
                )
                return self.current_plan

        return self._safe_stop(assessment, now, "no isolation subset restores mission invariants")

    def should_replan(self, records: Iterable[AttackRecord], phase: str | None = None) -> bool:
        signature = self._signature(records, phase or self.config.task_phase or "default")
        return signature != self._last_signature

