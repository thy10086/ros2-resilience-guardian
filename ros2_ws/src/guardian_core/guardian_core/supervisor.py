from __future__ import annotations

from .models import ActionType, MitigationPlan, RiskAssessment, SafetyDecision, SafetyState


class SafetySupervisor:
    """Independent policy boundary between risk decisions and robot actuation."""

    def __init__(self, default_speed_limit: float = 0.35, safe_stop_speed: float = 0.0) -> None:
        self.default_speed_limit = default_speed_limit
        self.safe_stop_speed = safe_stop_speed
        self.last_decision: SafetyDecision | None = None

    def decide(self, assessment: RiskAssessment, plan: MitigationPlan) -> SafetyDecision:
        now = assessment.timestamp
        if plan.requires_safe_stop or plan.action == ActionType.SAFE_STOP:
            decision = SafetyDecision(now, SafetyState.SAFE_STOP, False, self.safe_stop_speed, plan.reason, plan.plan_id)
        elif plan.action in {ActionType.ISOLATE_COMPONENT, ActionType.LIMIT_SPEED, ActionType.SWITCH_CONTROLLER, ActionType.REPLAN_MISSION}:
            decision = SafetyDecision(now, SafetyState.CONTAINING, False, min(self.default_speed_limit, 0.15), plan.reason, plan.plan_id)
        elif assessment.active_components and assessment.delta == 1 and assessment.gamma == 1:
            state = SafetyState.DEGRADED if assessment.risk >= 0.35 else SafetyState.RESUMABLE
            decision = SafetyDecision(now, state, True, self.default_speed_limit, assessment.reason, plan.plan_id)
        else:
            decision = SafetyDecision(now, SafetyState.NORMAL, True, self.default_speed_limit, assessment.reason, plan.plan_id)
        self.last_decision = decision
        return decision
