from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Iterable, Mapping, Optional


class VerificationCode(str, Enum):
    ACCEPTED = "ACCEPTED"
    UNKNOWN_SOURCE = "UNKNOWN_SOURCE"
    STALE = "STALE"
    FUTURE = "FUTURE"
    REPLAY = "REPLAY"
    INVALID = "INVALID"


class SafetyState(str, Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    CONTAINING = "CONTAINING"
    RECOVERING = "RECOVERING"
    RESUMABLE = "RESUMABLE"
    SAFE_STOP = "SAFE_STOP"
    ABORTED = "ABORTED"


class ActionType(str, Enum):
    NONE = "NONE"
    ISOLATE_COMPONENT = "ISOLATE_COMPONENT"
    LIMIT_SPEED = "LIMIT_SPEED"
    DEGRADED_RUN = "DEGRADED_RUN"
    SWITCH_CONTROLLER = "SWITCH_CONTROLLER"
    REPLAN_MISSION = "REPLAN_MISSION"
    SAFE_STOP = "SAFE_STOP"


def _validate_nonnegative_number(name: str, value: object) -> None:
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0.0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError(f"{name} must be a finite non-negative number")


@dataclass(frozen=True)
class AttackEvent:
    event_id: str
    source: str
    component: str
    attack_type: str
    sequence: int
    timestamp: float
    confidence: float = 1.0
    signature: str = ""


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    code: VerificationCode
    reason: str


@dataclass(frozen=True)
class ContainmentPolicy:
    action: ActionType
    speed_limit: float
    mission_allowed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.action, ActionType):
            raise ValueError("containment action must be an ActionType")
        if self.action not in {
            ActionType.SAFE_STOP, ActionType.ISOLATE_COMPONENT,
            ActionType.LIMIT_SPEED, ActionType.DEGRADED_RUN,
        }:
            raise ValueError("containment action has no supported enforcement adapter")
        if not isinstance(self.mission_allowed, bool):
            raise ValueError("containment mission_allowed must be boolean")
        _validate_nonnegative_number("containment speed limit", self.speed_limit)
        if self.action == ActionType.SAFE_STOP and (self.speed_limit != 0.0 or self.mission_allowed):
            raise ValueError("SAFE_STOP requires zero speed and mission_allowed=false")


@dataclass
class AttackRecord:
    event: AttackEvent
    first_seen: float
    last_seen: float
    status: str = "ACTIVE"

    @property
    def age(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


@dataclass(frozen=True)
class RiskAssessment:
    timestamp: float
    delta: int
    gamma: int
    psi: float
    risk: float
    critical_components: FrozenSet[str]
    active_components: FrozenSet[str]
    k_crit: float
    k_base: float
    reason: str


@dataclass(frozen=True)
class MitigationPlan:
    plan_id: str
    action: ActionType
    components: FrozenSet[str]
    created_at: float
    activate_at: float
    reason: str
    residual_psi: float
    requires_safe_stop: bool = False
    mission_allowed: bool = False
    speed_limit: Optional[float] = None


@dataclass(frozen=True)
class SafetyDecision:
    timestamp: float
    state: SafetyState
    mission_allowed: bool
    speed_limit: float
    reason: str
    plan_id: Optional[str] = None


@dataclass(frozen=True)
class GuardianConfig:
    task: str
    goal: str
    tau: Mapping[str, int]
    epsilon: Mapping[str, int] = field(default_factory=dict)
    theta_crit: float = 0.99
    theta_base: float = 0.72
    alpha_crit: float = 0.4
    alpha_base: float = 0.05
    trusted_sources: FrozenSet[str] = frozenset({"scenario_injector"})
    mitigatable_devices: Optional[FrozenSet[str]] = None
    max_event_age_sec: float = 5.0
    detection_delay_sec: float = 0.0
    mitigation_delay_sec: float = 1.0
    feedback_timeout_sec: float = 0.5
    max_planner_candidates: int = 128
    default_speed_limit: float = 0.35
    safe_stop_speed: float = 0.0
    task_phase: str = "default"
    profile_id: str = "default"
    actuator_adapter_id: str = "default-actuator"
    containment_policies: Mapping[tuple[str, str], ContainmentPolicy] = field(default_factory=dict)
    default_containment_policy: ContainmentPolicy = field(
        default_factory=lambda: ContainmentPolicy(ActionType.ISOLATE_COMPONENT, 0.15, False)
    )

    def __post_init__(self) -> None:
        for name in (
            "max_event_age_sec", "detection_delay_sec", "mitigation_delay_sec",
            "feedback_timeout_sec", "default_speed_limit", "safe_stop_speed",
        ):
            _validate_nonnegative_number(name, getattr(self, name))
        if type(self.max_planner_candidates) is not int or not 1 <= self.max_planner_candidates <= 1_000_000:
            raise ValueError("max_planner_candidates must be an integer in [1, 1000000]")
        if self.safe_stop_speed != 0.0:
            raise ValueError("safe_stop_speed must be zero")
        for name, value in (
            ("profile_id", self.profile_id),
            ("actuator_adapter_id", self.actuator_adapter_id),
        ):
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 96
                or value != value.strip()
                or "|" in value
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ValueError(f"{name} must be a bounded non-empty string")

    def containment_policy_for(
        self,
        attack_types: Iterable[str],
        phase: str | None = None,
    ) -> ContainmentPolicy:
        """Resolve each attack's policy, then combine all safety constraints."""
        return self.explicit_containment_policy_for(attack_types, phase) or self.default_containment_policy

    def explicit_containment_policy_for(
        self,
        attack_types: Iterable[str],
        phase: str | None = None,
    ) -> ContainmentPolicy | None:
        """Return a combined policy if at least one attack has an explicit match."""
        selected: list[ContainmentPolicy] = []
        has_explicit = False
        phase = phase or self.task_phase or "default"
        action_rank = {
            ActionType.DEGRADED_RUN: 1,
            ActionType.LIMIT_SPEED: 2,
            ActionType.ISOLATE_COMPONENT: 3,
            ActionType.SAFE_STOP: 4,
        }
        for attack_type in sorted({str(item) for item in attack_types if item}):
            for key in (
                (attack_type, phase),
                (attack_type, "*"),
                ("*", phase),
                ("*", "*"),
            ):
                policy = self.containment_policies.get(key)
                if policy is not None:
                    selected.append(policy)
                    has_explicit = True
                    break
            else:
                selected.append(self.default_containment_policy)
        if not has_explicit:
            return None
        return ContainmentPolicy(
            max((policy.action for policy in selected), key=action_rank.__getitem__),
            min(policy.speed_limit for policy in selected),
            all(policy.mission_allowed for policy in selected),
        )


