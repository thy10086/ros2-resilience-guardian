from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Mapping, Optional


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
    SWITCH_CONTROLLER = "SWITCH_CONTROLLER"
    REPLAN_MISSION = "REPLAN_MISSION"
    SAFE_STOP = "SAFE_STOP"


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
    default_speed_limit: float = 0.35
    safe_stop_speed: float = 0.0


