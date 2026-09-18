"""Risk- and stopping-distance-aware speed envelope."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyEnvelopeDecision:
    state: str
    speed_limit: float
    mission_allowed: bool
    reason: str


class SafetyEnvelopeController:
    def __init__(
        self,
        default_speed_limit: float = 0.35,
        braking_acceleration: float = 0.8,
        safety_margin: float = 0.15,
        contain_risk: float = 0.35,
        stop_risk: float = 0.80,
    ) -> None:
        if default_speed_limit < 0 or braking_acceleration <= 0 or safety_margin < 0:
            raise ValueError("speed, braking acceleration and margin must be valid")
        if not 0.0 <= contain_risk < stop_risk <= 1.0:
            raise ValueError("risk thresholds must satisfy 0 <= contain < stop <= 1")
        self.default_speed_limit = default_speed_limit
        self.braking_acceleration = braking_acceleration
        self.safety_margin = safety_margin
        self.contain_risk = contain_risk
        self.stop_risk = stop_risk

    def compute(self, risk: float, free_distance: float, sensor_fresh: bool) -> SafetyEnvelopeDecision:
        risk = max(0.0, min(1.0, float(risk)))
        if not sensor_fresh:
            return SafetyEnvelopeDecision("SAFE_STOP", 0.0, False, "sensor data is stale")
        if free_distance <= self.safety_margin:
            return SafetyEnvelopeDecision("SAFE_STOP", 0.0, False, "free distance is below safety margin")
        if risk >= self.stop_risk:
            return SafetyEnvelopeDecision("SAFE_STOP", 0.0, False, "fused risk exceeds stop threshold")
        braking_limit = math.sqrt(2.0 * self.braking_acceleration * (free_distance - self.safety_margin))
        risk_limit = self.default_speed_limit * (1.0 - risk)
        speed_limit = min(self.default_speed_limit, braking_limit, risk_limit)
        if risk >= self.contain_risk or speed_limit < self.default_speed_limit:
            return SafetyEnvelopeDecision("CONTAINING", max(0.0, speed_limit), False, "risk or stopping distance requires containment")
        return SafetyEnvelopeDecision("NORMAL", max(0.0, speed_limit), True, "risk and stopping distance are within limits")
