"""Latency-aware predictive safety envelope for commanded robot motion."""

from __future__ import annotations

import math
from dataclasses import dataclass


def _finite(value: float, name: str) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


@dataclass(frozen=True)
class MotionSample:
    speed: float
    free_distance: float
    risk: float
    risk_rate: float = 0.0
    uncertainty: float = 0.0
    sensor_fresh: bool = True


@dataclass(frozen=True)
class PredictiveConfig:
    default_speed_limit: float = 0.35
    braking_acceleration: float = 0.8
    safety_margin: float = 0.15
    control_latency_sec: float = 0.2
    sensor_latency_sec: float = 0.1
    prediction_horizon_sec: float = 0.5
    contain_risk: float = 0.35
    stop_risk: float = 0.8
    risk_distance_gain: float = 0.25

    def __post_init__(self) -> None:
        for name in (
            "default_speed_limit", "braking_acceleration", "safety_margin",
            "control_latency_sec", "sensor_latency_sec", "prediction_horizon_sec",
            "risk_distance_gain",
        ):
            value = _finite(getattr(self, name), name)
            if value < 0 or (name == "braking_acceleration" and value <= 0):
                raise ValueError(f"{name} must be valid")
        if not 0.0 <= self.contain_risk < self.stop_risk <= 1.0:
            raise ValueError("risk thresholds must satisfy 0 <= contain < stop <= 1")


@dataclass(frozen=True)
class PredictiveDecision:
    state: str
    speed_limit: float
    mission_allowed: bool
    stop_distance: float
    predicted_risk: float
    reason: str


class PredictiveEnvelope:
    def __init__(self, config: PredictiveConfig | None = None) -> None:
        self.config = config or PredictiveConfig()

    def evaluate(self, sample: MotionSample) -> PredictiveDecision:
        values = {
            "speed": sample.speed,
            "free_distance": sample.free_distance,
            "risk": sample.risk,
            "risk_rate": sample.risk_rate,
            "uncertainty": sample.uncertainty,
        }
        if any(not math.isfinite(float(value)) for value in values.values()):
            return PredictiveDecision("SAFE_STOP", 0.0, False, 0.0, 1.0, "non-finite motion input")
        if not isinstance(sample.sensor_fresh, bool):
            return PredictiveDecision("SAFE_STOP", 0.0, False, 0.0, 1.0, "sensor freshness flag is invalid")
        if any(float(value) < 0 for value in (sample.speed, sample.free_distance, sample.uncertainty)):
            return PredictiveDecision("SAFE_STOP", 0.0, False, 0.0, 1.0, "negative motion input")
        risk = max(0.0, min(1.0, float(sample.risk)))
        if not 0.0 <= float(sample.risk) <= 1.0:
            return PredictiveDecision("SAFE_STOP", 0.0, False, 0.0, 1.0, "risk is outside [0, 1]")
        growth = max(0.0, float(sample.risk_rate))
        horizon = self.config.prediction_horizon_sec
        predicted_risk = min(1.0, risk + growth * horizon)
        latency = self.config.control_latency_sec + self.config.sensor_latency_sec
        stop_distance = (
            sample.speed * latency
            + sample.speed ** 2 / (2.0 * self.config.braking_acceleration)
            + self.config.safety_margin
            + sample.uncertainty
            + predicted_risk * self.config.risk_distance_gain
        )
        if not sample.sensor_fresh:
            return PredictiveDecision("SAFE_STOP", 0.0, False, stop_distance, predicted_risk, "sensor data is stale")
        if sample.free_distance <= self.config.safety_margin or predicted_risk >= self.config.stop_risk:
            reason = "free distance is below safety margin" if sample.free_distance <= self.config.safety_margin else "predicted risk exceeds stop threshold"
            return PredictiveDecision("SAFE_STOP", 0.0, False, stop_distance, predicted_risk, reason)
        if stop_distance > sample.free_distance:
            return PredictiveDecision("SAFE_STOP", 0.0, False, stop_distance, predicted_risk, "current motion cannot stop within free distance")
        remaining = sample.free_distance - self.config.safety_margin - sample.uncertainty - predicted_risk * self.config.risk_distance_gain
        if remaining <= 0:
            return PredictiveDecision("SAFE_STOP", 0.0, False, stop_distance, predicted_risk, "predicted stopping distance exceeds free distance")
        acceleration = self.config.braking_acceleration
        latency_limit = -acceleration * latency + math.sqrt((acceleration * latency) ** 2 + 2.0 * acceleration * remaining)
        risk_limit = self.config.default_speed_limit * (1.0 - predicted_risk)
        speed_limit = max(0.0, min(self.config.default_speed_limit, latency_limit, risk_limit))
        containing = predicted_risk >= self.config.contain_risk
        if containing:
            return PredictiveDecision("CONTAINING", speed_limit, False, stop_distance, predicted_risk, "latency, distance, or risk growth requires containment")
        return PredictiveDecision("NORMAL", speed_limit, True, stop_distance, predicted_risk, "predicted envelope is satisfied")


__all__ = ["MotionSample", "PredictiveConfig", "PredictiveDecision", "PredictiveEnvelope"]
