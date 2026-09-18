"""Runtime checks for source, freshness, sequence and message timing rules."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable


@dataclass(frozen=True)
class TopicPolicy:
    topic: str
    source: str
    min_period_sec: float = 0.0
    max_gap_sec: float = float("inf")
    max_age_sec: float = 5.0


@dataclass(frozen=True)
class PolicyViolation:
    code: str
    topic: str
    reason: str


class TemporalPolicyMonitor:
    def __init__(self, policies: Iterable[TopicPolicy], max_future_skew_sec: float = 0.5) -> None:
        self._policies = {policy.topic: policy for policy in policies}
        self.max_future_skew_sec = max_future_skew_sec
        self._last: dict[str, tuple[int, float]] = {}

    def observe(self, topic: str, source: str, timestamp: float, sequence: int, now: float) -> tuple[PolicyViolation, ...]:
        policy = self._policies.get(topic)
        if policy is None:
            return (PolicyViolation("UNKNOWN_TOPIC", topic, "topic has no security policy"),)
        if not math.isfinite(timestamp) or not math.isfinite(now):
            return (PolicyViolation("INVALID_TIMESTAMP", topic, "timestamp and now must be finite"),)
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            return (PolicyViolation("INVALID_SEQUENCE", topic, "sequence must be an integer"),)
        violations: list[PolicyViolation] = []
        if source != policy.source:
            violations.append(PolicyViolation("UNTRUSTED_SOURCE", topic, f"expected source {policy.source!r}"))
        if timestamp > now + self.max_future_skew_sec:
            violations.append(PolicyViolation("FUTURE", topic, "message timestamp is too far in the future"))
        if now - timestamp > policy.max_age_sec:
            violations.append(PolicyViolation("STALE", topic, "message exceeds the freshness window"))
        previous = self._last.get(topic)
        if previous is not None:
            previous_sequence, previous_timestamp = previous
            if sequence <= previous_sequence:
                violations.append(PolicyViolation("REPLAY", topic, "sequence is not strictly increasing"))
            period = timestamp - previous_timestamp
            if period < policy.min_period_sec:
                violations.append(PolicyViolation("RATE_LIMIT", topic, "messages arrive faster than policy allows"))
            if period > policy.max_gap_sec:
                violations.append(PolicyViolation("RATE_GAP", topic, "message gap exceeds policy limit"))
        if not any(item.code in {"UNTRUSTED_SOURCE", "FUTURE", "STALE", "REPLAY"} for item in violations):
            self._last[topic] = (sequence, timestamp)
        return tuple(violations)
