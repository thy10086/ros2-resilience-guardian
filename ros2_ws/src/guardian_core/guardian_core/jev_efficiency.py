"""Efficient, fail-safe orchestration around the Jev semantic advisor.

The deterministic triage path makes the immediate decision. Jev remains an
advisory side channel for ambiguous, already verified incidents. This module
reduces provider work with stable incident fingerprints, bounded caching,
single-flight request coalescing, and a rolling call budget.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, replace
from enum import Enum
from threading import Event, Lock
from typing import Any, Callable

from .jev_advisor import JevAssessment, JevAssessmentStatus, JevSemanticAdvisor, SemanticContext


def _bounded(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(number):
        return default
    return max(0.0, min(1.0, number))


def _unit_input(value: Any) -> tuple[bool, float]:
    if isinstance(value, bool):
        return False, 0.0
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return False, 0.0
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return False, 0.0
    return True, number


class JevRoute(str, Enum):
    """How an efficient judgment was produced."""

    SKIPPED_UNVERIFIED = "SKIPPED_UNVERIFIED"
    LOCAL_SAFE = "LOCAL_SAFE"
    LOCAL_ENFORCED = "LOCAL_ENFORCED"
    REMOTE = "REMOTE"
    CACHE = "CACHE"
    COALESCED = "COALESCED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    UNAVAILABLE = "UNAVAILABLE"
    DISAGREEMENT = "DISAGREEMENT"
    COALESCED_TIMEOUT = "COALESCED_TIMEOUT"


@dataclass(frozen=True)
class JevEfficiencyPolicy:
    """Conservative routing and resource limits for the orchestration layer."""

    safe_risk_threshold: float = 0.20
    safe_mission_criticality_threshold: float = 0.30
    safe_confidence_threshold: float = 0.90
    critical_risk_threshold: float = 0.85
    max_remote_calls: int = 60
    budget_window_sec: float = 60.0
    cache_ttl_sec: float = 5.0
    max_cache_entries: int = 256
    coalesce_timeout_sec: float = 2.0
    max_latency_samples: int = 2048
    policy_version: str = "jev-efficient-v1"

    def __post_init__(self) -> None:
        for name in (
            "safe_risk_threshold",
            "safe_mission_criticality_threshold",
            "safe_confidence_threshold",
            "critical_risk_threshold",
        ):
            raw = getattr(self, name)
            if isinstance(raw, bool):
                raise ValueError(f"{name} must be finite and in [0, 1]")
            try:
                value = float(raw)
            except (TypeError, ValueError, OverflowError) as error:
                raise ValueError(f"{name} must be finite and in [0, 1]") from error
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be finite and in [0, 1]")
        if self.safe_risk_threshold >= self.critical_risk_threshold:
            raise ValueError("safe_risk_threshold must be below critical_risk_threshold")
        if not isinstance(self.max_remote_calls, int) or isinstance(self.max_remote_calls, bool) or self.max_remote_calls < 0:
            raise ValueError("max_remote_calls must be a non-negative integer")
        for name in ("budget_window_sec", "cache_ttl_sec", "coalesce_timeout_sec"):
            value = float(getattr(self, name))
            if not math.isfinite(value) or value < 0.0:
                raise ValueError(f"{name} must be finite and non-negative")
        if self.budget_window_sec == 0.0:
            raise ValueError("budget_window_sec must be positive")
        if not 0.05 <= self.coalesce_timeout_sec <= 30.0:
            raise ValueError("coalesce_timeout_sec must be between 0.05 and 30 seconds")
        if not isinstance(self.max_cache_entries, int) or isinstance(self.max_cache_entries, bool) or self.max_cache_entries < 1:
            raise ValueError("max_cache_entries must be a positive integer")
        if not isinstance(self.max_latency_samples, int) or isinstance(self.max_latency_samples, bool) or self.max_latency_samples < 1:
            raise ValueError("max_latency_samples must be a positive integer")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("policy_version must not be empty")


@dataclass(frozen=True)
class JevEfficientAssessment:
    """A bounded routing result plus optional normalized Jev advice."""

    event_id: str
    route: JevRoute
    fingerprint: str
    local_label: str
    local_score: float
    local_reason: str
    remote_called: bool = False
    cache_hit: bool = False
    coalesced: bool = False
    disagreement: bool = False
    assessment: JevAssessment | None = None
    latency_ms: float = 0.0

    @property
    def jev_status(self) -> JevAssessmentStatus | None:
        return self.assessment.status if self.assessment is not None else None

    def audit_payload(self) -> dict[str, Any]:
        """Return bounded metadata suitable for an audit record."""

        return {
            "event_id": self.event_id,
            "route": self.route.value,
            "fingerprint": self.fingerprint,
            "local_label": self.local_label,
            "local_score": self.local_score,
            "local_reason": self.local_reason,
            "remote_called": self.remote_called,
            "cache_hit": self.cache_hit,
            "coalesced": self.coalesced,
            "disagreement": self.disagreement,
            "jev_status": self.jev_status.value if self.jev_status else None,
            "jev_label": self.assessment.label if self.assessment else None,
            "latency_ms": self.latency_ms,
        }


@dataclass(frozen=True)
class JevEfficiencyMetrics:
    """Snapshot of bounded routing and provider-efficiency counters."""

    total_requests: int
    unverified: int
    local_safe: int
    local_enforced: int
    remote_calls: int
    cache_hits: int
    coalesced_requests: int
    budget_exhausted: int
    provider_failures: int
    disagreements: int
    p50_latency_ms: float
    p95_latency_ms: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "unverified": self.unverified,
            "local_safe": self.local_safe,
            "local_enforced": self.local_enforced,
            "remote_calls": self.remote_calls,
            "cache_hits": self.cache_hits,
            "coalesced_requests": self.coalesced_requests,
            "budget_exhausted": self.budget_exhausted,
            "provider_failures": self.provider_failures,
            "disagreements": self.disagreements,
            "p50_latency_ms": self.p50_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
        }


@dataclass(frozen=True)
class _Triage:
    route: JevRoute
    label: str
    score: float
    reason: str


class _Inflight:
    def __init__(self) -> None:
        self.done = Event()
        self.result: JevEfficientAssessment | None = None


class JevEfficientJudge:
    """Route verified incidents through local policy and bounded Jev use."""

    _TEMPORAL_SCORES = {
        "FLOODING": 0.75,
        "REPLAY": 0.75,
        "STALE": 0.70,
        "UNSAFE_COMMAND": 0.85,
    }

    def __init__(
        self,
        advisor: JevSemanticAdvisor,
        *,
        policy: JevEfficiencyPolicy | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.advisor = advisor
        self.policy = policy or JevEfficiencyPolicy()
        self._clock = clock or time.monotonic
        self._clock_lock = Lock()
        self._last_clock: float | None = None
        self._lock = Lock()
        self._cache: OrderedDict[str, tuple[float, JevAssessment]] = OrderedDict()
        self._inflight: dict[str, _Inflight] = {}
        self._window_started = self._now()
        self._remote_calls_in_window = 0
        self._total_requests = 0
        self._unverified = 0
        self._local_safe = 0
        self._local_enforced = 0
        self._remote_calls = 0
        self._cache_hits = 0
        self._coalesced_requests = 0
        self._budget_exhausted = 0
        self._provider_failures = 0
        self._disagreements = 0
        self._latencies: deque[float] = deque(maxlen=self.policy.max_latency_samples)

    def evaluate(self, context: SemanticContext) -> JevEfficientAssessment:
        started = self._now()
        try:
            triage = self._triage(context)
        except (AttributeError, TypeError, ValueError, OverflowError):
            triage = _Triage(
                JevRoute.LOCAL_ENFORCED,
                "unknown",
                1.0,
                "invalid context shape is enforced locally",
            )
        try:
            fingerprint = self._fingerprint(context)
        except (AttributeError, TypeError, ValueError, OverflowError):
            fingerprint = self._fallback_fingerprint(context)
        if triage.route == JevRoute.SKIPPED_UNVERIFIED:
            return self._finish(
                JevEfficientAssessment(
                    event_id=context.event_id,
                    route=JevRoute.SKIPPED_UNVERIFIED,
                    fingerprint=fingerprint,
                    local_label=triage.label,
                    local_score=triage.score,
                    local_reason="unverified source is never sent to Jev",
                ),
                started,
            )
        if triage.route in {JevRoute.LOCAL_SAFE, JevRoute.LOCAL_ENFORCED}:
            return self._finish(
                JevEfficientAssessment(
                    event_id=context.event_id,
                    route=triage.route,
                    fingerprint=fingerprint,
                    local_label=triage.label,
                    local_score=triage.score,
                    local_reason=triage.reason,
                ),
                started,
            )

        now = self._now()
        cached = self._get_cache(fingerprint, now)
        if cached is not None:
            assessment = replace(
                cached,
                status=JevAssessmentStatus.CACHED,
                event_id=context.event_id,
                reason="efficient fingerprint cache hit",
            )
            return self._finish(
                JevEfficientAssessment(
                    event_id=context.event_id,
                    route=JevRoute.CACHE,
                    fingerprint=fingerprint,
                    local_label=triage.label,
                    local_score=triage.score,
                    local_reason=triage.reason,
                    cache_hit=True,
                    disagreement=self._is_disagreement(triage, assessment),
                    assessment=assessment,
                ),
                started,
            )

        budget_exhausted = False
        with self._lock:
            # A caller can be descheduled between the cache lookup and this
            # lock. Sample the clock after acquiring the reservation lock so
            # an older request cannot roll the fixed window back after a
            # newer request has already advanced it.
            reservation_now = self._now()
            flight = self._inflight.get(fingerprint)
            owner = flight is None
            if owner and not self._reserve_budget_locked(reservation_now):
                self._budget_exhausted += 1
                budget_exhausted = True
            if owner:
                flight = _Inflight()
                if not budget_exhausted:
                    self._inflight[fingerprint] = flight

        if budget_exhausted:
            return self._finish(
                JevEfficientAssessment(
                    event_id=context.event_id,
                    route=JevRoute.BUDGET_EXHAUSTED,
                    fingerprint=fingerprint,
                    local_label=triage.label,
                    local_score=triage.score,
                    local_reason="Jev call budget exhausted; deterministic local result retained",
                ),
                started,
            )

        if not owner:
            assert flight is not None
            if not flight.done.wait(timeout=self.policy.coalesce_timeout_sec):
                return self._finish(
                    JevEfficientAssessment(
                        event_id=context.event_id,
                        route=JevRoute.COALESCED_TIMEOUT,
                        fingerprint=fingerprint,
                        local_label=triage.label,
                        local_score=triage.score,
                        local_reason="shared Jev request exceeded coalescing timeout; deterministic local result retained",
                        coalesced=True,
                    ),
                    started,
                )
            shared = flight.result
            if shared is None:
                return self._finish(
                    JevEfficientAssessment(
                        event_id=context.event_id,
                        route=JevRoute.UNAVAILABLE,
                        fingerprint=fingerprint,
                        local_label=triage.label,
                        local_score=triage.score,
                        local_reason="shared Jev request returned no result",
                        coalesced=True,
                    ),
                    started,
                )
            shared_assessment = shared.assessment
            usable = shared_assessment is not None and shared_assessment.status in {
                JevAssessmentStatus.OK, JevAssessmentStatus.CACHED,
            }
            if shared_assessment is not None:
                shared_assessment = replace(
                    shared_assessment,
                    status=JevAssessmentStatus.CACHED if usable else shared_assessment.status,
                    event_id=context.event_id,
                    reason="single-flight Jev result reused" if usable else shared_assessment.reason,
                )
            return self._finish(
                replace(
                    shared,
                    event_id=context.event_id,
                    route=JevRoute.COALESCED if usable else JevRoute.UNAVAILABLE,
                    local_label=triage.label,
                    local_score=triage.score,
                    local_reason=triage.reason if usable else shared.local_reason,
                    remote_called=False,
                    coalesced=True,
                    cache_hit=False,
                    disagreement=self._is_disagreement(triage, shared_assessment) if usable else False,
                    assessment=shared_assessment,
                ),
                started,
            )

        assert flight is not None
        try:
            assessment = self.advisor.evaluate(context)
            if assessment.status in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}:
                self._put_cache(fingerprint, assessment, reservation_now)
            disagreement = self._is_disagreement(triage, assessment)
            route = JevRoute.DISAGREEMENT if disagreement else (
                JevRoute.REMOTE if assessment.status in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}
                else JevRoute.UNAVAILABLE
            )
            result = JevEfficientAssessment(
                event_id=context.event_id,
                route=route,
                fingerprint=fingerprint,
                local_label=triage.label,
                local_score=triage.score,
                local_reason=triage.reason,
                remote_called=True,
                disagreement=disagreement,
                assessment=assessment,
            )
        except Exception as error:  # pragma: no cover - defensive adapter boundary
            result = JevEfficientAssessment(
                event_id=context.event_id,
                route=JevRoute.UNAVAILABLE,
                fingerprint=fingerprint,
                local_label=triage.label,
                local_score=triage.score,
                local_reason=f"Jev adapter failed: {type(error).__name__}",
                remote_called=True,
            )
        with self._lock:
            flight.result = result
            self._inflight.pop(fingerprint, None)
            flight.done.set()
        return self._finish(result, started)

    def metrics(self) -> JevEfficiencyMetrics:
        with self._lock:
            values = sorted(self._latencies)
            return JevEfficiencyMetrics(
                total_requests=self._total_requests,
                unverified=self._unverified,
                local_safe=self._local_safe,
                local_enforced=self._local_enforced,
                remote_calls=self._remote_calls,
                cache_hits=self._cache_hits,
                coalesced_requests=self._coalesced_requests,
                budget_exhausted=self._budget_exhausted,
                provider_failures=self._provider_failures,
                disagreements=self._disagreements,
                p50_latency_ms=self._percentile(values, 0.50),
                p95_latency_ms=self._percentile(values, 0.95),
            )

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()
        self.advisor.clear_cache()

    def _triage(self, context: SemanticContext) -> _Triage:
        if type(context.source_verified) is not bool:
            return _Triage(JevRoute.SKIPPED_UNVERIFIED, "unknown", 1.0, "source verification flag is not boolean")
        if not context.source_verified:
            return _Triage(JevRoute.SKIPPED_UNVERIFIED, "unknown", 1.0, "source is not verified")
        risk_valid, risk = _unit_input(context.graph_risk)
        criticality_valid, criticality = _unit_input(context.mission_criticality)
        confidence_valid, confidence = _unit_input(context.event_confidence)
        if not (risk_valid and criticality_valid and confidence_valid):
            return _Triage(JevRoute.LOCAL_ENFORCED, "unknown", 1.0, "non-finite or out-of-range risk input is enforced locally")
        if not isinstance(context.temporal_codes, (tuple, list)) or not all(isinstance(code, str) for code in context.temporal_codes):
            return _Triage(JevRoute.LOCAL_ENFORCED, "unknown", 1.0, "invalid temporal evidence is enforced locally")
        state = str(context.safety_state or "").upper()
        label = self._local_label(context)
        score = max(risk, criticality, max((self._TEMPORAL_SCORES.get(str(code).upper(), 0.0) for code in context.temporal_codes), default=0.0))
        if state in {"SAFE_STOP", "EMERGENCY_STOP"} or risk >= self.policy.critical_risk_threshold or (risk >= 0.70 and criticality >= 0.95):
            return _Triage(JevRoute.LOCAL_ENFORCED, label, max(score, risk), "deterministic critical risk is enforced locally")
        if (
            state == "NORMAL"
            and not context.temporal_codes
            and risk <= self.policy.safe_risk_threshold
            and criticality <= self.policy.safe_mission_criticality_threshold
            and confidence >= self.policy.safe_confidence_threshold
        ):
            return _Triage(JevRoute.LOCAL_SAFE, label, score, "verified low-risk event passed local fast path")
        return _Triage(JevRoute.REMOTE, label, score, "semantic ambiguity requires bounded Jev advice")

    def _local_label(self, context: SemanticContext) -> str:
        value = str(context.attack_type or "").strip().lower().replace("-", "_").replace(" ", "_")
        if value in JevSemanticAdvisor.ATTACK_LABELS:
            return value
        for code in context.temporal_codes:
            normalized = str(code).strip().lower().replace("-", "_").replace(" ", "_")
            if normalized in JevSemanticAdvisor.ATTACK_LABELS:
                return normalized
        return "benign" if _bounded(context.graph_risk) < self.policy.safe_risk_threshold else "unknown"

    def _fingerprint(self, context: SemanticContext) -> str:
        state = context.to_state()
        state.pop("event_id", None)
        state.pop("sequence", None)
        state["temporal_codes"] = sorted(set(state.get("temporal_codes", [])))
        state["active_components"] = sorted(set(state.get("active_components", [])))
        state["attack_type"] = str(state.get("attack_type", "")).lower()
        state["safety_state"] = str(state.get("safety_state", "")).upper()
        payload = {
            "model": self.advisor.config.model,
            "policy_version": self.policy.policy_version,
            "state": state,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _fallback_fingerprint(context: SemanticContext) -> str:
        return hashlib.sha256(repr(context).encode("utf-8", errors="replace")).hexdigest()

    def _get_cache(self, fingerprint: str, now: float) -> JevAssessment | None:
        with self._lock:
            # Re-sample after acquiring the cache lock. A caller can be
            # descheduled after its first clock read; using that stale value
            # could revive an efficient-layer entry past its TTL.
            now = max(now, self._now())
            entry = self._cache.get(fingerprint)
            if entry is None:
                return None
            expires_at, assessment = entry
            if now >= expires_at:
                self._cache.pop(fingerprint, None)
                return None
            self._cache.move_to_end(fingerprint)
            return assessment

    def _put_cache(self, fingerprint: str, assessment: JevAssessment, now: float) -> None:
        # Only a fresh provider answer starts a new efficient-layer lease.
        # Re-caching an advisor CACHED result would let a lower cache renew
        # this layer forever without another provider result.
        if self.policy.cache_ttl_sec <= 0.0 or assessment.status != JevAssessmentStatus.OK:
            return
        with self._lock:
            self._cache[fingerprint] = (now + self.policy.cache_ttl_sec, assessment)
            self._cache.move_to_end(fingerprint)
            while len(self._cache) > self.policy.max_cache_entries:
                self._cache.popitem(last=False)

    def _reserve_budget_locked(self, now: float) -> bool:
        if now < self._window_started or now - self._window_started >= self.policy.budget_window_sec:
            self._window_started = now
            self._remote_calls_in_window = 0
        if self._remote_calls_in_window >= self.policy.max_remote_calls:
            return False
        self._remote_calls_in_window += 1
        return True

    def _is_disagreement(self, triage: _Triage, assessment: JevAssessment) -> bool:
        if assessment.status not in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}:
            return False
        remote_label = assessment.label.lower()
        if triage.score >= 0.5 and triage.label not in {"benign", "unknown"} and remote_label == "benign":
            return True
        return triage.score <= self.policy.safe_risk_threshold and assessment.score >= 0.8

    def _finish(self, result: JevEfficientAssessment, started: float) -> JevEfficientAssessment:
        latency = max(0.0, (self._now() - started) * 1000.0)
        result = replace(result, latency_ms=latency)
        with self._lock:
            self._total_requests += 1
            self._latencies.append(latency)
            if result.route == JevRoute.SKIPPED_UNVERIFIED:
                self._unverified += 1
            elif result.route == JevRoute.LOCAL_SAFE:
                self._local_safe += 1
            elif result.route == JevRoute.LOCAL_ENFORCED:
                self._local_enforced += 1
            if result.remote_called:
                self._remote_calls += 1
                if result.assessment is None or result.assessment.status not in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}:
                    self._provider_failures += 1
            if result.cache_hit:
                self._cache_hits += 1
            if result.coalesced:
                self._coalesced_requests += 1
            if result.disagreement:
                self._disagreements += 1
        return result

    def _now(self) -> float:
        """Return a finite, non-decreasing clock value for cache/budget timing."""

        try:
            candidate = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            candidate = float("nan")
        with self._clock_lock:
            if not math.isfinite(candidate):
                candidate = self._last_clock if self._last_clock is not None else 0.0
            elif self._last_clock is not None and candidate < self._last_clock:
                candidate = self._last_clock
            self._last_clock = candidate
            return candidate

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        index = min(len(values) - 1, max(0, int(math.ceil(percentile * len(values))) - 1))
        return round(values[index], 3)


__all__ = [
    "JevEfficientAssessment",
    "JevEfficientJudge",
    "JevEfficiencyMetrics",
    "JevEfficiencyPolicy",
    "JevRoute",
]
