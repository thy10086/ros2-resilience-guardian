"""Temporal Jev incident sessions with short-lived ledger-bound advice."""

from __future__ import annotations

import hashlib
import json
import math
from collections import OrderedDict
from dataclasses import dataclass, replace
from enum import Enum
from threading import Lock
from typing import Any, Callable

from .evidence_ledger import Evidence, EvidenceLedger
from .jev_advisor import JevAssessmentStatus, SemanticContext
from .jev_efficiency import JevEfficientAssessment, JevEfficientJudge, JevRoute


def _unit(value: Any) -> tuple[bool, float]:
    if isinstance(value, bool):
        return False, 0.0
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return False, 0.0
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return False, 0.0
    return True, number


class JevSessionState(str, Enum):
    OBSERVING = "OBSERVING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    CONTAINING = "CONTAINING"
    EXPIRED = "EXPIRED"


class JevSessionRoute(str, Enum):
    QUERIED = "QUERIED"
    SESSION_REUSE = "SESSION_REUSE"
    LEDGER_BLOCKED = "LEDGER_BLOCKED"


@dataclass(frozen=True)
class JevSessionConfig:
    """Temporal thresholds and evidence lifetime for one session manager."""

    session_ttl_sec: float = 30.0
    min_query_interval_sec: float = 1.0
    risk_change_trigger: float = 0.15
    review_enter_score: float = 0.65
    review_exit_score: float = 0.35
    stable_window_sec: float = 2.0
    soft_evidence_ttl_sec: float = 5.0
    policy_version: str = "p1"
    max_sessions: int = 128

    def __post_init__(self) -> None:
        for name in (
            "session_ttl_sec",
            "min_query_interval_sec",
            "stable_window_sec",
            "soft_evidence_ttl_sec",
        ):
            value = getattr(self, name)
            if isinstance(value, bool):
                raise ValueError(f"{name} must be finite and non-negative")
            try:
                number = float(value)
            except (TypeError, ValueError, OverflowError) as error:
                raise ValueError(f"{name} must be finite and non-negative") from error
            if not math.isfinite(number) or number < 0.0:
                raise ValueError(f"{name} must be finite and non-negative")
        for name in ("risk_change_trigger", "review_enter_score", "review_exit_score"):
            valid, number = _unit(getattr(self, name))
            if not valid:
                raise ValueError(f"{name} must be finite and in [0, 1]")
        if self.review_exit_score >= self.review_enter_score:
            raise ValueError("review_exit_score must be below review_enter_score")
        if self.soft_evidence_ttl_sec == 0.0:
            raise ValueError("soft_evidence_ttl_sec must be positive")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("policy_version must not be empty")
        if not isinstance(self.max_sessions, int) or isinstance(self.max_sessions, bool) or self.max_sessions < 1:
            raise ValueError("max_sessions must be a positive integer")


@dataclass(frozen=True)
class JevSessionDecision:
    session_id: str
    event_id: str
    state: JevSessionState
    route: JevSessionRoute
    effective_score: float
    local_score: float
    queried: bool
    ledger_bound: bool
    ledger_evidence_id: str | None
    observation_count: int
    expires_at: float
    reason: str
    assessment: JevEfficientAssessment | None = None

    def audit_payload(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "event_id": self.event_id,
            "state": self.state.value,
            "route": self.route.value,
            "effective_score": self.effective_score,
            "local_score": self.local_score,
            "queried": self.queried,
            "ledger_bound": self.ledger_bound,
            "ledger_evidence_id": self.ledger_evidence_id,
            "observation_count": self.observation_count,
            "expires_at": self.expires_at,
            "reason": self.reason,
        }


@dataclass
class _SessionRecord:
    state: JevSessionState
    created_at: float
    last_seen: float
    last_query_at: float | None = None
    last_local_score: float = 0.0
    last_safety_state: str = "UNKNOWN"
    last_result: JevEfficientAssessment | None = None
    last_context_signature: str = ""
    below_review_since: float | None = None
    observation_count: int = 0
    last_evidence_id: str | None = None
    last_parent_evidence_id: str | None = None


class JevIncidentSession:
    """Aggregate Jev judgments without letting semantic advice control safety."""

    def __init__(
        self,
        judge: JevEfficientJudge,
        ledger: EvidenceLedger,
        *,
        config: JevSessionConfig | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.judge = judge
        self.ledger = ledger
        self.config = config or JevSessionConfig()
        self._clock = clock or __import__("time").monotonic
        self._lock = Lock()
        self._ledger_lock = Lock()
        self._sessions: OrderedDict[str, _SessionRecord] = OrderedDict()
        self._session_locks: dict[str, Lock] = {}

    def _observed_at(self, supplied: float | None) -> float:
        candidate = self._clock() if supplied is None else supplied
        try:
            value = float(candidate)
        except (TypeError, ValueError, OverflowError):
            value = float("nan")
        if math.isfinite(value):
            return value
        try:
            fallback = float(self._clock())
        except (TypeError, ValueError, OverflowError):
            fallback = 0.0
        return fallback if math.isfinite(fallback) else 0.0

    def observe(
        self,
        context: SemanticContext,
        *,
        parent_evidence_id: str | None,
        incident_key: str | None = None,
        now: float | None = None,
    ) -> JevSessionDecision:
        session_id = self._session_id(context, incident_key)
        with self._lock:
            session_lock = self._session_locks.setdefault(session_id, Lock())
        session_lock.acquire()
        try:
            return self._observe_serialized(
                context,
                parent_evidence_id=parent_evidence_id,
                incident_key=incident_key,
                now=now,
            )
        finally:
            session_lock.release()
            with self._lock:
                self._prune_session_locks()

    def _observe_serialized(
        self,
        context: SemanticContext,
        *,
        parent_evidence_id: str | None,
        incident_key: str | None = None,
        now: float | None = None,
    ) -> JevSessionDecision:
        observed_at = self._observed_at(now)
        session_id = self._session_id(context, incident_key)
        with self._lock:
            record = self._sessions.get(session_id)
            if record is not None and observed_at < record.last_seen:
                observed_at = record.last_seen
            expired = record is not None and observed_at - record.last_seen > self.config.session_ttl_sec
            if expired:
                self._sessions.pop(session_id, None)
                record = None
            elif record is not None:
                self._sessions.move_to_end(session_id)

        if not self._ledger_valid():
            if record is None:
                record = _SessionRecord(state=JevSessionState.CONTAINING, created_at=observed_at, last_seen=observed_at)
            record.state = JevSessionState.CONTAINING
            record.last_seen = observed_at
            record.observation_count += 1
            self._store_record(session_id, record)
            return JevSessionDecision(
                session_id=session_id,
                event_id=str(context.event_id),
                state=JevSessionState.CONTAINING,
                route=JevSessionRoute.LEDGER_BLOCKED,
                effective_score=1.0,
                local_score=1.0,
                queried=False,
                ledger_bound=False,
                ledger_evidence_id=None,
                observation_count=record.observation_count,
                expires_at=observed_at + self.config.session_ttl_sec,
                reason="ledger integrity failed; semantic judgment is blocked and containment retained",
                assessment=None,
            )

        risk_valid, risk = _unit(context.graph_risk)
        context_signature = self._context_signature(context, parent_evidence_id)
        parent_changed = record is not None and record.last_parent_evidence_id != parent_evidence_id
        queried = record is None or self._should_query(record, context, context_signature, risk_valid, risk, observed_at)
        result = self.judge.evaluate(context) if queried else replace(record.last_result, event_id=str(context.event_id))
        if result is None:
            queried = True
            result = self.judge.evaluate(context)
        local_score = result.local_score
        effective_score = self._effective_score(result, local_score)
        if record is None:
            record = _SessionRecord(
                state=JevSessionState.OBSERVING,
                created_at=observed_at,
                last_seen=observed_at,
            )
        next_state = self._transition(record, context, result, effective_score, observed_at)
        ledger_bound = False
        ledger_evidence_id: str | None = None
        ledger_blocked = False
        if queried and self._eligible_soft_advice(result, allow_cached=parent_changed):
            ledger_bound, ledger_evidence_id, ledger_blocked = self._append_soft_evidence(
                record,
                session_id,
                context,
                parent_evidence_id,
                observed_at,
                result,
            )
            if ledger_blocked:
                next_state = JevSessionState.CONTAINING

        record.state = next_state
        record.last_seen = observed_at
        record.last_local_score = local_score
        record.last_context_signature = context_signature
        record.last_safety_state = str(context.safety_state or "UNKNOWN").upper()
        record.last_result = result
        record.last_parent_evidence_id = parent_evidence_id
        record.observation_count += 1
        if queried:
            record.last_query_at = observed_at
        self._store_record(session_id, record)

        route = JevSessionRoute.LEDGER_BLOCKED if ledger_blocked else (
            JevSessionRoute.QUERIED if queried else JevSessionRoute.SESSION_REUSE
        )
        reason = self._reason(next_state, result, ledger_blocked, expired)
        return JevSessionDecision(
            session_id=session_id,
            event_id=str(context.event_id),
            state=next_state,
            route=route,
            effective_score=effective_score,
            local_score=local_score,
            queried=queried,
            ledger_bound=ledger_bound,
            ledger_evidence_id=ledger_evidence_id,
            observation_count=record.observation_count,
            expires_at=observed_at + self.config.session_ttl_sec,
            reason=reason,
            assessment=result,
        )

    def _should_query(
        self,
        record: _SessionRecord,
        context: SemanticContext,
        context_signature: str,
        risk_valid: bool,
        risk: float,
        now: float,
    ) -> bool:
        if record.last_query_at is None or record.last_result is None:
            return True
        if record.last_context_signature and context_signature != record.last_context_signature:
            return True
        if now - record.last_query_at >= self.config.min_query_interval_sec:
            return True
        if not risk_valid or abs(risk - record.last_local_score) > self.config.risk_change_trigger + 1e-12:
            return True
        safety_state = str(context.safety_state or "UNKNOWN").upper()
        return safety_state != record.last_safety_state

    def _store_record(self, session_id: str, record: _SessionRecord) -> None:
        with self._lock:
            self._sessions[session_id] = record
            self._sessions.move_to_end(session_id)
            while len(self._sessions) > self.config.max_sessions:
                self._sessions.popitem(last=False)

    def _prune_session_locks(self) -> None:
        active_ids = set(self._sessions)
        for session_id, session_lock in tuple(self._session_locks.items()):
            if session_id not in active_ids and not session_lock.locked():
                self._session_locks.pop(session_id, None)

    def _transition(
        self,
        record: _SessionRecord,
        context: SemanticContext,
        result: JevEfficientAssessment,
        score: float,
        now: float,
    ) -> JevSessionState:
        safety_state = str(context.safety_state or "UNKNOWN").upper()
        if result.route in {JevRoute.LOCAL_ENFORCED, JevRoute.SKIPPED_UNVERIFIED} or safety_state in {"SAFE_STOP", "CONTAINING"}:
            record.below_review_since = None
            return JevSessionState.CONTAINING
        assessment = result.assessment
        needs_review = (
            result.disagreement
            or score >= self.config.review_enter_score
            or (assessment is not None and assessment.needs_human_review)
        )
        if record.state == JevSessionState.CONTAINING and not self._stable_exit(record, safety_state, score, now):
            return JevSessionState.CONTAINING
        if needs_review:
            record.below_review_since = None
            return JevSessionState.REVIEW_REQUIRED
        if record.state == JevSessionState.REVIEW_REQUIRED and not self._stable_exit(record, safety_state, score, now):
            return JevSessionState.REVIEW_REQUIRED
        return JevSessionState.OBSERVING

    def _stable_exit(self, record: _SessionRecord, safety_state: str, score: float, now: float) -> bool:
        if safety_state != "NORMAL" or score > self.config.review_exit_score:
            record.below_review_since = None
            return False
        if record.below_review_since is None:
            record.below_review_since = now
            return False
        return now - record.below_review_since >= self.config.stable_window_sec

    def _eligible_soft_advice(self, result: JevEfficientAssessment, *, allow_cached: bool = False) -> bool:
        return (
            (result.remote_called or allow_cached)
            and result.assessment is not None
            and result.assessment.status in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}
        )

    def _append_soft_evidence(
        self,
        record: _SessionRecord,
        session_id: str,
        context: SemanticContext,
        parent_evidence_id: str | None,
        observed_at: float,
        result: JevEfficientAssessment,
    ) -> tuple[bool, str | None, bool]:
        if not parent_evidence_id:
            return False, None, True
        assessment = result.assessment
        assert assessment is not None
        material = json.dumps(
            {
                "session": session_id,
                "fingerprint": result.fingerprint,
                "observed_at": observed_at,
                "count": record.observation_count,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        evidence_id = f"jev-{hashlib.sha256(material).hexdigest()[:24]}"
        evidence = Evidence(
            evidence_id=evidence_id,
            source="jev",
            kind="semantic_advice",
            node=str(context.component or "unknown"),
            observed_at=observed_at,
            expires_at=observed_at + self.config.soft_evidence_ttl_sec,
            confidence=assessment.confidence,
            severity=assessment.score,
            policy_version=self.config.policy_version,
            parent_ids=(parent_evidence_id,),
            supersedes=record.last_evidence_id,
            verified=True,
            hard_stop=False,
        )
        with self._ledger_lock:
            if not self._ledger_valid_unlocked():
                return False, None, True
            try:
                self.ledger.append(evidence)
            except (TypeError, ValueError):
                return False, None, True
        record.last_evidence_id = evidence_id
        return True, evidence_id, False

    def _ledger_valid(self) -> bool:
        with self._ledger_lock:
            return self._ledger_valid_unlocked()

    def _ledger_valid_unlocked(self) -> bool:
        try:
            return bool(self.ledger.verify())
        except Exception:
            return False

    def _effective_score(self, result: JevEfficientAssessment, local_score: float) -> float:
        score = local_score
        if result.assessment is not None and result.assessment.status in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}:
            valid, remote_score = _unit(result.assessment.score)
            if valid:
                score = max(score, remote_score)
        return max(0.0, min(1.0, score))

    @staticmethod
    def _normalized_context_state(context: SemanticContext) -> dict[str, Any]:
        state = context.to_state()
        state.pop("event_id", None)
        state.pop("sequence", None)
        state.pop("summary", None)
        state["temporal_codes"] = sorted(set(str(code).upper() for code in state.get("temporal_codes", ())))
        state["active_components"] = sorted(set(str(item) for item in state.get("active_components", ())))
        state["attack_type"] = str(state.get("attack_type", "")).lower()
        state["safety_state"] = str(state.get("safety_state", "UNKNOWN")).upper()
        state["source_verified"] = context.source_verified if type(context.source_verified) is bool else None
        for field in ("graph_risk", "mission_criticality", "event_confidence"):
            valid, number = _unit(getattr(context, field, None))
            state[field] = round(number, 12) if valid else None
        return state

    @staticmethod
    def _session_id(context: SemanticContext, incident_key: str | None) -> str:
        if incident_key and str(incident_key).strip():
            return str(incident_key).strip()[:128]
        state = JevIncidentSession._normalized_context_state(context)
        payload = {
            "component": state.get("component", ""),
            "attack_type": state.get("attack_type", ""),
            "active_components": state.get("active_components", []),
        }
        return f"incident-{hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:24]}"

    @staticmethod
    def _context_signature(context: SemanticContext, parent_evidence_id: str | None = None) -> str:
        payload = JevIncidentSession._normalized_context_state(context)
        payload["parent_evidence_id"] = str(parent_evidence_id or "")[:256]
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @staticmethod
    def _reason(state: JevSessionState, result: JevEfficientAssessment, blocked: bool, expired: bool) -> str:
        if blocked:
            return "ledger integrity or parent binding blocked semantic evidence; containment retained"
        if expired:
            return f"expired session restarted in {state.value}"
        if result.route == JevRoute.DISAGREEMENT:
            return "Jev disagrees with deterministic evidence; human review is required"
        if result.route == JevRoute.UNAVAILABLE:
            return "Jev unavailable; deterministic session state retained"
        return f"incident session is {state.value}"


__all__ = [
    "JevIncidentSession",
    "JevSessionConfig",
    "JevSessionDecision",
    "JevSessionRoute",
    "JevSessionState",
]
