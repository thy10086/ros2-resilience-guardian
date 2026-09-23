"""Optional, fail-safe semantic advice from TypeSafe Jev.

The advisor is deliberately a side-channel. It classifies a compact incident
summary and returns bounded evidence for audit or offline fusion experiments;
it never owns the ROS 2 control loop, safety state machine, or recovery gate.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, replace
from enum import Enum
from threading import Lock
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"
_MAX_TEXT = 512
_SENSITIVE_VALUE = re.compile(
    r"(?i)\b(api[_ -]?key|authorization|credential|password|secret|signature|token)"
    r"\s*[:=]\s*([^\s,;]+)"
)


def _bounded(value: Any, default: float = 0.0) -> float:
    """Return a finite float in the interval [0, 1]."""

    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(number):
        return default
    return max(0.0, min(1.0, number))


def _safe_text(value: Any, *, limit: int = _MAX_TEXT) -> str:
    text = str(value or "").replace("\x00", " ")
    text = "".join(character if character.isprintable() else " " for character in text)
    text = _SENSITIVE_VALUE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    return text.strip()[:limit]


def _normal_label(value: Any, allowed: set[str], *, unknown: str = "UNKNOWN") -> str:
    label = _safe_text(value, limit=64).lower().replace("-", "_").replace(" ", "_")
    return label if label in allowed else unknown


class JevAssessmentStatus(str, Enum):
    DISABLED = "DISABLED"
    SKIPPED_UNVERIFIED = "SKIPPED_UNVERIFIED"
    OK = "OK"
    CACHED = "CACHED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


@dataclass(frozen=True)
class SemanticContext:
    """Allowlisted, low-volume context safe to send for semantic review."""

    event_id: str
    component: str
    attack_type: str
    event_confidence: float
    source_verified: bool
    temporal_codes: tuple[str, ...] = ()
    graph_risk: float = 0.0
    mission_criticality: float = 0.0
    active_components: tuple[str, ...] = ()
    safety_state: str = "UNKNOWN"
    sequence: int = 0
    summary: str = ""

    def to_state(self) -> dict[str, Any]:
        """Serialize only bounded, non-secret fields for the remote request."""

        return {
            "event_id": _safe_text(self.event_id, limit=96),
            "component": _safe_text(self.component, limit=96),
            "attack_type": _safe_text(self.attack_type, limit=64),
            "event_confidence": _bounded(self.event_confidence),
            "source_verified": bool(self.source_verified),
            "temporal_codes": [_safe_text(code, limit=64) for code in self.temporal_codes[:16]],
            "graph_risk": _bounded(self.graph_risk),
            "mission_criticality": _bounded(self.mission_criticality),
            "active_components": [_safe_text(item, limit=96) for item in self.active_components[:32]],
            "safety_state": _safe_text(self.safety_state, limit=64),
            "sequence": self._safe_sequence(),
            "summary": _safe_text(self.summary),
        }

    def _safe_sequence(self) -> int:
        try:
            return max(0, int(self.sequence))
        except (TypeError, ValueError, OverflowError):
            return 0


@dataclass(frozen=True)
class JevAdvisorConfig:
    """Runtime configuration; disabled and keyless by default."""

    enabled: bool = False
    api_key: str = ""
    endpoint: str = DEFAULT_ENDPOINT
    model: str = DEFAULT_MODEL
    timeout_sec: float = 1.5
    max_response_bytes: int = 64 * 1024
    cache_ttl_sec: float = 5.0
    max_cache_entries: int = 128

    def __post_init__(self) -> None:
        if not self.endpoint:
            raise ValueError("Jev endpoint must not be empty")
        try:
            parsed = urlparse(self.endpoint)
            hostname = parsed.hostname
        except ValueError as error:
            raise ValueError("Jev endpoint is not a valid URL") from error
        if not hostname or parsed.username or parsed.password:
            raise ValueError("Jev endpoint must not contain URL credentials")
        if parsed.scheme != "https" and hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Jev endpoint must use HTTPS (HTTP is allowed only for localhost tests)")
        try:
            timeout = float(self.timeout_sec)
            max_response_bytes = int(self.max_response_bytes)
            cache_ttl = float(self.cache_ttl_sec)
            max_cache_entries = int(self.max_cache_entries)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("Jev numeric configuration is invalid") from error
        if not math.isfinite(timeout) or not 0.05 <= timeout <= 30.0:
            raise ValueError("Jev timeout must be between 0.05 and 30 seconds")
        if max_response_bytes < 1024:
            raise ValueError("Jev response limit is too small")
        if not math.isfinite(cache_ttl) or cache_ttl < 0.0:
            raise ValueError("Jev cache TTL must be non-negative")
        if max_cache_entries < 1:
            raise ValueError("Jev cache must hold at least one entry")


@dataclass(frozen=True)
class JevAssessment:
    """Normalized, bounded Jev output suitable for audit or soft evidence."""

    status: JevAssessmentStatus
    event_id: str
    label: str = "UNKNOWN"
    score: float = 0.0
    confidence: float = 0.0
    mission_impact: str = "unknown"
    needs_human_review: bool = False
    provider: str = "typesafe"
    model: str = DEFAULT_MODEL
    observed_at: float = 0.0
    expires_at: float = 0.0
    reason: str = ""

    def recommends_review(self, *, score_threshold: float = 0.75, confidence_threshold: float = 0.75) -> bool:
        """Return a soft review suggestion; this cannot alter safety state."""

        return (
            self.status in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}
            and self.needs_human_review
            and self.score >= _bounded(score_threshold)
            and self.confidence >= _bounded(confidence_threshold)
        )

    def audit_payload(self) -> dict[str, Any]:
        """Return safe metadata for AuditLogger; no request or credential data."""

        return {
            "status": self.status.value,
            "event_id": self.event_id,
            "label": self.label,
            "score": self.score,
            "confidence": self.confidence,
            "mission_impact": self.mission_impact,
            "needs_human_review": self.needs_human_review,
            "provider": self.provider,
            "model": self.model,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "reason": self.reason,
        }


class JevTransport(Protocol):
    def __call__(self, endpoint: str, headers: Mapping[str, str], body: bytes, timeout: float) -> bytes:
        ...


class JevSemanticAdvisor:
    """Call Jev only for verified summaries and normalize its response.

    The injected transport makes offline tests deterministic. The default
    transport performs one bounded HTTP request with no automatic retry.
    """

    ATTACK_LABELS = {"flooding", "replay", "stale", "unsafe_command", "semantic_misbehavior", "benign"}
    IMPACT_LABELS = {"low", "medium", "critical"}

    def __init__(
        self,
        config: JevAdvisorConfig | None = None,
        *,
        transport: JevTransport | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config or JevAdvisorConfig()
        self._transport = transport or self._http_transport
        self._clock = clock or time.time
        self._cache: dict[str, tuple[float, JevAssessment]] = {}
        self._cache_lock = Lock()

    def evaluate(self, context: SemanticContext) -> JevAssessment:
        now = float(self._clock())
        if type(context.source_verified) is not bool or not context.source_verified:
            return self._result(
                JevAssessmentStatus.SKIPPED_UNVERIFIED,
                context,
                now,
                "unverified source is never sent to Jev",
            )
        if not self.config.enabled or not self.config.api_key.strip():
            return self._result(JevAssessmentStatus.DISABLED, context, now, "Jev advisor is disabled or keyless")

        cache_key = self._cache_key(context)
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached is not None:
                expires_at, assessment = cached
                if now < expires_at:
                    return replace(assessment, status=JevAssessmentStatus.CACHED, reason="cached Jev assessment")
                self._cache.pop(cache_key, None)

        body = json.dumps(self._request_payload(context), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            raw = self._transport(
                self.config.endpoint,
                {"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json"},
                body,
                float(self.config.timeout_sec),
            )
            if len(raw) > int(self.config.max_response_bytes):
                return self._result(JevAssessmentStatus.INVALID, context, now, "Jev response exceeded size limit")
            payload = json.loads(raw.decode("utf-8"))
            assessment = self._parse_response(payload, context, now)
        except HTTPError as error:
            return self._result(JevAssessmentStatus.UNAVAILABLE, context, now, f"Jev HTTP error {error.code}")
        except (TimeoutError, URLError, OSError) as error:
            detail = _safe_text(error, limit=160)
            return self._result(JevAssessmentStatus.UNAVAILABLE, context, now, detail or "Jev transport failed")
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            detail = _safe_text(error, limit=160)
            return self._result(JevAssessmentStatus.INVALID, context, now, detail or "Jev response was invalid")
        except Exception as error:  # pragma: no cover - defensive provider boundary
            detail = _safe_text(error, limit=160)
            return self._result(JevAssessmentStatus.UNAVAILABLE, context, now, detail or "Jev provider failed")

        if assessment.status == JevAssessmentStatus.OK:
            with self._cache_lock:
                if len(self._cache) >= int(self.config.max_cache_entries):
                    oldest = min(self._cache, key=lambda key: self._cache[key][0])
                    self._cache.pop(oldest, None)
                self._cache[cache_key] = (assessment.expires_at, assessment)
        return assessment

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    def _request_payload(self, context: SemanticContext) -> dict[str, Any]:
        return {
            "state": context.to_state(),
            "model": self.config.model,
            "questions": {
                "attack_type": {
                    "type": "choice",
                    "instructions": "What type of security event best describes this verified incident?",
                    "criteria": {
                        "flooding": "A source emits an unusual volume or rate of messages.",
                        "replay": "An old or repeated message is being reused.",
                        "stale": "A message is too old for the current control decision.",
                        "unsafe_command": "A command can create unsafe physical behavior.",
                        "semantic_misbehavior": "The format is valid but the behavior is suspicious.",
                        "benign": "The evidence is consistent with normal operation.",
                    },
                },
                "mission_impact": {
                    "type": "choice",
                    "instructions": "How severe is the likely mission impact?",
                    "criteria": {
                        "low": "No meaningful effect on robot behavior.",
                        "medium": "The mission may need to degrade or pause.",
                        "critical": "The event can affect a critical actuator or safety boundary.",
                    },
                },
                "needs_human_review": {
                    "type": "noul",
                    "instructions": "Should a human review this incident before mission recovery?",
                },
            },
        }

    def _parse_response(self, payload: Any, context: SemanticContext, now: float) -> JevAssessment:
        if not isinstance(payload, Mapping) or not isinstance(payload.get("answers"), Mapping):
            return self._result(JevAssessmentStatus.INVALID, context, now, "Jev response has no answers object")
        answers = payload["answers"]
        attack = answers.get("attack_type")
        impact = answers.get("mission_impact")
        review = answers.get("needs_human_review")
        if not all(isinstance(answer, Mapping) for answer in (attack, impact, review)):
            return self._result(JevAssessmentStatus.INVALID, context, now, "Jev response is missing typed answers")
        if (
            _safe_text(attack.get("type"), limit=16).lower() != "choice"
            or _safe_text(impact.get("type"), limit=16).lower() != "choice"
            or _safe_text(review.get("type"), limit=16).lower() != "noul"
        ):
            return self._result(JevAssessmentStatus.INVALID, context, now, "Jev response has mismatched answer types")

        label = _normal_label(attack.get("choice"), self.ATTACK_LABELS)
        mission_impact = _normal_label(impact.get("choice"), self.IMPACT_LABELS, unknown="unknown")
        attack_probabilities = attack.get("probabilities") if isinstance(attack.get("probabilities"), Mapping) else {}
        impact_probabilities = impact.get("probabilities") if isinstance(impact.get("probabilities"), Mapping) else {}
        attack_score = _bounded(attack_probabilities.get(label, 0.0)) if label != "UNKNOWN" else 0.0
        impact_score = _bounded(impact_probabilities.get(mission_impact, 0.0)) if mission_impact != "unknown" else 0.0
        if mission_impact == "medium":
            impact_score *= 0.6
        review_probability = _bounded(review.get("noul", 0.0))
        score = max(attack_score, impact_score, review_probability * 0.8)

        confidence_values = [
            _bounded(attack.get("confidence"), default=-1.0),
            _bounded(impact.get("confidence"), default=-1.0),
        ]
        confidence_values = [value for value in confidence_values if value >= 0.0]
        confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.5
        model = _safe_text(payload.get("model") or self.config.model, limit=96)
        reason = f"Jev classified {label} with {mission_impact} mission impact"
        return JevAssessment(
            status=JevAssessmentStatus.OK,
            event_id=_safe_text(context.event_id, limit=96),
            label=label,
            score=_bounded(score),
            confidence=_bounded(confidence),
            mission_impact=mission_impact,
            needs_human_review=review_probability >= 0.5,
            model=model or self.config.model,
            observed_at=now,
            expires_at=now + float(self.config.cache_ttl_sec),
            reason=reason,
        )

    def _result(self, status: JevAssessmentStatus, context: SemanticContext, now: float, reason: str) -> JevAssessment:
        return JevAssessment(
            status=status,
            event_id=_safe_text(context.event_id, limit=96),
            model=self.config.model,
            observed_at=now,
            expires_at=now,
            reason=reason,
        )

    def _cache_key(self, context: SemanticContext) -> str:
        encoded = json.dumps(
            {"model": self.config.model, "state": context.to_state()},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _http_transport(self, endpoint: str, headers: Mapping[str, str], body: bytes, timeout: float) -> bytes:
        request = Request(endpoint, data=body, headers=dict(headers), method="POST")
        with urlopen(request, timeout=timeout) as response:
            return response.read(int(self.config.max_response_bytes) + 1)


__all__ = [
    "DEFAULT_ENDPOINT",
    "DEFAULT_MODEL",
    "JevAdvisorConfig",
    "JevAssessment",
    "JevAssessmentStatus",
    "JevSemanticAdvisor",
    "SemanticContext",
]
