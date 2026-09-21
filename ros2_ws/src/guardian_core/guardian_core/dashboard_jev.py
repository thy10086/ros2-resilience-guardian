"""Bounded Jev proxy behavior used by the local dashboard.

The browser-facing dashboard accepts a one-shot API key and short state
summary, then discards the key after the provider call.  This module keeps the
provider boundary independent from ROS 2 so it can be tested without a live
node and so the HTTP handler has no credential-specific logic.
"""

from __future__ import annotations

import json
import math
import socket
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .jev_advisor import (
    DEFAULT_ENDPOINT,
    DEFAULT_MODEL,
    JevAdvisorConfig,
    JevAssessment,
    JevAssessmentStatus,
    JevSemanticAdvisor,
    SemanticContext,
)


MAX_REQUEST_BYTES = 64 * 1024
MAX_API_KEY_CHARS = 512
MAX_STATE_CHARS = 4096
DEFAULT_TIMEOUT_SEC = 8.0


class _NoRedirectHandler(HTTPRedirectHandler):
    """Treat provider redirects as errors so credentials never follow them."""

    def redirect_request(self, *_args: Any, **_kwargs: Any):
        return None


_HTTP_OPENER = build_opener(_NoRedirectHandler)


class JevRequestError(ValueError):
    """A client request rejected before contacting the provider."""

    def __init__(self, http_status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.http_status = int(http_status)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class JevProxyResponse:
    """HTTP status and JSON payload returned by :class:`JevDashboardService`."""

    http_status: int
    payload: dict[str, Any]


def _error_response(status: int, code: str, message: str) -> JevProxyResponse:
    response_status = "INVALID_REQUEST" if status < 500 else ("INVALID" if code == "invalid_response" else "UNAVAILABLE")
    return JevProxyResponse(
        http_status=status,
        payload={
            "status": response_status,
            "connected": False,
            "error": {"code": code, "message": message},
        },
    )


def _safe_message(value: Any, *, limit: int = 240) -> str:
    text = str(value or "").replace("\x00", " ")
    text = "".join(character if character.isprintable() else " " for character in text)
    return text.strip()[:limit]


def parse_request(raw: bytes) -> tuple[str, str]:
    """Parse and validate the small JSON body accepted by the dashboard."""

    if not isinstance(raw, (bytes, bytearray)):
        raise JevRequestError(400, "invalid_body", "Request body must be JSON")
    if len(raw) > MAX_REQUEST_BYTES:
        raise JevRequestError(413, "request_too_large", "Request body is too large")
    try:
        value = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JevRequestError(400, "invalid_json", "Request body must be valid JSON") from error
    if not isinstance(value, Mapping):
        raise JevRequestError(400, "invalid_body", "Request body must be a JSON object")

    api_key = value.get("api_key")
    state = value.get("state")
    api_key = _validate_api_key(api_key)
    if not isinstance(state, str) or not state.strip():
        raise JevRequestError(400, "missing_state", "Enter a test state")
    if len(state) > MAX_STATE_CHARS:
        raise JevRequestError(400, "state_too_long", "Test state is too long")
    return api_key.strip(), state.strip()


def _validate_api_key(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise JevRequestError(400, "missing_api_key", "Enter a Jev API key")
    normalized = value.strip()
    if len(normalized) > MAX_API_KEY_CHARS:
        raise JevRequestError(400, "api_key_too_long", "Jev API key is too long")
    if any(ord(character) < 33 or ord(character) > 126 for character in normalized):
        raise JevRequestError(400, "invalid_api_key", "Jev API key contains invalid characters")
    return normalized


class _CaptureTransport:
    """Record only bounded provider failure metadata for response mapping."""

    def __init__(self, transport: Callable[..., bytes]) -> None:
        self.transport = transport
        self.http_status: int | None = None
        self.error: BaseException | None = None

    def __call__(self, endpoint: str, headers: Mapping[str, str], body: bytes, timeout: float) -> bytes:
        try:
            return self.transport(endpoint, headers, body, timeout)
        except HTTPError as error:
            self.http_status = int(error.code)
            self.error = error
            raise
        except Exception as error:
            self.error = error
            raise


class JevDashboardService:
    """Execute one bounded, advisory Jev request for a dashboard user."""

    def __init__(
        self,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        model: str = DEFAULT_MODEL,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        transport: Callable[..., bytes] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        try:
            timeout = float(timeout_sec)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("Jev timeout is invalid") from error
        if not math.isfinite(timeout) or not 0.05 <= timeout <= 30.0:
            raise ValueError("Jev timeout must be between 0.05 and 30 seconds")
        if not isinstance(model, str) or not model.strip() or len(model) > 96:
            raise ValueError("Jev model is invalid")
        parsed_endpoint = urlparse(endpoint)
        if endpoint != DEFAULT_ENDPOINT and parsed_endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Dashboard Jev endpoint must be the official TypeSafe endpoint")
        # Validate the endpoint using the same HTTPS and credential checks as
        # the core adapter.  The dashboard never accepts it from the browser.
        JevAdvisorConfig(endpoint=endpoint, model=model, timeout_sec=timeout)
        self.endpoint = endpoint
        self.model = model.strip()
        self.timeout_sec = timeout
        self.transport = transport
        self.clock = clock or time.monotonic

    def test(self, api_key: str, state: str) -> JevProxyResponse:
        """Call Jev once and return a safe, JSON-ready response."""

        try:
            validated_key, validated_state = self._validate_values(api_key, state)
        except JevRequestError as error:
            return _error_response(error.http_status, error.code, error.message)

        started = float(self.clock())
        captured_transport = _CaptureTransport(self.transport or self._default_transport)
        advisor = JevSemanticAdvisor(
            JevAdvisorConfig(
                enabled=True,
                api_key=validated_key,
                endpoint=self.endpoint,
                model=self.model,
                timeout_sec=self.timeout_sec,
                cache_ttl_sec=0.0,
                max_cache_entries=1,
            ),
            transport=captured_transport,
            clock=self.clock,
        )
        assessment = advisor.evaluate(
            SemanticContext(
                event_id="dashboard-manual-test",
                component="dashboard",
                attack_type="MANUAL_TEST",
                event_confidence=1.0,
                source_verified=True,
                safety_state="MANUAL_TEST",
                summary=validated_state,
            )
        )
        elapsed_ms = max(0.0, (float(self.clock()) - started) * 1000.0)
        if assessment.status in {JevAssessmentStatus.OK, JevAssessmentStatus.CACHED}:
            return JevProxyResponse(
                http_status=200,
                payload={
                    "status": "OK",
                    "connected": True,
                    "assessment": self._assessment_payload(assessment, validated_key),
                    "latency_ms": round(elapsed_ms, 1),
                },
            )

        if assessment.status == JevAssessmentStatus.INVALID:
            return _error_response(502, "invalid_response", "Jev returned an invalid response")

        timeout = self._is_timeout(captured_transport.error, assessment)
        if timeout:
            return _error_response(504, "provider_timeout", "Jev request timed out")
        provider_status = captured_transport.http_status
        if provider_status is not None:
            code = "provider_http_error"
            message = f"Jev provider returned HTTP {provider_status}"
            return JevProxyResponse(
                http_status=502,
                payload={
                    "status": "UNAVAILABLE",
                    "connected": False,
                    "error": {
                        "code": code,
                        "message": message,
                        "upstream_status": provider_status,
                    },
                },
            )
        return _error_response(502, "provider_unavailable", "Jev service is unavailable")

    def _validate_values(self, api_key: Any, state: Any) -> tuple[str, str]:
        normalized_key = _validate_api_key(api_key)
        if not isinstance(state, str) or not state.strip():
            raise JevRequestError(400, "missing_state", "Enter a test state")
        if len(state) > MAX_STATE_CHARS:
            raise JevRequestError(400, "state_too_long", "Test state is too long")
        return normalized_key, state.strip()

    @staticmethod
    def _assessment_payload(assessment: JevAssessment, secret: str) -> dict[str, Any]:
        model = _safe_message(assessment.model).replace(secret, "<redacted>")
        reason = _safe_message(assessment.reason).replace(secret, "<redacted>")
        return {
            "status": assessment.status.value,
            "event_id": assessment.event_id,
            "label": assessment.label,
            "score": assessment.score,
            "confidence": assessment.confidence,
            "mission_impact": assessment.mission_impact,
            "needs_human_review": assessment.needs_human_review,
            "model": model or DEFAULT_MODEL,
            "reason": reason,
        }

    @staticmethod
    def _is_timeout(error: BaseException | None, assessment: JevAssessment) -> bool:
        if isinstance(error, (TimeoutError, socket.timeout)):
            return True
        if isinstance(error, URLError) and "timed out" in str(error.reason).lower():
            return True
        return "timed out" in assessment.reason.lower() or "timeout" in assessment.reason.lower()

    @staticmethod
    def _default_transport(endpoint: str, headers: Mapping[str, str], body: bytes, timeout: float) -> bytes:
        request = Request(endpoint, data=body, headers=dict(headers), method="POST")
        with _HTTP_OPENER.open(request, timeout=timeout) as response:
            return response.read(64 * 1024 + 1)


__all__ = [
    "DEFAULT_TIMEOUT_SEC",
    "JevDashboardService",
    "JevProxyResponse",
    "JevRequestError",
    "MAX_API_KEY_CHARS",
    "MAX_REQUEST_BYTES",
    "MAX_STATE_CHARS",
    "parse_request",
]
