"""Contract tests for the dashboard's bounded Jev proxy service.

These tests deliberately exercise the pure service boundary rather than the
HTTP server.  The dashboard can then use the same validation and error
mapping for a browser request and for an offline caller.
"""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Mapping
from urllib.error import HTTPError

import pytest

from guardian_core.dashboard_jev import JevDashboardService, _NoRedirectHandler, parse_request


API_KEY = "jev-test-key-do-not-log"
STATE = "verified high-rate command anomaly in the navigation component"


class FakeTransport:
    """Capture one provider call and optionally return/raise a fixture."""

    def __init__(self, response: bytes | None = None, error: BaseException | None = None):
        self.response = response
        self.error = error
        self.calls: list[dict[str, object]] = []

    def __call__(self, endpoint, headers, body, timeout):
        self.calls.append(
            {
                "endpoint": endpoint,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


def valid_response() -> bytes:
    return json.dumps(
        {
            "model": "jev-1.13.0",
            "answers": {
                "attack_type": {
                    "type": "choice",
                    "choice": "unsafe_command",
                    "confidence": 0.92,
                    "probabilities": {"unsafe_command": 0.92},
                },
                "mission_impact": {
                    "type": "choice",
                    "choice": "critical",
                    "confidence": 0.88,
                    "probabilities": {"critical": 0.90},
                },
                "needs_human_review": {"type": "noul", "noul": 1.0},
            },
        }
    ).encode("utf-8")


def make_service(transport: FakeTransport) -> JevDashboardService:
    return JevDashboardService(transport=transport)


def payload_of(response) -> Mapping[str, object]:
    payload = response.payload
    assert isinstance(payload, Mapping)
    return payload


def assert_rejection(call, expected_status: int) -> None:
    """Accept either a typed rejection response or a typed exception."""

    try:
        response = call()
    except Exception as error:  # noqa: BLE001 - boundary contract allows either form
        actual = getattr(error, "http_status", getattr(error, "status_code", None))
        assert actual == expected_status, repr(error)
        return
    assert response.http_status == expected_status


def test_missing_api_key_is_rejected_without_calling_provider():
    transport = FakeTransport(response=valid_response())
    service = make_service(transport)

    try:
        response = service.test("", STATE)
    except Exception as error:  # noqa: BLE001 - validation may be exception based
        assert isinstance(error, (TypeError, ValueError))
        assert not transport.calls
        return

    payload = payload_of(response)
    assert response.http_status == 400
    assert payload["status"] == "INVALID_REQUEST"
    assert payload["connected"] is False
    assert not transport.calls


def test_invalid_json_request_is_rejected_with_bad_request():
    assert_rejection(lambda: parse_request(b"{not-json"), 400)


def test_request_larger_than_64_kibibytes_is_rejected():
    oversized = b"{" + b"x" * (64 * 1024) + b"}"
    assert len(oversized) > 64 * 1024
    assert_rejection(lambda: parse_request(oversized), 413)


def test_api_key_control_characters_are_rejected_before_provider_call():
    transport = FakeTransport(response=valid_response())
    service = make_service(transport)

    response = service.test("bad\nkey", STATE)

    assert response.http_status == 400
    assert response.payload["error"]["code"] == "invalid_api_key"
    assert not transport.calls


def test_successful_provider_call_returns_bounded_assessment_and_redacts_key(caplog):
    transport = FakeTransport(response=valid_response())
    service = make_service(transport)

    with caplog.at_level(logging.INFO):
        response = service.test(API_KEY, STATE)

    payload = payload_of(response)
    assert response.http_status == 200
    assert payload["status"] == "OK"
    assert payload["connected"] is True
    assessment = payload["assessment"]
    assert isinstance(assessment, Mapping)
    assert assessment["label"] == "unsafe_command"
    assert assessment["mission_impact"] == "critical"
    assert 0.0 <= float(assessment["score"]) <= 1.0
    assert 0.0 <= float(assessment["confidence"]) <= 1.0
    assert isinstance(payload["latency_ms"], (int, float))
    assert payload["latency_ms"] >= 0

    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["endpoint"] == "https://api.typesafe.ai/v1/systemone"
    headers = call["headers"]
    assert isinstance(headers, Mapping)
    assert headers.get("Authorization") == f"Bearer {API_KEY}"
    assert headers.get("Content-Type") == "application/json"
    request_body = json.loads(call["body"].decode("utf-8"))
    assert request_body["model"] == "jev-latest"
    assert request_body["state"]["summary"] == STATE
    assert set(request_body["questions"]) == {"attack_type", "mission_impact", "needs_human_review"}
    assert API_KEY not in json.dumps(request_body)
    assert API_KEY not in json.dumps({k: v for k, v in headers.items() if k != "Authorization"})
    assert API_KEY not in json.dumps(payload)
    assert API_KEY not in caplog.text


@pytest.mark.parametrize("status_code", [401, 429])
def test_upstream_http_errors_are_unavailable_and_do_not_leak_key(status_code, caplog):
    error = HTTPError(
        "https://api.typesafe.ai/v1/systemone",
        status_code,
        "provider rejected request",
        hdrs=None,
        fp=io.BytesIO(b"secret provider details"),
    )
    transport = FakeTransport(error=error)
    service = make_service(transport)

    with caplog.at_level(logging.INFO):
        response = service.test(API_KEY, STATE)

    payload = payload_of(response)
    assert response.http_status == 502
    assert payload["status"] == "UNAVAILABLE"
    assert payload["connected"] is False
    assert "error" in payload and isinstance(payload["error"], Mapping)
    error_payload = payload["error"]
    assert str(status_code) in json.dumps(error_payload)
    assert API_KEY not in json.dumps(payload)
    assert API_KEY not in caplog.text


def test_provider_timeout_maps_to_gateway_timeout():
    service = make_service(FakeTransport(error=TimeoutError("provider timed out")))

    response = service.test(API_KEY, STATE)

    payload = payload_of(response)
    assert response.http_status == 504
    assert payload["status"] == "UNAVAILABLE"
    assert payload["connected"] is False
    assert "timed" in json.dumps(payload["error"]).lower()


def test_invalid_provider_response_maps_to_bad_gateway_without_raw_body():
    service = make_service(FakeTransport(response=b"not-json"))

    response = service.test(API_KEY, STATE)

    payload = payload_of(response)
    assert response.http_status == 502
    assert payload["status"] == "INVALID"
    assert payload["connected"] is False
    assert b"not-json" not in json.dumps(payload).encode("utf-8")
    assert API_KEY not in json.dumps(payload)


def test_provider_echo_of_api_key_is_redacted_from_success_payload(caplog):
    response = json.loads(valid_response())
    response["model"] = API_KEY
    service = make_service(FakeTransport(response=json.dumps(response).encode("utf-8")))

    with caplog.at_level(logging.INFO):
        result = service.test(API_KEY, STATE)

    assert result.http_status == 200
    assert API_KEY not in json.dumps(result.payload)
    assert API_KEY not in caplog.text


def test_dashboard_rejects_non_official_remote_endpoint():
    with pytest.raises(ValueError, match="official TypeSafe endpoint"):
        JevDashboardService(endpoint="https://evil.example.test")


def test_dashboard_transport_does_not_follow_provider_redirects():
    handler = _NoRedirectHandler()

    assert handler.redirect_request(object(), None, 302, "Found", {}) is None
