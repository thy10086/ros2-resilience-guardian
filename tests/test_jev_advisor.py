import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from guardian_core.jev_advisor import (
    JevAdvisorConfig,
    JevAssessmentStatus,
    JevSemanticAdvisor,
    SemanticContext,
)


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def __call__(self, endpoint, headers, body, timeout):
        self.calls.append({"endpoint": endpoint, "headers": headers, "body": body, "timeout": timeout})
        if self.error is not None:
            raise self.error
        return self.response


def context(*, sequence=1, source_verified=True, summary="high-rate command anomaly"):
    return SemanticContext(
        event_id=f"event-{sequence}",
        component="nav",
        attack_type="UNSAFE_COMMAND",
        event_confidence=0.8,
        source_verified=source_verified,
        temporal_codes=("REPLAY",),
        graph_risk=0.81,
        mission_criticality=0.9,
        active_components=("nav", "base"),
        safety_state="CONTAINING",
        sequence=sequence,
        summary=summary,
    )


def response_for(
    *,
    attack="unsafe_command",
    attack_confidence=0.92,
    attack_probability=0.92,
    impact="critical",
    impact_confidence=0.88,
    impact_probability=0.90,
    review=1.0,
):
    return json.dumps(
        {
            "model": "jev-1.13.0",
            "answers": {
                "attack_type": {
                    "type": "choice",
                    "choice": attack,
                    "confidence": attack_confidence,
                    "probabilities": {
                        attack: attack_probability,
                    },
                },
                "mission_impact": {
                    "type": "choice",
                    "choice": impact,
                    "confidence": impact_confidence,
                    "probabilities": {impact: impact_probability},
                },
                "needs_human_review": {"type": "noul", "noul": review},
            },
        }
    ).encode("utf-8")


def valid_response():
    return response_for()


def test_disabled_advisor_is_a_noop_without_calling_the_network():
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=False, api_key="secret"), transport=transport
    )

    result = advisor.evaluate(context())

    assert result.status == JevAssessmentStatus.DISABLED
    assert result.score == 0.0
    assert not transport.calls


def test_verified_context_maps_typed_answers_and_redacts_summary():
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret", cache_ttl_sec=10.0),
        transport=transport,
        clock=lambda: 100.0,
    )

    result = advisor.evaluate(context(summary="token=secret-value signature=raw-secret"))

    assert result.status == JevAssessmentStatus.OK
    assert result.label == "unsafe_command"
    assert result.mission_impact == "critical"
    assert result.needs_human_review is True
    assert result.score == 1.0
    assert result.confidence == 0.9
    audit = result.audit_payload()
    assert "secret" not in json.dumps(audit).lower()
    assert "body" not in audit
    request = transport.calls[0]["body"].decode("utf-8")
    assert "secret-value" not in request
    assert "raw-secret" not in request
    assert '"model":"jev-latest"' in request
    assert '"questions"' in request


def test_category_probabilities_are_evidence_not_risk_severity():
    high_severity = FakeTransport(
        response=response_for(
            attack="unsafe_command",
            attack_confidence=0.01,
            attack_probability=0.01,
            impact="low",
            impact_confidence=0.01,
            impact_probability=0.01,
            review=0.0,
        )
    )
    high_severity_result = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=high_severity
    ).evaluate(context())

    low_severity = FakeTransport(
        response=response_for(
            attack="benign",
            attack_confidence=0.99,
            attack_probability=0.99,
            impact="low",
            impact_confidence=0.99,
            impact_probability=0.99,
            review=0.0,
        )
    )
    low_severity_result = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=low_severity
    ).evaluate(context())

    assert high_severity_result.score == 1.0
    assert low_severity_result.score == 0.0
    assert high_severity_result.score > low_severity_result.score


def test_risk_score_is_monotonic_for_attack_impact_and_review_signals():
    def evaluate(**kwargs):
        transport = FakeTransport(response=response_for(**kwargs))
        return JevSemanticAdvisor(
            JevAdvisorConfig(enabled=True, api_key="secret"), transport=transport
        ).evaluate(context())

    benign = evaluate(attack="benign", impact="low", review=0.0, attack_probability=0.01, impact_probability=0.01)
    replay = evaluate(attack="replay", impact="low", review=0.0, attack_probability=0.01, impact_probability=0.01)
    unsafe = evaluate(
        attack="unsafe_command", impact="low", review=0.0,
        attack_probability=0.01, impact_probability=0.01,
    )
    medium = evaluate(attack="benign", impact="medium", review=0.0, attack_probability=0.01, impact_probability=0.01)
    critical = evaluate(attack="benign", impact="critical", review=0.0, attack_probability=0.01, impact_probability=0.01)
    review = evaluate(attack="benign", impact="low", review=1.0, attack_probability=0.01, impact_probability=0.01)

    assert benign.score < replay.score < unsafe.score
    assert benign.score < medium.score < critical.score
    assert review.needs_human_review is True
    assert review.score > benign.score


def test_probability_and_confidence_evidence_raise_confidence_without_raising_score():
    high_evidence = FakeTransport(
        response=response_for(
            attack="replay",
            attack_confidence=0.95,
            attack_probability=0.95,
            impact="medium",
            impact_confidence=0.95,
            impact_probability=0.95,
            review=0.0,
        )
    )
    low_evidence = FakeTransport(
        response=response_for(
            attack="replay",
            attack_confidence=0.20,
            attack_probability=0.20,
            impact="medium",
            impact_confidence=0.20,
            impact_probability=0.20,
            review=0.0,
        )
    )

    high = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=high_evidence
    ).evaluate(context())
    low = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=low_evidence
    ).evaluate(context())

    assert high.score == low.score
    assert high.confidence > low.confidence
    assert high.confidence == 0.95
    assert low.confidence == 0.2


def test_rejected_source_is_never_sent_to_jev():
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=transport
    )

    result = advisor.evaluate(context(source_verified=False))

    assert result.status == JevAssessmentStatus.SKIPPED_UNVERIFIED
    assert not transport.calls


def test_non_boolean_source_is_never_sent_to_jev():
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=transport
    )

    result = advisor.evaluate(context(source_verified="false"))

    assert result.status == JevAssessmentStatus.SKIPPED_UNVERIFIED
    assert not transport.calls


def test_timeout_falls_back_to_unavailable_advice():
    transport = FakeTransport(error=TimeoutError("timed out"))
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=transport
    )

    result = advisor.evaluate(context())

    assert result.status == JevAssessmentStatus.UNAVAILABLE
    assert result.score == 0.0
    assert "timed out" in result.reason


def test_unexpected_transport_failure_is_fail_safe():
    transport = FakeTransport(error=RuntimeError("provider crashed"))
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=transport
    )

    result = advisor.evaluate(context())

    assert result.status == JevAssessmentStatus.UNAVAILABLE
    assert "provider crashed" in result.reason


def test_malformed_response_is_invalid_and_unknown_labels_are_bounded():
    response = json.dumps(
        {
            "answers": {
                "attack_type": {
                    "type": "choice",
                    "choice": "novel_label",
                    "confidence": 9.0,
                    "probabilities": {"novel_label": 4.0},
                },
                "mission_impact": {"type": "choice", "choice": "unknown", "probabilities": {}},
                "needs_human_review": {"type": "noul", "noul": -3.0},
            }
        }
    ).encode("utf-8")
    transport = FakeTransport(response=response)
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=transport
    )

    result = advisor.evaluate(context())

    assert result.status == JevAssessmentStatus.OK
    assert result.label == "UNKNOWN"
    assert result.mission_impact == "unknown"
    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert result.needs_human_review is False

    invalid_transport = FakeTransport(response=b"{}")
    invalid_advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=invalid_transport
    )
    assert invalid_advisor.evaluate(context()).status == JevAssessmentStatus.INVALID

    wrong_type = json.loads(valid_response())
    wrong_type["answers"]["needs_human_review"]["type"] = "choice"
    wrong_transport = FakeTransport(response=json.dumps(wrong_type).encode("utf-8"))
    wrong_advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret"), transport=wrong_transport
    )
    assert wrong_advisor.evaluate(context()).status == JevAssessmentStatus.INVALID


def test_successful_answers_are_cached_until_context_changes_or_expiry():
    now = [100.0]
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret", cache_ttl_sec=5.0),
        transport=transport,
        clock=lambda: now[0],
    )

    first = advisor.evaluate(context(sequence=1))
    cached = advisor.evaluate(context(sequence=1))
    changed = advisor.evaluate(context(sequence=2))
    now[0] = 106.0
    expired = advisor.evaluate(context(sequence=2))

    assert first.status == JevAssessmentStatus.OK
    assert cached.status == JevAssessmentStatus.CACHED
    assert changed.status == JevAssessmentStatus.OK
    assert expired.status == JevAssessmentStatus.OK
    assert len(transport.calls) == 3


def test_invalid_advisor_clock_falls_back_to_finite_time():
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret", cache_ttl_sec=5.0),
        transport=transport,
        clock=lambda: float("nan"),
    )

    result = advisor.evaluate(context())

    assert result.status == JevAssessmentStatus.OK
    assert result.observed_at == 0.0
    assert result.expires_at == 5.0
    assert transport.calls


def test_advisor_clock_rollback_cannot_shorten_or_rewind_cache_time():
    now = iter((10.0, *([5.0] * 8)))
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret", cache_ttl_sec=5.0),
        transport=transport,
        clock=lambda: next(now),
    )

    first = advisor.evaluate(context(sequence=1))
    second = advisor.evaluate(context(sequence=2))

    assert first.observed_at == 10.0
    assert second.observed_at == 10.0
    assert second.expires_at == 15.0
    assert len(transport.calls) == 2


def test_delayed_advisor_cache_lookup_cannot_reuse_expired_result(monkeypatch):
    now = [100.0]
    transport = FakeTransport(response=valid_response())
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="secret", cache_ttl_sec=5.0),
        transport=transport,
        clock=lambda: now[0],
    )
    cached_context = context(sequence=1, summary="advisor cache race")
    assert advisor.evaluate(cached_context).status == JevAssessmentStatus.OK
    paused, release = threading.Event(), threading.Event()
    original_cache_key = advisor._cache_key

    def delayed_cache_key(incident):
        paused.set()
        assert release.wait(5.0), "delayed advisor cache lookup was not released"
        return original_cache_key(incident)

    monkeypatch.setattr(advisor, "_cache_key", delayed_cache_key)
    with ThreadPoolExecutor(max_workers=1) as executor:
        delayed = executor.submit(advisor.evaluate, cached_context)
        try:
            assert paused.wait(2.0), "request did not reach the advisor cache boundary"
            now[0] = 106.0
            advisor._now()
        finally:
            release.set()
        result = delayed.result(timeout=2.0)

    assert result.status == JevAssessmentStatus.OK
    assert len(transport.calls) == 2


def test_config_rejects_remote_http_credentials_and_nonfinite_values():
    with pytest.raises(ValueError, match="HTTPS"):
        JevAdvisorConfig(endpoint="http://remote.example.test")
    with pytest.raises(ValueError, match="credentials"):
        JevAdvisorConfig(endpoint="https://secret@example.test")
    with pytest.raises(ValueError, match="timeout"):
        JevAdvisorConfig(timeout_sec=float("nan"))
    with pytest.raises(ValueError, match="cache TTL"):
        JevAdvisorConfig(cache_ttl_sec=float("inf"))
