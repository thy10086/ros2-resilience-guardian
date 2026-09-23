import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

import guardian_core.jev_efficiency as efficiency
from guardian_core.jev_advisor import JevAssessment, JevAssessmentStatus, SemanticContext
from guardian_core.jev_efficiency import (
    JevEfficientJudge,
    JevEfficiencyPolicy,
    JevRoute,
)


def context(
    *,
    event_id="event-1",
    sequence=1,
    graph_risk=0.6,
    mission_criticality=0.6,
    event_confidence=0.8,
    temporal_codes=("REPLAY",),
    safety_state="CONTAINING",
    summary="ambiguous command anomaly",
    source_verified=True,
):
    return SemanticContext(
        event_id=event_id,
        component="nav",
        attack_type="UNSAFE_COMMAND",
        event_confidence=event_confidence,
        source_verified=source_verified,
        temporal_codes=temporal_codes,
        graph_risk=graph_risk,
        mission_criticality=mission_criticality,
        active_components=("nav", "base"),
        safety_state=safety_state,
        sequence=sequence,
        summary=summary,
    )


def response(*, label="unsafe_command", impact="critical", review=1.0):
    return json.dumps(
        {
            "model": "jev-test",
            "answers": {
                "attack_type": {
                    "type": "choice",
                    "choice": label,
                    "confidence": 0.9,
                    "probabilities": {label: 0.9},
                },
                "mission_impact": {
                    "type": "choice",
                    "choice": impact,
                    "confidence": 0.9,
                    "probabilities": {impact: 0.9},
                },
                "needs_human_review": {"type": "noul", "noul": review},
            },
        }
    ).encode()


class Transport:
    def __init__(self, payload=None):
        self.payload = payload or response()
        self.calls = []

    def __call__(self, endpoint, headers, body, timeout):
        self.calls.append((endpoint, headers, body, timeout))
        return self.payload


def make_judge(transport, **policy_changes):
    clock = policy_changes.pop("clock", time.time)
    policy = JevEfficiencyPolicy(**policy_changes)
    from guardian_core.jev_advisor import JevAdvisorConfig, JevSemanticAdvisor

    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline", cache_ttl_sec=30.0),
        transport=transport,
        clock=time.time,
    )
    return JevEfficientJudge(advisor, policy=policy, clock=clock)


def test_low_risk_verified_event_uses_local_fast_path_without_remote_call():
    transport = Transport()
    judge = make_judge(transport)

    result = judge.evaluate(
        context(
            graph_risk=0.1,
            mission_criticality=0.1,
            event_confidence=0.95,
            temporal_codes=(),
            safety_state="NORMAL",
        )
    )

    assert result.route == JevRoute.LOCAL_SAFE
    assert result.remote_called is False
    assert not transport.calls


def test_invalid_efficiency_clock_is_fail_safe_and_metrics_stay_finite():
    transport = Transport()
    judge = make_judge(transport, clock=lambda: float("nan"))

    result = judge.evaluate(
        context(
            graph_risk=0.1,
            mission_criticality=0.1,
            event_confidence=0.95,
            temporal_codes=(),
            safety_state="NORMAL",
        )
    )

    assert result.route == JevRoute.LOCAL_SAFE
    assert math.isfinite(result.latency_ms)
    metrics = judge.metrics()
    assert math.isfinite(metrics.p50_latency_ms)
    assert math.isfinite(metrics.p95_latency_ms)


def test_efficiency_clock_rollback_does_not_create_negative_latency_or_reset_cache_early():
    now = iter((10.0, *([5.0] * 12)))
    transport = Transport()
    judge = make_judge(transport, clock=lambda: next(now))

    first = judge.evaluate(context())
    second = judge.evaluate(context(event_id="event-2", sequence=2))

    assert first.route == JevRoute.REMOTE
    assert second.route == JevRoute.CACHE
    assert first.latency_ms >= 0.0
    assert second.latency_ms >= 0.0
    assert len(transport.calls) == 1


def test_judge_cache_ttl_cannot_be_renewed_by_advisor_cached_result():
    from guardian_core.jev_advisor import JevAdvisorConfig, JevSemanticAdvisor

    advisor_clock = [100.0]
    judge_clock = [0.0]
    transport = Transport()
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline", cache_ttl_sec=100.0),
        transport=transport,
        clock=lambda: advisor_clock[0],
    )

    class CountingAdvisor:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.config = wrapped.config
            self.calls = 0

        def evaluate(self, incident):
            self.calls += 1
            return self.wrapped.evaluate(incident)

        def clear_cache(self):
            self.wrapped.clear_cache()

    counted = CountingAdvisor(advisor)
    judge = JevEfficientJudge(
        counted,
        policy=JevEfficiencyPolicy(cache_ttl_sec=5.0),
        clock=lambda: judge_clock[0],
    )

    first = judge.evaluate(context())
    judge_clock[0] = 6.0
    advisor_cached = judge.evaluate(context())
    judge_clock[0] = 10.0
    must_recheck = judge.evaluate(context())

    assert first.route == JevRoute.REMOTE
    assert advisor_cached.route == JevRoute.REMOTE
    assert advisor_cached.assessment is not None
    assert advisor_cached.assessment.status.value == "CACHED"
    assert must_recheck.route == JevRoute.REMOTE
    assert must_recheck.assessment is not None
    assert must_recheck.assessment.status.value == "CACHED"
    assert counted.calls == 3
    assert len(transport.calls) == 1


def test_critical_event_is_enforced_locally_without_waiting_for_jev():
    transport = Transport()
    judge = make_judge(transport)

    result = judge.evaluate(context(graph_risk=0.95, safety_state="SAFE_STOP"))

    assert result.route == JevRoute.LOCAL_ENFORCED
    assert result.local_score >= 0.95
    assert result.remote_called is False
    assert not transport.calls


def test_stable_fingerprint_reuses_jev_result_across_event_ids_and_sequences():
    transport = Transport()
    judge = make_judge(transport)

    first = judge.evaluate(context(event_id="event-1", sequence=1))
    second = judge.evaluate(context(event_id="event-2", sequence=2))

    assert first.route == JevRoute.REMOTE
    assert second.route == JevRoute.CACHE
    assert first.fingerprint == second.fingerprint
    assert second.assessment is not None
    assert second.assessment.event_id == "event-2"
    assert len(transport.calls) == 1


def test_concurrent_identical_requests_use_single_flight():
    started = threading.Event()
    release = threading.Event()
    calls = []

    def transport(endpoint, headers, body, timeout):
        calls.append(body)
        started.set()
        assert release.wait(2.0)
        return response()

    judge = make_judge(transport)
    results = []
    first = threading.Thread(target=lambda: results.append(judge.evaluate(context())))
    second = threading.Thread(target=lambda: results.append(judge.evaluate(context(event_id="event-2", sequence=2))))
    first.start()
    assert started.wait(1.0)
    second.start()
    deadline = time.time() + 1.0
    while time.time() < deadline:
        with judge._lock:  # The test waits for the request to be coalescible.
            if judge._inflight:
                break
        time.sleep(0.001)
    release.set()
    first.join(2.0)
    second.join(2.0)

    assert len(calls) == 1
    assert len(results) == 2
    assert {item.route for item in results} == {JevRoute.REMOTE, JevRoute.COALESCED}
    assert judge.metrics().coalesced_requests == 1


def test_call_budget_returns_local_fallback_after_budget_is_exhausted():
    transport = Transport()
    judge = make_judge(transport, max_remote_calls=1, budget_window_sec=60.0)

    first = judge.evaluate(context(summary="first ambiguity"))
    second = judge.evaluate(context(summary="second ambiguity", event_id="event-2"))

    assert first.route == JevRoute.REMOTE
    assert second.route == JevRoute.BUDGET_EXHAUSTED
    assert second.remote_called is False
    assert len(transport.calls) == 1
    assert judge.metrics().budget_exhausted == 1


def test_remote_disagreement_is_reported_without_changing_local_enforcement():
    transport = Transport(response(label="benign", impact="low", review=0.0))
    judge = make_judge(transport)

    result = judge.evaluate(context())

    assert result.route == JevRoute.DISAGREEMENT
    assert result.disagreement is True
    assert result.local_score > 0.0
    assert result.assessment is not None
    assert result.assessment.label == "benign"


def test_invalid_numeric_context_fails_closed_without_remote_call():
    transport = Transport()
    judge = make_judge(transport)

    result = judge.evaluate(
        context(
            graph_risk=math.nan,
            mission_criticality=0.1,
            event_confidence=0.99,
            temporal_codes=(),
            safety_state="NORMAL",
        )
    )

    assert result.route == JevRoute.LOCAL_ENFORCED
    assert result.local_score == 1.0
    assert not transport.calls


def test_non_boolean_source_verification_is_never_sent_to_jev():
    transport = Transport()
    judge = make_judge(transport)

    result = judge.evaluate(context(source_verified="false"))

    assert result.route == JevRoute.SKIPPED_UNVERIFIED
    assert not transport.calls


def test_unexpected_provider_exception_is_counted_as_failure():
    class RaisingAdvisor:
        config = SimpleNamespace(model="jev-test")

        def evaluate(self, _context):
            raise RuntimeError("provider crashed")

        def clear_cache(self):
            return None

    judge = JevEfficientJudge(RaisingAdvisor())

    result = judge.evaluate(context())

    assert result.route == JevRoute.UNAVAILABLE
    assert judge.metrics().provider_failures == 1


class BlockingAdvisor:
    config = SimpleNamespace(model="jev-test")

    def __init__(self, assessment):
        self.assessment = assessment
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def evaluate(self, incident):
        self.calls += 1
        self.started.set()
        if not self.release.wait(5.0):
            raise TimeoutError("test provider was not released")
        if self.assessment is None:
            raise RuntimeError("offline adapter failure")
        return self.assessment


def shared_pair(judge, advisor, monkeypatch):
    """Release the owner only after a follower actually waits on its flight."""
    waiting = threading.Event()

    class ObservedCompletion:
        def __init__(self):
            self.done = threading.Event()

        def wait(self, timeout):
            waiting.set()
            return self.done.wait(timeout)

        def set(self):
            self.done.set()

    monkeypatch.setattr(efficiency, "Event", ObservedCompletion)
    with ThreadPoolExecutor(max_workers=2) as executor:
        owner = executor.submit(judge.evaluate, context())
        try:
            assert advisor.started.wait(2.0)
            follower = executor.submit(judge.evaluate, context(event_id="event-2", sequence=2))
            assert waiting.wait(2.0)
        finally:
            advisor.release.set()
        return owner.result(timeout=2.0), follower.result(timeout=2.0)


@pytest.mark.parametrize("status", [
    JevAssessmentStatus.UNAVAILABLE, JevAssessmentStatus.INVALID,
    JevAssessmentStatus.DISABLED, JevAssessmentStatus.SKIPPED_UNVERIFIED, None,
])
def test_single_flight_preserves_failed_advice_and_counts_one_failure(status, monkeypatch):
    assessment = None if status is None else JevAssessment(
        status=status, event_id="event-1", reason="offline failure or unavailable advice",
    )
    advisor = BlockingAdvisor(assessment)
    judge = JevEfficientJudge(advisor)
    owner, follower = shared_pair(judge, advisor, monkeypatch)

    assert owner.route == follower.route == JevRoute.UNAVAILABLE
    assert follower.coalesced and not follower.remote_called and not follower.cache_hit
    assert follower.event_id == "event-2"
    assert follower.local_score == owner.local_score
    assert not follower.disagreement
    if assessment is None:
        assert follower.assessment is None
    else:
        assert follower.assessment.status == status
        assert follower.assessment.event_id == "event-2"
        assert follower.assessment.reason == assessment.reason
    assert follower.audit_payload()["jev_status"] == (status.value if status else None)
    assert advisor.calls == 1
    metrics = judge.metrics()
    assert metrics.total_requests == 2
    assert metrics.remote_calls == metrics.provider_failures == metrics.coalesced_requests == 1
    # Failure is neither cached nor left as an in-flight request.
    advisor.assessment = JevAssessment(status=JevAssessmentStatus.OK, event_id="event-1")
    assert judge.evaluate(context()).route == JevRoute.REMOTE
    assert advisor.calls == 2


@pytest.mark.parametrize("status", [JevAssessmentStatus.OK, JevAssessmentStatus.CACHED])
@pytest.mark.parametrize("label,disagreement", [("unsafe_command", False), ("benign", True)])
def test_single_flight_success_preserves_disagreement_and_current_event(status, label, disagreement, monkeypatch):
    advisor = BlockingAdvisor(JevAssessment(
        status=status, event_id="event-1", label=label, score=0.1, confidence=0.9,
        observed_at=100.0, expires_at=105.0,
    ))
    judge = JevEfficientJudge(advisor)
    owner, follower = shared_pair(judge, advisor, monkeypatch)

    assert owner.route == (JevRoute.DISAGREEMENT if disagreement else JevRoute.REMOTE)
    assert follower.route == JevRoute.COALESCED
    assert follower.coalesced and not follower.remote_called
    assert follower.disagreement is disagreement
    assert follower.assessment.status == JevAssessmentStatus.CACHED
    assert follower.assessment.event_id == "event-2"
    assert follower.assessment.observed_at == 100.0
    assert follower.assessment.expires_at == 105.0
    assert advisor.calls == 1
    assert judge.metrics().provider_failures == 0
    assert judge.metrics().disagreements == (2 if disagreement else 0)


def test_cache_hit_preserves_conflict_with_deterministic_attack_evidence():
    payload = json.loads(response(label="benign", impact="low", review=0.0))
    for name, label in (("attack_type", "benign"), ("mission_impact", "low")):
        payload["answers"][name]["probabilities"] = {label: 0.1}
    transport = Transport(json.dumps(payload).encode())
    judge = make_judge(transport)

    first = judge.evaluate(context(graph_risk=0.55, mission_criticality=0.1, temporal_codes=(), safety_state="NORMAL"))
    cached = judge.evaluate(context(event_id="event-2", graph_risk=0.55, mission_criticality=0.1, temporal_codes=(), safety_state="NORMAL"))

    assert first.route == JevRoute.DISAGREEMENT
    assert cached.route == JevRoute.CACHE and cached.cache_hit
    assert cached.disagreement and cached.audit_payload()["disagreement"]
    assert cached.assessment.event_id == "event-2"
    assert cached.local_score == first.local_score == 0.55
    assert judge.metrics().disagreements == 2
    assert len(transport.calls) == 1
