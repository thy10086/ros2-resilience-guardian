import json
import threading
import time
from dataclasses import replace

import pytest

from guardian_core.evidence_ledger import Evidence, EvidenceLedger
from guardian_core.jev_advisor import JevAdvisorConfig, JevSemanticAdvisor, SemanticContext
from guardian_core.jev_efficiency import JevEfficientJudge, JevEfficiencyPolicy, JevRoute
from guardian_core.jev_incident_session import (
    JevIncidentSession,
    JevSessionConfig,
    JevSessionRoute,
    JevSessionState,
)


class Clock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


class Transport:
    def __init__(self, error=None):
        self.calls = 0
        self.error = error

    def __call__(self, endpoint, headers, body, timeout):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return json.dumps(
            {
                "model": "jev-session-stub",
                "answers": {
                    "attack_type": {
                        "type": "choice",
                        "choice": "unsafe_command",
                        "confidence": 0.9,
                        "probabilities": {"unsafe_command": 0.9},
                    },
                    "mission_impact": {
                        "type": "choice",
                        "choice": "critical",
                        "confidence": 0.9,
                        "probabilities": {"critical": 0.9},
                    },
                    "needs_human_review": {"type": "noul", "noul": 1.0},
                },
            }
        ).encode()


class BlockingTransport(Transport):
    def __init__(self):
        super().__init__()
        self.first_started = threading.Event()
        self.release_first = threading.Event()
        self._calls_lock = threading.Lock()

    def __call__(self, endpoint, headers, body, timeout):
        with self._calls_lock:
            self.calls += 1
            call_number = self.calls
        if call_number == 1:
            self.first_started.set()
            self.release_first.wait(timeout=2.0)
        return json.dumps(
            {
                "model": "jev-session-stub",
                "answers": {
                    "attack_type": {
                        "type": "choice",
                        "choice": "unsafe_command",
                        "confidence": 0.9,
                        "probabilities": {"unsafe_command": 0.9},
                    },
                    "mission_impact": {
                        "type": "choice",
                        "choice": "critical",
                        "confidence": 0.9,
                        "probabilities": {"critical": 0.9},
                    },
                    "needs_human_review": {"type": "noul", "noul": 1.0},
                },
            }
        ).encode()


class ConcurrencyCheckingLedger(EvidenceLedger):
    def __init__(self):
        super().__init__()
        self._append_lock = threading.Lock()
        self._active_appends = 0
        self.concurrent_append = False

    def append(self, evidence):
        with self._append_lock:
            self._active_appends += 1
            if self._active_appends > 1:
                self.concurrent_append = True
        time.sleep(0.05)
        try:
            return super().append(evidence)
        finally:
            with self._append_lock:
                self._active_appends -= 1


def context(
    event_id="event-1",
    sequence=1,
    graph_risk=0.6,
    mission_criticality=0.6,
    event_confidence=0.8,
    source_verified=True,
    temporal_codes=("REPLAY",),
    safety_state="NORMAL",
    summary="verified command anomaly",
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


def parent_ledger(*, hard_stop=False):
    ledger = EvidenceLedger()
    ledger.append(Evidence(
        evidence_id="event-proof",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=1.0,
        severity=1.0 if hard_stop else 0.6,
        policy_version="p1",
        verified=True,
        hard_stop=hard_stop,
    ))
    return ledger


def make_session(clock, transport, ledger=None, **config_changes):
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline", cache_ttl_sec=30.0),
        transport=transport,
        clock=lambda: 100.0,
    )
    judge = JevEfficientJudge(
        advisor,
        policy=JevEfficiencyPolicy(max_remote_calls=20, cache_ttl_sec=30.0),
        clock=clock,
    )
    return JevIncidentSession(
        judge,
        ledger or parent_ledger(),
        config=JevSessionConfig(**config_changes),
        clock=clock,
    )


def test_session_gates_repeated_queries_and_requeries_on_risk_change():
    clock = Clock()
    transport = Transport()
    session = make_session(clock, transport, min_query_interval_sec=1.0)

    first = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-a")
    clock.now = 0.2
    reused = session.observe(
        context(event_id="event-2", sequence=2),
        parent_evidence_id="event-proof",
        incident_key="incident-a",
    )
    clock.now = 2.0
    changed = session.observe(
        context(event_id="event-3", sequence=3, graph_risk=0.8),
        parent_evidence_id="event-proof",
        incident_key="incident-a",
    )

    assert first.route == JevSessionRoute.QUERIED
    assert reused.route == JevSessionRoute.SESSION_REUSE
    assert changed.route == JevSessionRoute.QUERIED
    assert changed.state == JevSessionState.REVIEW_REQUIRED
    assert transport.calls == 2


def test_review_state_needs_stable_window_before_exit():
    clock = Clock()
    session = make_session(clock, Transport(), stable_window_sec=2.0, min_query_interval_sec=0.0)

    entered = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-b")
    clock.now = 1.0
    still_review = session.observe(
        context(event_id="event-2", sequence=2, graph_risk=0.1, mission_criticality=0.1,
                event_confidence=0.95, temporal_codes=(), safety_state="NORMAL"),
        parent_evidence_id="event-proof",
        incident_key="incident-b",
    )
    clock.now = 3.1
    observing = session.observe(
        context(event_id="event-3", sequence=3, graph_risk=0.1, mission_criticality=0.1,
                event_confidence=0.95, temporal_codes=(), safety_state="NORMAL"),
        parent_evidence_id="event-proof",
        incident_key="incident-b",
    )

    assert entered.state == JevSessionState.REVIEW_REQUIRED
    assert still_review.state == JevSessionState.REVIEW_REQUIRED
    assert observing.state == JevSessionState.OBSERVING


def test_jev_advice_is_short_lived_soft_evidence_bound_to_parent():
    clock = Clock()
    ledger = parent_ledger()
    session = make_session(clock, Transport(), ledger=ledger, soft_evidence_ttl_sec=3.0)

    decision = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-c")

    assert decision.ledger_bound is True
    assert decision.ledger_evidence_id is not None
    soft = next(item for item in ledger.active(1.0) if item.source == "jev")
    assert soft.parent_ids == ("event-proof",)
    assert soft.policy_version == "p1"
    assert soft.hard_stop is False
    assert soft.expires_at == 3.0
    assert ledger.verify()


def test_cache_reuse_does_not_refresh_soft_evidence_expiry():
    clock = Clock()
    ledger = parent_ledger()
    session = make_session(clock, Transport(), ledger=ledger, min_query_interval_sec=0.0, soft_evidence_ttl_sec=3.0)

    first = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-d")
    clock.now = 2.0
    cached = session.observe(
        context(event_id="event-2", sequence=2),
        parent_evidence_id="event-proof",
        incident_key="incident-d",
    )

    assert first.ledger_evidence_id is not None
    assert cached.route == JevSessionRoute.QUERIED
    assert cached.ledger_bound is False
    assert len(ledger.export()) == 2


def test_invalid_ledger_blocks_soft_advice_and_preserves_containment():
    clock = Clock()
    ledger = parent_ledger()
    ledger._records[0] = Evidence(
        evidence_id="event-proof",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=0.0,
        severity=0.6,
        policy_version="p1",
        verified=True,
    )
    session = make_session(clock, Transport(), ledger=ledger)

    decision = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-e")

    assert decision.state == JevSessionState.CONTAINING
    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.ledger_bound is False


def test_provider_failure_does_not_append_soft_evidence():
    clock = Clock()
    ledger = parent_ledger()
    session = make_session(clock, Transport(error=TimeoutError("offline")), ledger=ledger)

    decision = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-f")

    assert decision.state == JevSessionState.REVIEW_REQUIRED
    assert decision.ledger_bound is False
    assert len(ledger.export()) == 1


def test_tampered_ledger_blocks_even_a_local_fast_path():
    clock = Clock()
    ledger = parent_ledger()
    ledger._records[0] = Evidence(
        evidence_id="event-proof",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=0.0,
        severity=0.6,
        policy_version="p1",
        verified=True,
    )
    transport = Transport()
    session = make_session(clock, transport, ledger=ledger)

    decision = session.observe(
        context(
            graph_risk=0.1,
            mission_criticality=0.1,
            event_confidence=0.95,
            temporal_codes=(),
            safety_state="NORMAL",
        ),
        parent_evidence_id="event-proof",
        incident_key="incident-tampered-local",
    )

    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.state == JevSessionState.CONTAINING
    assert not transport.calls


def test_context_semantic_change_requeries_inside_interval():
    clock = Clock()
    transport = Transport()
    session = make_session(clock, transport, min_query_interval_sec=10.0)

    first = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-context")
    clock.now = 0.1
    changed = session.observe(
        context(event_id="event-2", sequence=2, temporal_codes=("STALE",)),
        parent_evidence_id="event-proof",
        incident_key="incident-context",
    )

    assert first.route == JevSessionRoute.QUERIED
    assert changed.route == JevSessionRoute.QUERIED
    assert transport.calls == 2


def test_same_session_observations_are_serialized_without_lost_updates():
    clock = Clock()
    transport = BlockingTransport()
    session = make_session(clock, transport, min_query_interval_sec=10.0)
    decisions = []

    def observe(event_id):
        decisions.append(
            session.observe(
                context(event_id=event_id, sequence=2),
                parent_evidence_id="event-proof",
                incident_key="incident-concurrent",
            )
        )

    first = threading.Thread(target=observe, args=("event-concurrent-1",))
    second = threading.Thread(target=observe, args=("event-concurrent-2",))
    first.start()
    assert transport.first_started.wait(timeout=1.0)
    second.start()
    time.sleep(0.05)
    transport.release_first.set()
    first.join(timeout=2.0)
    second.join(timeout=2.0)

    assert not first.is_alive() and not second.is_alive()
    assert transport.calls == 1
    assert sorted(decision.observation_count for decision in decisions) == [1, 2]
    assert session._sessions["incident-concurrent"].observation_count == 2


def test_ledger_blocked_sessions_still_respect_max_sessions():
    clock = Clock()
    ledger = parent_ledger()
    ledger._records[0] = Evidence(
        evidence_id="event-proof",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=0.0,
        severity=0.6,
        policy_version="p1",
        verified=True,
    )
    session = make_session(clock, Transport(), ledger=ledger, max_sessions=2)

    for incident_key in ("blocked-a", "blocked-b", "blocked-c"):
        decision = session.observe(context(), parent_evidence_id="event-proof", incident_key=incident_key)
        assert decision.route == JevSessionRoute.LEDGER_BLOCKED

    assert len(session._sessions) == 2


def test_mission_and_confidence_changes_requery_inside_interval():
    clock = Clock()
    transport = Transport()
    session = make_session(clock, transport, min_query_interval_sec=10.0)

    session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-numeric")
    clock.now = 0.1
    changed = session.observe(
        context(event_id="event-2", sequence=2, mission_criticality=0.2),
        parent_evidence_id="event-proof",
        incident_key="incident-numeric",
    )

    assert changed.route == JevSessionRoute.QUERIED
    assert transport.calls == 2

    clock.now = 0.2
    changed_again = session.observe(
        context(event_id="event-3", sequence=3, event_confidence=0.2),
        parent_evidence_id="event-proof",
        incident_key="incident-numeric",
    )

    assert changed_again.route == JevSessionRoute.QUERIED
    assert transport.calls == 3


def test_parent_evidence_change_requeries_and_rebinds_soft_advice():
    clock = Clock()
    ledger = parent_ledger()
    ledger.append(Evidence(
        evidence_id="event-proof-2",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=1.0,
        severity=0.7,
        policy_version="p1",
        verified=True,
    ))
    transport = Transport()
    session = make_session(clock, transport, ledger=ledger, min_query_interval_sec=10.0)

    first = session.observe(context(), parent_evidence_id="event-proof", incident_key="incident-parent")
    clock.now = 0.1
    changed = session.observe(
        context(event_id="event-2", sequence=2),
        parent_evidence_id="event-proof-2",
        incident_key="incident-parent",
    )

    assert first.ledger_evidence_id is not None
    assert changed.route == JevSessionRoute.QUERIED
    assert changed.ledger_evidence_id is not None
    assert changed.ledger_evidence_id != first.ledger_evidence_id
    current = [item for item in ledger.active(0.1) if item.source == "jev"]
    assert len(current) == 1
    assert current[0].parent_ids == ("event-proof-2",)


def test_different_sessions_serialize_ledger_append_without_serializing_judgment():
    clock = Clock()
    ledger = ConcurrencyCheckingLedger()
    ledger.append(Evidence(
        evidence_id="event-proof",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=1.0,
        severity=0.6,
        policy_version="p1",
        verified=True,
    ))
    session = make_session(clock, Transport(), ledger=ledger, min_query_interval_sec=10.0)
    start = threading.Barrier(3)
    decisions = []

    def observe(incident_key, graph_risk):
        start.wait(timeout=1.0)
        decisions.append(
            session.observe(
                context(graph_risk=graph_risk),
                parent_evidence_id="event-proof",
                incident_key=incident_key,
            )
        )

    first = threading.Thread(target=observe, args=("incident-ledger-a", 0.6))
    second = threading.Thread(target=observe, args=("incident-ledger-b", 0.7))
    first.start()
    second.start()
    start.wait(timeout=1.0)
    first.join(timeout=3.0)
    second.join(timeout=3.0)

    assert not first.is_alive() and not second.is_alive()
    assert len(decisions) == 2
    assert ledger.concurrent_append is False
    assert ledger.verify()


def test_session_signature_reuses_bounded_context_representation():
    clock = Clock()
    transport = Transport()
    session = make_session(clock, transport, min_query_interval_sec=10.0)
    shared_prefix = "X" * 64

    first = session.observe(
        context(temporal_codes=(shared_prefix + "first-tail" * 100,), summary="a" * 10000),
        parent_evidence_id="event-proof",
        incident_key="incident-bounded-context",
    )
    clock.now = 0.1
    reused = session.observe(
        context(
            event_id="event-2",
            sequence=2,
            temporal_codes=(shared_prefix + "second-tail" * 100,),
            summary="b" * 10000,
        ),
        parent_evidence_id="event-proof",
        incident_key="incident-bounded-context",
    )

    assert first.route == JevSessionRoute.QUERIED
    assert reused.route == JevSessionRoute.SESSION_REUSE
    assert transport.calls == 1


def test_non_boolean_source_verification_cannot_reuse_verified_session():
    clock = Clock()
    transport = Transport()
    session = make_session(clock, transport, min_query_interval_sec=10.0)

    first = session.observe(
        context(),
        parent_evidence_id="event-proof",
        incident_key="incident-source-type",
    )
    clock.now = 0.1
    invalid = session.observe(
        context(event_id="event-2", sequence=2, source_verified="false"),
        parent_evidence_id="event-proof",
        incident_key="incident-source-type",
    )

    assert first.route == JevSessionRoute.QUERIED
    assert invalid.route == JevSessionRoute.QUERIED
    assert invalid.state == JevSessionState.CONTAINING
    assert invalid.assessment is not None
    assert invalid.assessment.route == JevRoute.SKIPPED_UNVERIFIED
    assert transport.calls == 1


def test_invalid_observation_time_does_not_crash_session_decision():
    clock = Clock(now=5.0)
    session = make_session(clock, Transport())

    decision = session.observe(
        context(),
        parent_evidence_id="event-proof",
        incident_key="incident-invalid-time",
        now="not-a-time",
    )

    assert decision.route == JevSessionRoute.QUERIED
    assert decision.expires_at == 35.0


def test_session_time_cannot_move_backwards_and_extend_ttl():
    clock = Clock(now=0.0)
    session = make_session(clock, Transport(), min_query_interval_sec=10.0)

    first = session.observe(
        context(),
        parent_evidence_id="event-proof",
        incident_key="incident-time-order",
        now=10.0,
    )
    second = session.observe(
        context(event_id="event-2", sequence=2),
        parent_evidence_id="event-proof",
        incident_key="incident-time-order",
        now=5.0,
    )

    assert first.expires_at == 40.0
    assert second.expires_at == 40.0
    assert session._sessions["incident-time-order"].last_seen == 10.0


def append_second_parent(ledger):
    root = Evidence(**ledger.export()[0]["evidence"])
    return ledger.append(replace(root, evidence_id="event-proof-2"))


def test_cached_parent_rebinding_keeps_original_soft_evidence_deadline():
    clock, transport, ledger = Clock(), Transport(), parent_ledger()
    append_second_parent(ledger)
    session = make_session(clock, transport, ledger=ledger, soft_evidence_ttl_sec=3.0)
    first = session.observe(context(), parent_evidence_id="event-proof", incident_key="lease")
    clock.now = 2.0
    rebound = session.observe(context(event_id="next"), parent_evidence_id="event-proof-2", incident_key="lease")

    assert rebound.ledger_bound
    bound = next(item for item in ledger.active(clock.now) if item.source == "jev")
    assert bound.supersedes == first.ledger_evidence_id
    assert bound.parent_ids == ("event-proof-2",)
    assert bound.observed_at == 2.0
    assert bound.expires_at == 3.0
    assert not any(item.source == "jev" for item in ledger.active(3.0))
    assert transport.calls == 1


@pytest.mark.parametrize("at", [3.0, 4.0])
def test_cached_rebinding_cannot_revive_expired_soft_evidence(at):
    clock, transport, ledger = Clock(), Transport(), parent_ledger()
    append_second_parent(ledger)
    session = make_session(clock, transport, ledger=ledger, soft_evidence_ttl_sec=3.0)
    session.observe(context(), parent_evidence_id="event-proof", incident_key="lease")
    before = ledger.anchor()
    clock.now = at
    rebound = session.observe(context(event_id="next"), parent_evidence_id="event-proof-2", incident_key="lease")

    assert not rebound.ledger_bound
    assert rebound.ledger_evidence_id is None
    assert ledger.anchor() == before
    assert not any(item.source == "jev" for item in ledger.active(at))
    assert transport.calls == 1


def test_advisor_cache_hit_after_judge_cache_expiry_cannot_renew_soft_evidence():
    clock, transport, ledger = Clock(), Transport(), parent_ledger()
    session = make_session(clock, transport, ledger=ledger, soft_evidence_ttl_sec=3.0, session_ttl_sec=60.0)
    session.observe(context(), parent_evidence_id="event-proof", incident_key="lease")
    before = ledger.anchor()
    clock.now = 31.0  # judge cache expired; advisor's independent test clock still reads 100
    result = session.observe(context(), parent_evidence_id="event-proof", incident_key="lease")

    assert transport.calls == 1
    assert not result.ledger_bound
    assert ledger.anchor() == before


@pytest.mark.parametrize("problem", ["missing", "expired", "future", "unverified", "policy", "superseded", "ancestor_expired"])
def test_inactive_parent_blocks_before_query_even_for_local_safe_context(problem):
    ledger = EvidenceLedger()
    root = Evidence("event-proof", "verifier", "verified_event", "nav", 0.0, 100.0, 1.0, 0.6, "p1", verified=True)
    if problem == "expired":
        root = replace(root, expires_at=1.0)
    elif problem == "future":
        root = replace(root, observed_at=5.0)
    elif problem == "unverified":
        root = replace(root, verified=False)
    elif problem == "policy":
        root = replace(root, policy_version="other")
    elif problem == "ancestor_expired":
        ledger.append(replace(root, evidence_id="ancestor", expires_at=1.0))
        root = replace(root, parent_ids=("ancestor",))
    if problem != "missing":
        ledger.append(root)
    if problem == "superseded":
        ledger.append(replace(root, evidence_id="replacement", supersedes="event-proof"))
    clock, transport = Clock(now=2.0), Transport()
    session = make_session(clock, transport, ledger=ledger)
    before = ledger.anchor()
    decision = session.observe(
        context(graph_risk=0.1, mission_criticality=0.1, event_confidence=0.95, temporal_codes=()),
        parent_evidence_id="event-proof", incident_key="parent-gate",
    )
    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.state == JevSessionState.CONTAINING
    assert decision.assessment is None
    assert not decision.queried and not decision.ledger_bound
    assert not transport.calls
    assert ledger.anchor() == before


def test_parent_expiry_invalidates_session_reuse_inside_query_interval():
    clock, transport = Clock(), Transport()
    ledger = EvidenceLedger()
    ledger.append(Evidence("event-proof", "verifier", "verified_event", "nav", 0.0, 1.0, 1.0, 0.6, "p1", verified=True))
    session = make_session(clock, transport, ledger=ledger, min_query_interval_sec=10.0)
    session.observe(context(), parent_evidence_id="event-proof", incident_key="parent-gate")
    clock.now = 1.0
    decision = session.observe(context(event_id="next"), parent_evidence_id="event-proof", incident_key="parent-gate")
    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.state == JevSessionState.CONTAINING
    assert decision.assessment is None
    assert transport.calls == 1


def test_parent_replaced_during_provider_call_blocks_soft_append():
    clock, transport, ledger = Clock(), Transport(), parent_ledger()
    root = Evidence(**ledger.export()[0]["evidence"])

    def replacing_transport(*args):
        ledger.append(replace(root, evidence_id="replacement", supersedes="event-proof"))
        return transport(*args)

    session = make_session(clock, replacing_transport, ledger=ledger)
    decision = session.observe(context(), parent_evidence_id="event-proof", incident_key="parent-race")
    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.state == JevSessionState.CONTAINING
    assert not decision.ledger_bound
    assert len(ledger.export()) == 2
    assert ledger.verify()


def test_fresh_provider_result_after_expiry_can_create_new_soft_evidence():
    clock, transport, ledger = Clock(), Transport(), parent_ledger()
    session = make_session(clock, transport, ledger=ledger, soft_evidence_ttl_sec=3.0)
    session.observe(context(), parent_evidence_id="event-proof", incident_key="lease")
    clock.now = 4.0
    fresh = session.observe(context(graph_risk=0.7), parent_evidence_id="event-proof", incident_key="lease")
    assert fresh.ledger_bound
    assert transport.calls == 2
    assert next(item for item in ledger.active(4.0) if item.source == "jev").expires_at == 7.0


def test_new_session_retains_review_requirement_when_cached_advice_conflicts():
    transport = Transport()

    def benign_transport(*args):
        payload = json.loads(transport(*args))
        payload["answers"]["attack_type"].update(choice="benign", probabilities={"benign": 0.1})
        payload["answers"]["mission_impact"].update(choice="low", probabilities={"low": 0.1})
        payload["answers"]["needs_human_review"]["noul"] = 0.0
        return json.dumps(payload).encode()

    session = make_session(Clock(), benign_transport)
    incident = context(graph_risk=0.55, mission_criticality=0.1, temporal_codes=())
    first = session.observe(incident, parent_evidence_id="event-proof", incident_key="conflict-owner")
    cached = session.observe(replace(incident, event_id="next"), parent_evidence_id="event-proof", incident_key="conflict-cached")

    assert first.state == JevSessionState.REVIEW_REQUIRED
    assert cached.assessment.route == JevRoute.CACHE
    assert cached.state == JevSessionState.REVIEW_REQUIRED
    assert cached.assessment.disagreement
    assert not cached.ledger_bound
    assert transport.calls == 1


@pytest.mark.parametrize("delay", [1.0, 1.5])
@pytest.mark.parametrize("provider_fails", [False, True])
@pytest.mark.parametrize("explicit_time", [False, True])
def test_parent_expiring_during_judgment_blocks_at_completion(delay, provider_fails, explicit_time):
    # Explicit replay time need not share the clock's origin.
    origin = 10.0 if explicit_time else 0.0
    clock = Clock(now=1000.0 if explicit_time else origin)
    transport = Transport(error=TimeoutError("offline timeout") if provider_fails else None)
    ledger = EvidenceLedger()
    ledger.append(Evidence("event-proof", "verifier", "verified_event", "nav", origin, origin + 1.0, 1.0, 0.6, "p1", verified=True))
    before = ledger.anchor()

    def delayed_transport(*args):
        clock.now += delay
        return transport(*args)

    session = make_session(clock, delayed_transport, ledger=ledger)
    decision = session.observe(context(), parent_evidence_id="event-proof", incident_key="delayed-parent", now=origin if explicit_time else None)

    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.state == JevSessionState.CONTAINING
    assert decision.queried and transport.calls == 1
    assert decision.assessment is None
    assert not decision.ledger_bound and decision.ledger_evidence_id is None
    assert decision.expires_at == origin + delay + session.config.session_ttl_sec
    assert ledger.anchor() == before


def test_ancestor_expiring_during_judgment_blocks_append():
    clock, transport = Clock(), Transport()
    ledger = EvidenceLedger()
    ancestor = Evidence("ancestor", "verifier", "verified_event", "nav", 0.0, 1.0, 1.0, 0.6, "p1", verified=True)
    ledger.append(ancestor)
    ledger.append(replace(ancestor, evidence_id="event-proof", expires_at=100.0, parent_ids=("ancestor",)))
    before = ledger.anchor()

    def delayed_transport(*args):
        clock.now = 1.0
        return transport(*args)

    session = make_session(clock, delayed_transport, ledger=ledger)
    decision = session.observe(context(), parent_evidence_id="event-proof")
    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.state == JevSessionState.CONTAINING
    assert decision.assessment is None
    assert ledger.anchor() == before


@pytest.mark.parametrize("problem", ["replacement", "tamper"])
def test_failed_provider_still_rechecks_parent_integrity(problem):
    clock, ledger = Clock(), parent_ledger()
    transport = Transport(error=TimeoutError("offline timeout"))
    root = Evidence(**ledger.export()[0]["evidence"])

    def invalidating_transport(*args):
        if problem == "replacement":
            ledger.append(replace(root, evidence_id="replacement", supersedes="event-proof"))
        else:
            ledger._records[0] = replace(root, confidence=0.5)
        return transport(*args)

    session = make_session(clock, invalidating_transport, ledger=ledger)
    decision = session.observe(context(), parent_evidence_id="event-proof")
    assert transport.calls == 1
    assert decision.route == JevSessionRoute.LEDGER_BLOCKED
    assert decision.state == JevSessionState.CONTAINING
    assert decision.assessment is None
    assert not decision.ledger_bound
    assert not any(item["evidence"]["source"] == "jev" for item in ledger.export())


@pytest.mark.parametrize("delay", [3.0, 4.0])
def test_provider_wait_cannot_restart_an_exhausted_soft_evidence_lifetime(delay):
    clock, transport, ledger = Clock(), Transport(), parent_ledger()
    before = ledger.anchor()

    def delayed_transport(*args):
        clock.now += delay
        return transport(*args)

    session = make_session(clock, delayed_transport, ledger=ledger, soft_evidence_ttl_sec=3.0)
    decision = session.observe(context(), parent_evidence_id="event-proof")
    assert decision.route == JevSessionRoute.QUERIED
    assert not decision.ledger_bound and decision.ledger_evidence_id is None
    assert ledger.anchor() == before


@pytest.mark.parametrize("explicit_time", [False, True])
def test_valid_delayed_advice_consumes_ttl_without_mixing_clock_origins(explicit_time):
    origin = 10.0 if explicit_time else 0.0
    clock = Clock(now=1000.0 if explicit_time else origin)
    transport, ledger = Transport(), parent_ledger()

    def delayed_transport(*args):
        clock.now += 2.0
        return transport(*args)

    session = make_session(clock, delayed_transport, ledger=ledger, soft_evidence_ttl_sec=3.0)
    decision = session.observe(context(), parent_evidence_id="event-proof", now=origin if explicit_time else None)
    assert decision.ledger_bound
    soft = next(item for item in ledger.active(origin + 2.0) if item.source == "jev")
    assert soft.observed_at == origin + 2.0
    assert soft.expires_at == origin + 3.0
    assert ledger.verify()
