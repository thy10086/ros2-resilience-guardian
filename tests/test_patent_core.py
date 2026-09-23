import math
from dataclasses import replace

import pytest

from guardian_core.assurance import AssuranceController
from guardian_core.causal_graph import (
    CausalEdge,
    CausalNode,
    GraphSnapshot,
    compare_graphs,
    trace_risk,
)
from guardian_core.evidence_ledger import Evidence, EvidenceLedger
from guardian_core.predictive_envelope import MotionSample, PredictiveConfig, PredictiveEnvelope
from guardian_core.recovery_protocol import (
    RecoveryConfig,
    RecoveryObservation,
    RecoveryProtocol,
)


def _snapshot(*, weight: float = 0.8) -> GraphSnapshot:
    return GraphSnapshot(
        nodes=(
            CausalNode("nav", "node", "mission", 0.5),
            CausalNode("cmd_vel", "topic", "control", 0.7),
            CausalNode("base", "actuator", "physical", 1.0),
        ),
        edges=(
            CausalEdge("nav", "cmd_vel", weight, "publishes"),
            CausalEdge("cmd_vel", "base", 0.9, "controls"),
        ),
        observed_at=10.0,
    )


def test_causal_trace_returns_path_and_detects_graph_change():
    snapshot = _snapshot()
    trace = trace_risk(snapshot, {"nav": 0.9}, now=10.1, max_age_sec=1.0)

    assert trace.risk_by_node["base"] == pytest.approx(0.648)
    assert trace.paths_by_node["base"] == ("nav", "cmd_vel", "base")
    assert trace.critical_nodes == frozenset({"base"})
    assert trace.snapshot_fingerprint == snapshot.fingerprint
    assert compare_graphs(snapshot, _snapshot(weight=0.5)).changed_edges == ("nav->cmd_vel",)


def test_causal_trace_rejects_stale_or_unknown_seed():
    with pytest.raises(ValueError, match="stale"):
        trace_risk(_snapshot(), {"nav": 0.9}, now=12.0, max_age_sec=1.0)
    with pytest.raises(ValueError, match="unknown seed"):
        trace_risk(_snapshot(), {"unknown": 0.9}, now=10.0, max_age_sec=1.0)


def test_evidence_ledger_proves_lineage_and_detects_tampering():
    ledger = EvidenceLedger()
    root = ledger.append(Evidence(
        evidence_id="e1", source="policy", kind="temporal", node="cmd_vel",
        observed_at=1.0, expires_at=5.0, confidence=0.9, severity=0.6,
        policy_version="p1", verified=True,
    ))
    derived = ledger.append(Evidence(
        evidence_id="e2", source="graph", kind="propagation", node="base",
        observed_at=1.1, expires_at=5.0, confidence=0.8, severity=0.8,
        policy_version="p1", parent_ids=(root.evidence_id,), verified=True,
    ))
    assert ledger.active(2.0) == (root, derived)
    assert ledger.verify()
    anchor = ledger.anchor()
    assert anchor.count == 2 and anchor.head

    ledger._records[1] = Evidence(**{**derived.__dict__, "severity": 0.1})
    assert not ledger.verify()


def test_ledger_blocks_expired_or_unverified_lineage():
    ledger = EvidenceLedger()
    parent = ledger.append(Evidence(
        evidence_id="bad", source="sensor", kind="observation", node="scan",
        observed_at=1.0, expires_at=1.5, confidence=0.8, severity=0.4,
        policy_version="p1", verified=False,
    ))
    with pytest.raises(ValueError, match="parent"):
        ledger.append(Evidence(
            evidence_id="child", source="graph", kind="propagation", node="base",
            observed_at=1.1, expires_at=2.0, confidence=0.8, severity=0.4,
            policy_version="p1", parent_ids=(parent.evidence_id,), verified=True,
        ))


def test_predictive_envelope_accounts_for_latency_and_risk_growth():
    controller = PredictiveEnvelope(PredictiveConfig(
        default_speed_limit=0.35,
        braking_acceleration=0.8,
        control_latency_sec=0.2,
        sensor_latency_sec=0.1,
        prediction_horizon_sec=0.5,
    ))
    calm = controller.evaluate(MotionSample(0.2, 2.0, 0.05, risk_rate=0.0, uncertainty=0.0))
    growing = controller.evaluate(MotionSample(0.2, 2.0, 0.05, risk_rate=0.8, uncertainty=0.0))
    delayed = controller.evaluate(MotionSample(0.2, 2.0, 0.05, risk_rate=0.0, uncertainty=0.0, sensor_fresh=False))

    assert calm.stop_distance > 0.0
    assert 0.0 < growing.speed_limit < calm.speed_limit
    assert growing.state == "CONTAINING"
    assert delayed.state == "SAFE_STOP" and delayed.speed_limit == 0.0


def test_predictive_envelope_fails_safe_on_nonfinite_input():
    result = PredictiveEnvelope().evaluate(MotionSample(math.nan, 2.0, 0.1))
    assert result.state == "SAFE_STOP" and result.speed_limit == 0.0


def _observation(t: float, *, graph: str = "g1", ledger: str = "h1", probe: bool = True, **changes: object) -> RecoveryObservation:
    values = dict(
        now=t,
        no_active_attacks=True,
        graph_fingerprint=graph,
        policy_fingerprint="p1",
        ledger_anchor=ledger,
        commands_cleared=True,
        sensor_fresh=True,
        policy_valid=True,
        probe_success=probe,
        command_epoch=1,
        risk=0.1,
    )
    values.update(changes)
    return RecoveryObservation(**values)


def test_recovery_protocol_requires_probe_then_commit_and_binds_context():
    protocol = RecoveryProtocol(RecoveryConfig(dwell_sec=1.0, stable_window_sec=0.5, proof_ttl_sec=0.5))
    assert protocol.observe(_observation(0.0)).state == "RECOVERY_PROBING"
    assert protocol.observe(_observation(0.6)).state == "RECOVERY_CANDIDATE"
    proof = protocol.commit(_observation(1.1))
    assert proof.graph_fingerprint == "g1"
    assert protocol.authorize_command(proof, _observation(1.2)).state == "RESUMABLE"
    assert protocol.authorize_command(proof, _observation(1.3)).state == "SAFE_STOP"


def test_recovery_protocol_invalidates_old_proof_on_graph_or_attack_change():
    protocol = RecoveryProtocol(RecoveryConfig(dwell_sec=0.0, stable_window_sec=0.0, proof_ttl_sec=2.0))
    protocol.observe(_observation(1.0))
    proof = protocol.commit(_observation(1.1))
    changed = protocol.authorize_command(proof, _observation(1.2, graph="g2"))
    assert changed.state == "SAFE_STOP"
    assert "context" in changed.reason


def test_assurance_explains_hard_stop_and_counterfactual():
    ledger = EvidenceLedger()
    ledger.append(Evidence(
        evidence_id="stop", source="sensor", kind="physical", node="base",
        observed_at=1.0, expires_at=3.0, confidence=1.0, severity=1.0,
        policy_version="p1", verified=True, hard_stop=True,
    ))
    ledger.append(Evidence(
        evidence_id="soft", source="graph", kind="propagation", node="cmd_vel",
        observed_at=1.0, expires_at=3.0, confidence=0.8, severity=0.6,
        policy_version="p1", verified=True,
    ))
    assurance = AssuranceController()
    decision = assurance.assess(ledger, now=1.5)
    counterfactuals = assurance.counterfactuals(ledger, now=1.5)
    assert decision.level == "SAFE_STOP"
    assert "stop" in decision.hard_stop_ids
    assert any(item.evidence_id == "stop" and item.level_without != "SAFE_STOP" for item in counterfactuals)


def _evidence(eid="e1", **changes):
    values = dict(evidence_id=eid, source="policy", kind="temporal", node="nav",
                  observed_at=1.0, expires_at=5.0, confidence=1.0, severity=0.9,
                  policy_version="p1", verified=True)
    values.update(changes)
    return Evidence(**values)


@pytest.mark.parametrize("field", ["verified", "hard_stop"])
@pytest.mark.parametrize("value", ["false", 1, 0, None])
def test_evidence_rejects_non_boolean_trust_flags(field, value):
    with pytest.raises(ValueError, match=field):
        _evidence(**{field: value})


def test_native_boolean_evidence_preserves_active_and_export_semantics():
    ledger = EvidenceLedger()
    unverified = ledger.append(_evidence("unverified", verified=False))
    soft = ledger.append(_evidence("soft", hard_stop=False))
    stop = ledger.append(_evidence("stop", hard_stop=True))
    assert unverified.verified is False
    assert ledger.active(1.5) == (soft, stop)
    assert ledger.verify()
    assert EvidenceLedger.verify_export(ledger.export(), ledger.anchor())


@pytest.mark.parametrize("field", ["verified", "hard_stop"])
def test_rehashed_non_boolean_evidence_fails_live_and_export_validation(field):
    ledger = EvidenceLedger()
    record = ledger.append(_evidence(severity=0.0))
    # Simulate a malformed legacy record with a matching hash, so this tests
    # field semantics independently of ordinary hash-mismatch detection.
    object.__setattr__(record, field, "false")
    ledger._hashes[0] = ledger._hash_entry("GENESIS", record)
    assert not ledger.verify()
    assert not EvidenceLedger.verify_export(ledger.export(), ledger.anchor())
    assert ledger.active(1.5) == ()
    decision = AssuranceController().assess(ledger, now=1.5)
    assert decision.level == "SAFE_STOP"
    assert decision.hard_stop_ids == ("ledger-integrity",)


@pytest.mark.parametrize("field", ["verified", "hard_stop"])
def test_invalid_candidate_cannot_mutate_ledger_or_supersede_evidence(field):
    ledger = EvidenceLedger()
    original = ledger.append(_evidence())
    candidate = _evidence("replacement", supersedes=original.evidence_id)
    object.__setattr__(candidate, field, "false")
    before = ledger.anchor(), ledger.export()
    with pytest.raises(ValueError, match=field):
        ledger.append(candidate)
    assert (ledger.anchor(), ledger.export()) == before
    assert ledger.active(1.5) == (original,)
    assert ledger.verify()


@pytest.mark.parametrize("field", ["verified", "hard_stop"])
def test_malformed_existing_record_cannot_accept_child_or_replacement(field):
    ledger = EvidenceLedger()
    original = ledger.append(_evidence())
    object.__setattr__(original, field, "false")
    previous = "GENESIS"
    for index, record in enumerate(ledger._records):
        previous = ledger._hash_entry(previous, record)
        ledger._hashes[index] = previous
    before = ledger.anchor(), ledger.export()
    with pytest.raises(ValueError, match="parent|trust flags"):
        ledger.append(_evidence("child", parent_ids=(original.evidence_id,)))
    with pytest.raises(ValueError, match="trust flags"):
        ledger.append(_evidence("replacement", supersedes=original.evidence_id))
    assert (ledger.anchor(), ledger.export()) == before


def test_graph_cycles_have_simple_paths_and_order_independent_fingerprint():
    graph = GraphSnapshot(
        (CausalNode("a", "node", "control"), CausalNode("b", "actuator", "physical", 1.0)),
        (CausalEdge("a", "b", 1.0, "controls"), CausalEdge("b", "a", 1.0, "feedback")),
        1.0,
    )
    trace = trace_risk(graph, {"b": 0.5}, now=1.0, max_age_sec=1.0)
    assert all(len(path) == len(set(path)) for path in trace.paths_by_node.values())
    assert replace(graph, edges=tuple(reversed(graph.edges)), observed_at=2.0).fingerprint == graph.fingerprint
    with pytest.raises(ValueError, match="duplicate"):
        replace(graph, edges=graph.edges + (graph.edges[0],))


def test_ledger_anchor_rejects_truncation_and_parent_expiry():
    ledger = EvidenceLedger()
    ledger.append(_evidence(expires_at=2.0))
    ledger.append(_evidence("child", parent_ids=("e1",)))
    assert ledger.active(2.5) == ()
    anchor = ledger.anchor()
    exported = ledger.export()
    assert EvidenceLedger.verify_export(exported, anchor)
    assert not EvidenceLedger.verify_export(exported[:-1], anchor)
    exported[0]["evidence"]["severity"] = 0.0
    assert not EvidenceLedger.verify_export(exported, anchor)


def test_ledger_export_rejects_invalid_parent_and_cross_policy_lineage():
    ledger = EvidenceLedger()
    ledger.append(_evidence())
    ledger.append(_evidence("child", parent_ids=("e1",)))
    exported = ledger.export()
    exported[1]["evidence"]["parent_ids"] = ["missing"]
    assert not EvidenceLedger.verify_export(exported, ledger.anchor())

    ledger = EvidenceLedger()
    ledger.append(_evidence())
    ledger.append(_evidence("child", parent_ids=("e1",)))
    exported = ledger.export()
    exported[1]["evidence"]["policy_version"] = "p2"
    assert not EvidenceLedger.verify_export(exported, ledger.anchor())


def test_unverified_replacement_cannot_clear_stop_or_cross_policy_lineage():
    ledger = EvidenceLedger()
    ledger.append(_evidence(hard_stop=True))
    with pytest.raises(ValueError):
        ledger.append(_evidence("clear", verified=False, severity=0.0, supersedes="e1"))
    with pytest.raises(ValueError):
        ledger.append(_evidence("child", policy_version="p2", parent_ids=("e1",)))
    assert ledger.active(1.5)[0].hard_stop


def test_soft_replacement_cannot_clear_hard_stop():
    ledger = EvidenceLedger()
    ledger.append(_evidence(hard_stop=True))
    with pytest.raises(ValueError, match="hard-stop"):
        ledger.append(_evidence("clear", supersedes="e1", hard_stop=False, severity=0.0))


def test_integrity_failure_cannot_produce_allow():
    ledger = EvidenceLedger()
    ledger.append(_evidence())
    ledger._records[0] = replace(ledger._records[0], severity=0.0)
    assert AssuranceController().assess(ledger, now=1.5).level == "SAFE_STOP"


def test_benign_evidence_cannot_dilute_risk_and_counterfactual_removes_children():
    ledger = EvidenceLedger()
    ledger.append(_evidence(hard_stop=True))
    ledger.append(_evidence("child", kind="propagation", parent_ids=("e1",)))
    assurance = AssuranceController()
    score = assurance.assess(ledger, now=1.5).score
    for i in range(30):
        ledger.append(_evidence(f"benign{i}", severity=0.0))
    assert assurance.assess(ledger, now=1.5).score == score
    cf = next(c for c in assurance.counterfactuals(ledger, now=1.5) if c.evidence_id == "e1")
    assert cf.score_without == 0.0 and cf.level_without == "ALLOW"
    assert ledger.verify()


def test_current_motion_outside_braking_envelope_requests_stop():
    result = PredictiveEnvelope().evaluate(MotionSample(1.0, 0.5, 0.0))
    assert result.stop_distance > 0.5
    assert result.state == "SAFE_STOP" and result.speed_limit == 0.0


def test_low_risk_can_continue_with_reduced_speed():
    decision = PredictiveEnvelope().evaluate(MotionSample(0.1, 2.0, 0.05))
    assert decision.mission_allowed and decision.state == "NORMAL"
    assert 0.0 < decision.speed_limit < 0.35


@pytest.mark.parametrize("field,value", [("risk", -1.0), ("risk", 2.0), ("sensor_fresh", "false")])
def test_invalid_motion_does_not_allow_motion(field, value):
    decision = PredictiveEnvelope().evaluate(replace(MotionSample(0.1, 2.0, 0.0), **{field: value}))
    assert decision.state == "SAFE_STOP"


def _candidate_protocol():
    protocol = RecoveryProtocol(RecoveryConfig(dwell_sec=0.0, stable_window_sec=0.0, proof_ttl_sec=1.0))
    protocol.observe(_observation(1.0))
    return protocol, protocol.commit(_observation(1.1))


def test_forged_or_modified_recovery_proof_cannot_authorize():
    protocol, proof = _candidate_protocol()
    other = RecoveryProtocol(protocol.config)
    assert not other.authorize_command(proof, _observation(1.2)).allowed
    assert not protocol.authorize_command(replace(proof, expires_at=99.0), _observation(1.2)).allowed
    assert not protocol.authorize_command(proof, _observation(1.3)).allowed


def test_recovery_proof_id_is_signed_and_cannot_be_replayed_with_new_id():
    protocol, proof = _candidate_protocol()
    assert not protocol.authorize_command(replace(proof, proof_id="forged"), _observation(1.2)).allowed


def test_intervening_observation_invalidates_proof():
    protocol, proof = _candidate_protocol()
    assert protocol.observe(_observation(1.2)).state == "RECOVERY_CANDIDATE"
    assert not protocol.authorize_command(proof, _observation(1.3)).allowed


def test_latest_failed_observation_revokes_old_proof():
    protocol, proof = _candidate_protocol()
    assert protocol.observe(_observation(1.2, graph="g2")).state == "SAFE_STOP"
    assert not protocol.authorize_command(proof, _observation(1.3)).allowed


def test_recovery_rejects_non_boolean_flags_and_invalid_proof_type():
    with pytest.raises(ValueError, match="boolean"):
        _observation(1.0, sensor_fresh="false")
    protocol, _proof = _candidate_protocol()
    assert not protocol.authorize_command(object(), _observation(1.2)).allowed


@pytest.mark.parametrize("changes", [
    {"risk": 0.95}, {"risk": 0.2}, {"no_active_attacks": False},
    {"sensor_fresh": False}, {"commands_cleared": False}, {"policy_valid": False},
    {"policy_fingerprint": "p2"}, {"ledger": "h2"}, {"command_epoch": 2}, {"probe": False},
])
def test_new_risk_or_context_change_revokes_recovery(changes):
    protocol, proof = _candidate_protocol()
    assert not protocol.authorize_command(proof, _observation(1.2, **changes)).allowed
    assert not protocol.authorize_command(proof, _observation(1.3)).allowed


def test_recovery_requires_observation_continuity_and_later_commit():
    protocol = RecoveryProtocol(RecoveryConfig(max_observation_gap_sec=0.7))
    protocol.observe(_observation(0.0))
    assert protocol.observe(_observation(10.0)).state == "SAFE_STOP"
    with pytest.raises(ValueError):
        protocol.commit(_observation(10.1))
    protocol, proof = _candidate_protocol()
    assert not protocol.authorize_command(proof, _observation(1.1)).allowed


def test_legacy_recovery_decision_export_is_unchanged():
    from guardian_core import RecoveryDecision as exported
    from guardian_core.recovery_gate import RecoveryDecision as legacy
    assert exported is legacy
