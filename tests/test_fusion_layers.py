import math

import pytest

from guardian_core.evidence_fusion import EvidenceBundle, EvidenceFusion
from guardian_core.graph_model import GraphEdge, GraphNode, SecurityGraph
from guardian_core.policy_monitor import TopicPolicy, TemporalPolicyMonitor
from guardian_core.recovery_gate import RecoveryEvidence, RecoveryGate
from guardian_core.safety_envelope import SafetyEnvelopeController


def test_graph_risk_propagates_to_critical_actuator():
    graph = SecurityGraph([
        GraphNode("nav", "node", 0.4),
        GraphNode("cmd_vel", "topic", 0.7),
        GraphNode("base", "actuator", 1.0),
    ], [
        GraphEdge("nav", "cmd_vel", 0.9),
        GraphEdge("cmd_vel", "base", 0.8),
    ])

    assessment = graph.propagate({"nav": 0.9})

    assert assessment.risk_by_node["cmd_vel"] == 0.81
    assert assessment.risk_by_node["base"] == pytest.approx(0.648)
    assert assessment.critical_nodes == frozenset({"base"})


def test_temporal_monitor_rejects_source_stale_and_replay_messages():
    monitor = TemporalPolicyMonitor([
        TopicPolicy("/scan", "lidar", min_period_sec=0.05, max_gap_sec=0.5, max_age_sec=0.2),
    ])

    assert monitor.observe("/scan", "lidar", 1.0, 1, 1.0) == ()
    assert {v.code for v in monitor.observe("/scan", "camera", 1.1, 2, 1.1)} == {"UNTRUSTED_SOURCE"}
    assert {v.code for v in monitor.observe("/scan", "lidar", 1.1, 1, 1.1)} == {"REPLAY"}
    assert {v.code for v in monitor.observe("/scan", "lidar", 1.1, 2, 1.5)} == {"STALE"}
    assert {v.code for v in monitor.observe("/scan", "lidar", math.nan, 3, 1.5)} == {"INVALID_TIMESTAMP"}
    assert {v.code for v in monitor.observe("/scan", "lidar", 1.2, True, 1.5)} == {"INVALID_SEQUENCE"}


def test_evidence_fusion_explains_containment_and_safe_stop():
    fusion = EvidenceFusion()
    contain = fusion.evaluate(EvidenceBundle(
        event_confidence=0.8,
        source_trust=0.9,
        temporal_violation=0.4,
        graph_risk=0.9,
        mission_criticality=0.5,
        physical_inconsistency=0.0,
    ))
    stop = fusion.evaluate(EvidenceBundle(
        event_confidence=0.1,
        source_trust=0.1,
        temporal_violation=1.0,
        graph_risk=1.0,
        mission_criticality=1.0,
        physical_inconsistency=1.0,
    ))

    assert contain.level == "CONTAIN"
    assert contain.score > 0.35
    assert contain.reasons
    assert stop.level == "SAFE_STOP"


def test_fusion_and_envelope_reject_invalid_configuration():
    with pytest.raises(ValueError, match="unknown evidence weights"):
        EvidenceFusion(weights={"graph_risk": 1.0, "attacker": 1.0})
    with pytest.raises(ValueError, match="risk thresholds"):
        SafetyEnvelopeController(contain_risk=0.8, stop_risk=0.5)


def test_safety_envelope_reduces_speed_and_stops_on_stale_sensor():
    controller = SafetyEnvelopeController(default_speed_limit=0.35, braking_acceleration=0.8)
    clear = controller.compute(risk=0.0, free_distance=2.0, sensor_fresh=True)
    risky = controller.compute(risk=0.5, free_distance=2.0, sensor_fresh=True)
    stale = controller.compute(risk=0.1, free_distance=2.0, sensor_fresh=False)

    assert clear.speed_limit == 0.35 and clear.mission_allowed
    assert 0.0 < risky.speed_limit < clear.speed_limit
    assert risky.state == "CONTAINING" and not risky.mission_allowed
    assert stale.speed_limit == 0.0 and stale.state == "SAFE_STOP"


def test_recovery_gate_requires_all_conditions():
    gate = RecoveryGate()
    evidence = RecoveryEvidence(True, True, True, True, True, True)
    assert gate.evaluate(evidence).allowed
    blocked = gate.evaluate(RecoveryEvidence(True, False, True, True, True, True))
    assert not blocked.allowed
    assert "graph_stable" in blocked.missing
