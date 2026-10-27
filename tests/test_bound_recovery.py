"""Safety contracts for the evidence/context-bound AMR recovery loop."""
from dataclasses import replace
import hashlib

import pytest

from guardian_core.recovery_protocol import RecoveryConfig, RecoveryObservation, RecoveryProtocol


def observation(now):
    return RecoveryObservation(now, True, "graph", "policy", "ledger", True, True, True, True, 2, 0.0)


def test_public_checksum_cannot_forge_recovery_signature():
    protocol = RecoveryProtocol(RecoveryConfig(dwell_sec=0, stable_window_sec=0))
    proof = protocol.commit(observation(1.0))
    public = "|".join(map(str, (proof.issuer, proof.graph_fingerprint,
        proof.policy_fingerprint, proof.ledger_anchor, proof.command_epoch,
        proof.risk, proof.issued_at, proof.expires_at, proof.proof_id)))
    forged = replace(proof, signature=hashlib.sha256(public.encode()).hexdigest())
    assert not protocol.authorize_command(forged, observation(1.1)).allowed


def coordinator():
    from guardian_core.bound_recovery import EvidenceBoundRecovery
    return EvidenceBoundRecovery(RecoveryConfig(dwell_sec=0.2, stable_window_sec=0.1, proof_ttl_sec=0.5))


def step(gate, now, **changes):
    from guardian_core.bound_recovery import RecoveryTelemetry
    fields = dict(now=now, telemetry=RecoveryTelemetry(now, 0.0, 5.0, True, False, True, True),
        graph_fingerprint="graph", policy_fingerprint="policy", command_epoch=1,
        stopped_ack=True, unresolved=False, forced_stop=False)
    fields.update(changes)
    return gate.update(**fields)


def test_stable_health_issues_proof_then_authorizes_next_epoch():
    gate = coordinator()
    assert not step(gate, 1.0).mission_allowed
    assert not step(gate, 1.1).mission_allowed
    candidate = step(gate, 1.25)
    assert candidate.phase == "RECOVERY_CANDIDATE"
    assert not candidate.mission_allowed
    assert gate.pending_proof.command_epoch == 2
    assert step(gate, 1.3).mission_allowed
    assert gate.last_proof_id
    assert step(gate, 1.4, command_epoch=2, stopped_ack=False).mission_allowed


@pytest.mark.parametrize("change", [dict(graph_fingerprint="changed"),
    dict(policy_fingerprint="changed"), dict(command_epoch=2), dict(unresolved=True)])
def test_context_change_between_issue_and_use_blocks_motion(change):
    gate = coordinator()
    step(gate, 1.0)
    step(gate, 1.25)
    assert gate.pending_proof is not None
    assert not step(gate, 1.3, **change).mission_allowed


def test_ledger_change_between_issue_and_use_blocks_motion():
    from guardian_core.evidence_ledger import Evidence
    gate = coordinator()
    step(gate, 1.0)
    step(gate, 1.25)
    gate.ledger.append(Evidence("new", "monitor", "probe", "base", 1.26, 5, 1, 0, "policy", verified=True))
    assert not step(gate, 1.3).mission_allowed


def test_stale_observation_or_continuing_attack_cannot_recover():
    from guardian_core.bound_recovery import RecoveryTelemetry
    gate = coordinator()
    assert not step(gate, 1, telemetry=None).mission_allowed
    stale = RecoveryTelemetry(1, 0, 5, True, False, True, True)
    assert not step(gate, 2, telemetry=stale).mission_allowed
    attack = replace(stale, received_at=2.1, attack_active=True)
    assert not step(gate, 2.1, telemetry=attack).mission_allowed


def test_healthy_heartbeats_do_not_change_evidence_anchor():
    gate = coordinator()
    step(gate, 1)
    anchor = gate.ledger.anchor()
    step(gate, 1.05)
    assert gate.ledger.anchor() == anchor


def test_missing_stop_ack_and_unflushed_commands_prevent_recovery():
    from guardian_core.bound_recovery import RecoveryTelemetry
    gate = coordinator()
    assert not step(gate, 1, stopped_ack=False).mission_allowed
    uncleared = RecoveryTelemetry(1.1, 0, 5, True, False, False, True)
    assert not step(gate, 1.1, telemetry=uncleared).mission_allowed


def test_ledger_capacity_fails_closed():
    from guardian_core.bound_recovery import EvidenceBoundRecovery
    gate = EvidenceBoundRecovery(max_evidence=1)
    step(gate, 1)
    assert not step(gate, 1.1, graph_fingerprint="changed").mission_allowed
    assert gate.ledger.anchor().count == 1
    assert step(gate, 1.2).phase == "SAFE_STOP"


def test_completed_proof_cannot_be_reissued_from_same_candidate():
    protocol = RecoveryProtocol(RecoveryConfig(dwell_sec=0, stable_window_sec=0))
    observed = observation(1)
    proof = protocol.commit(observed)
    assert protocol.authorize_command(proof, observation(1.1)).allowed
    with pytest.raises(ValueError):
        protocol.issue_observed(observed)


def running_gate():
    gate = coordinator()
    step(gate, 1.0)
    step(gate, 1.25)
    assert step(gate, 1.3).mission_allowed
    return gate


@pytest.mark.parametrize("age, allowed", [(0.0, True), (0.49, False)])
def test_running_motion_uses_distance_remaining_since_capture(age, allowed):
    from guardian_core.bound_recovery import RecoveryTelemetry
    gate = running_gate()
    telemetry = RecoveryTelemetry(10.0 - age, 0.35, 0.34, True, False, True, True)
    decision = step(gate, 10.0, telemetry=telemetry, command_epoch=2, stopped_ack=False)
    assert decision.mission_allowed is allowed
    if not allowed:
        assert decision.speed_limit == 0.0


@pytest.mark.parametrize("speed, free_distance", [(0.0, 0.24), (0.35, 0.34)])
def test_older_capture_cannot_increase_motion_permission_or_speed(speed, free_distance):
    from guardian_core.bound_recovery import RecoveryTelemetry
    decisions = []
    for age in (0.0, 0.05, 0.1, 0.2, 0.49):
        gate = running_gate()
        # Even a stationary sample cannot exclude subsequent acceleration up
        # to the configured 0.35 m/s operating bound.
        telemetry = RecoveryTelemetry(10.0, speed, free_distance, True, False, True, True)
        decisions.append(step(gate, 10.0 + age, telemetry=telemetry,
            command_epoch=2, stopped_ack=False))
    assert decisions[0].mission_allowed
    assert not decisions[-1].mission_allowed
    assert decisions[-1].speed_limit < decisions[0].speed_limit
    for newer, older in zip(decisions, decisions[1:]):
        assert older.mission_allowed <= newer.mission_allowed
        assert older.speed_limit <= newer.speed_limit + 1e-12


def test_capture_age_overlaps_fixed_sensor_latency_instead_of_adding_it_twice():
    from guardian_core.bound_recovery import RecoveryTelemetry
    gate = running_gate()
    # After 0.2 s, 0.31 m remains. Current stopping distance with control
    # latency is 0.2965625 m; counting sensor latency again would require
    # 0.3315625 m and reject this safe control.
    telemetry = RecoveryTelemetry(9.8, 0.35, 0.38, True, False, True, True)
    decision = step(gate, 10.0, telemetry=telemetry, command_epoch=2, stopped_ack=False)
    assert decision.mission_allowed
    assert 0.35 <= decision.speed_limit + 1e-12


def test_old_zero_speed_sample_does_not_assume_robot_remained_stationary():
    from guardian_core.bound_recovery import RecoveryTelemetry
    gate = running_gate()
    # An old zero-speed sample cannot exclude subsequent acceleration. With
    # the operating speed bound, only 0.265 m remains and stopping needs more.
    telemetry = RecoveryTelemetry(9.9, 0.0, 0.30, True, False, True, True)
    decision = step(gate, 10.0, telemetry=telemetry, command_epoch=2, stopped_ack=False)
    assert not decision.mission_allowed


def test_fresh_stopped_samples_with_nearby_clearance_still_complete_recovery():
    from guardian_core.bound_recovery import RecoveryTelemetry
    gate = coordinator()
    decisions = []
    for now in (1.0, 1.25, 1.3):
        telemetry = RecoveryTelemetry(now - 0.1, 0.0, 0.40, True, False, True, True)
        decisions.append(step(gate, now, telemetry=telemetry))
    assert decisions[-2].phase == "RECOVERY_CANDIDATE"
    assert decisions[-1].mission_allowed
