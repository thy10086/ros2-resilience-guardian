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
