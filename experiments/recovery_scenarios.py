"""Bounded virtual-time scenarios exercising production recovery/sensor cores.

This models actuator ACKs; real DDS authentication is covered separately by
the three-process launch test. No alternative recovery algorithm lives here.
"""
from dataclasses import dataclass
import math
from types import SimpleNamespace

from guardian_core.bound_recovery import BoundRecoveryDecision, EvidenceBoundRecovery, RecoveryTelemetry
from guardian_core.independent_observation import SensorObservationBuffer, fuse_observations
from guardian_core.recovery_protocol import RecoveryConfig, RecoveryObservation
from guardian_core.recovery_feedback import RecoveryFrame, evidence_state, proof_summary

KINDS = ("healthy", "wait", "gap", "incident", "paused", "stale", "replay", "invalid_scan",
    "speed_mismatch", "near_obstacle", "commands_pending", "probe_failed", "ack_missing",
    "graph_change", "graph_missing", "policy_change", "epoch_change", "replay_proof")


@dataclass(frozen=True)
class Action:
    kind: str
    duration: float = .1

    def __post_init__(self):
        if (self.kind not in KINDS or type(self.duration) not in (int, float)
                or not math.isfinite(self.duration) or not .01 <= self.duration <= 1):
            raise ValueError("action must have a known kind and finite duration in [0.01, 1]")


def execute_scenario(actions, *, variant="full", gate_factory=None, witnesses=None):
    if witnesses is not None and not isinstance(witnesses, list):
        raise ValueError("witnesses must be a list or None")
    if len(actions) > 32:
        raise ValueError("scenario exceeds 32 actions")
    if gate_factory is not None:
        if variant != "full" or not callable(gate_factory):
            raise ValueError("gate_factory requires full variant and a callable")
        gate = gate_factory()
    elif variant == "full":
        gate = EvidenceBoundRecovery(RecoveryConfig(dwell_sec=.2, stable_window_sec=.1,
            proof_ttl_sec=.5))
    else:
        from recovery_mutations import make_gate
        gate = make_gate(variant)
    sensors = SensorObservationBuffer()
    now, epoch, graph_version, policy_version = 1.0, 1, 1, 1
    mode, graph, ack, unresolved = "healthy", "graph-1", True, False
    running, last_stamp = False, 0.0
    last_proof = None
    consumed_proofs = set()
    trace = []
    for action in actions:
        if not isinstance(action, Action):
            raise ValueError("scenario entries must be Action values")
        if action.kind == "healthy":
            mode, graph, ack = "healthy", f"graph-{graph_version}", True
        elif action.kind == "incident":
            gate.record_incident(SimpleNamespace(source="adapter", component="amr", confidence=1.0),
                now=now, policy=f"policy-{policy_version}")
            unresolved, mode = True, "attack"
        elif action.kind == "graph_change":
            graph_version += 1
            graph = f"graph-{graph_version}"
        elif action.kind == "graph_missing":
            graph = ""
        elif action.kind == "policy_change":
            policy_version += 1
        elif action.kind == "epoch_change":
            epoch += 1
        elif action.kind == "ack_missing":
            ack = False
        elif action.kind not in ("wait", "gap", "replay_proof"):
            mode = action.kind
        # Preserve total requested duration, including the final fractional tick.
        # gap deliberately suspends controller updates, exercising proof TTL;
        # wait keeps normal periodic updates and therefore is not equivalent.
        steps = 1 if action.kind == "gap" else math.ceil(action.duration / .05 - 1e-10)
        for step in range(steps):
            now += action.duration if action.kind == "gap" else min(.05, action.duration - step * .05)
            pending_before = gate.pending_proof
            frame_index = len(trace)
            speed = .2 if running else 0.0
            stamp = now - 2 if mode == "stale" else last_stamp if mode == "replay" else now
            if mode != "paused":
                sensors.observe_odometry(stamp=stamp, received_at=now, now_ros=now,
                    frame="map", child_frame="base_link",
                    linear=(speed + (.4 if mode == "speed_mismatch" else 0), 0, 0), angular=(0, 0, 0))
                distance = .01 if mode == "near_obstacle" else 5.0
                sensors.observe_scan(stamp=stamp, received_at=now, now_ros=now,
                    frame="base_scan", angle_min=-.3, angle_increment=.3,
                    range_min=0.0, range_max=10.0,
                    ranges=(float("nan"),) * 3 if mode == "invalid_scan" else (distance,) * 3)
                if mode not in ("stale", "replay"):
                    last_stamp = stamp
            adapter = RecoveryTelemetry(now, speed, 5.0, True, mode == "attack",
                mode != "commands_pending", mode != "probe_failed")
            independent = sensors.evaluate(now_ros=now, now=now)
            effective = fuse_observations(adapter, independent,
                now=now, max_age=.5)
            controller_telemetry = adapter if variant == "no_independent_observation" else effective
            stopped_ack = ack and not running
            if (unresolved and stopped_ack and effective is not None
                    and effective.healthy(now, .5) and effective.speed <= 1e-6):
                gate.resolve_source("adapter", now=now, policy=f"policy-{policy_version}")
                unresolved = False
            input_epoch = epoch
            if witnesses is not None:
                witnesses.append({"kind": "observation", "frame_index": frame_index,
                    "now": now, "healthy": effective is not None and effective.healthy(now, .5),
                    "stopped_ack": stopped_ack, "zero_speed": effective is not None and effective.speed <= 1e-6})
                if pending_before is not None:
                    changed = [name for name, actual in (("graph_fingerprint", graph),
                        ("policy_fingerprint", f"policy-{policy_version}"), ("command_epoch", epoch + 1))
                        if getattr(pending_before, name) != actual]
                    if now >= pending_before.expires_at or changed:
                        witnesses.append({"kind": "candidate_challenge", "frame_index": frame_index,
                            "now": now, "proof": proof_summary(pending_before),
                            "expired": now >= pending_before.expires_at, "changed_fields": changed})
            if action.kind == "replay_proof" and step == 0 and last_proof is not None:
                anchor = gate.ledger.anchor()
                observation = RecoveryObservation(now, not unresolved, graph or "unavailable",
                    f"policy-{policy_version}", f"{anchor.count}:{anchor.head}",
                    adapter.commands_cleared, adapter.sensor_fresh, bool(graph), adapter.probe_success,
                    epoch, 0.0)
                replayed = gate.protocol.authorize_command(last_proof, observation)
                if witnesses is not None:
                    witnesses.append({"kind": "proof_replay", "frame_index": frame_index,
                        "now": now, "proof_id": last_proof.proof_id,
                        "previously_consumed": last_proof.proof_id in consumed_proofs,
                        "allowed": replayed.allowed, "reason": replayed.reason})
                bound = (BoundRecoveryDecision("RESUMABLE", True, .2, replayed.reason, last_proof.proof_id)
                    if replayed.allowed else gate._stop(replayed.reason))
            else:
                bound = gate.update(now=now, telemetry=controller_telemetry, graph_fingerprint=graph,
                    policy_fingerprint=f"policy-{policy_version}", command_epoch=epoch,
                    stopped_ack=stopped_ack, unresolved=unresolved, forced_stop=False)
                if (pending_before is not None and bound.phase == "RESUMABLE"
                        and bound.mission_allowed and bound.proof_id == pending_before.proof_id):
                    consumed_proofs.add(bound.proof_id)
                    if witnesses is not None:
                        witnesses.append({"kind": "proof_consumed", "frame_index": frame_index,
                            "now": now, "proof_id": bound.proof_id, "allowed": True})
            if gate.pending_proof is not None:
                last_proof = gate.pending_proof
            if bound.mission_allowed != running:
                epoch += 1
                sensors.reset(now_ros=now)
            running = bound.mission_allowed
            anchor = gate.ledger.anchor()
            state = evidence_state(effective, now, .5)
            if independent is not None and independent.free_distance <= .01:
                state = "near_obstacle"
            trace.append(RecoveryFrame(now, "navigate" if running else "stabilize", bound.phase,
                state, stopped_ack, unresolved, False, graph, f"policy-{policy_version}",
                f"{anchor.count}:{anchor.head}", input_epoch, epoch, running, bound.speed_limit,
                effective.speed if effective else speed, proof_summary(gate.pending_proof), bound.proof_id))
    return trace


def seed_scenarios():
    scenarios = [[Action("healthy", .5)]]
    for fault in ("incident", "paused", "stale", "replay", "invalid_scan", "speed_mismatch",
                  "near_obstacle", "commands_pending", "probe_failed", "ack_missing", "graph_missing"):
        scenarios.append([Action("healthy", .5), Action(fault, .6), Action("healthy", .6)])
    for change in ("graph_change", "policy_change", "epoch_change"):
        scenarios.append([Action("healthy", .25), Action(change, .05), Action("wait", .6)])
    scenarios.append([Action("healthy", .25), Action("gap", .51), Action("wait", .5)])
    scenarios.append([Action("healthy", .35), Action("replay_proof", .05), Action("healthy", .6)])
    return scenarios
