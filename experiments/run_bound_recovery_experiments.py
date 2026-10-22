"""Run the actual ROS 2 AMR software loop in an isolated localhost domain.

No pytest dependency, remote provider, browser or physical actuator is required.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws/src/guardian_core"))


def run() -> dict:
    import rclpy
    from rclpy.executors import SingleThreadedExecutor
    from geometry_msgs.msg import Twist
    from std_msgs.msg import String
    from guardian_interfaces.msg import SafetyStatus
    from guardian_core.guardian_node import GuardianNode
    from guardian_core.amr_simulator import AmrSimulatorNode

    keys = ("ROS_DOMAIN_ID", "ROS_LOCALHOST_ONLY", "GUARDIAN_FEEDBACK_SECRET", "GUARDIAN_EVENT_SECRET")
    previous = {key: os.environ.get(key) for key in keys}
    os.environ["ROS_DOMAIN_ID"] = str(170 + os.getpid() % 30)
    os.environ["ROS_LOCALHOST_ONLY"] = "1"
    os.environ["GUARDIAN_FEEDBACK_SECRET"] = secrets.token_hex(32)
    os.environ.pop("GUARDIAN_EVENT_SECRET", None)
    nodes = []
    executor = None
    try:
        rclpy.init(args=["bound_recovery_experiment", "--ros-args", "-p",
            "guardian_node:evidence_bound_recovery:=true", "-p",
            "guardian_node:startup_feedback_grace_sec:=3.0", "-p",
            "guardian_node:max_event_age_sec:=0.3"])
        executor = SingleThreadedExecutor()
        guardian = GuardianNode()
        nodes.append(guardian)
        simulator = AmrSimulatorNode()
        nodes.append(simulator)
        probe = rclpy.create_node("bound_recovery_experiment_probe")
        nodes.append(probe)
        for node in nodes:
            executor.add_node(node)
        controls = probe.create_publisher(String, "/amr_07/sim_control", 20)
        statuses, motions, audit = [], [], []
        probe.create_subscription(SafetyStatus, "guardian/safety_status",
            lambda msg: statuses.append((time.monotonic(), msg)), 20)
        probe.create_subscription(Twist, "/cmd_vel",
            lambda msg: motions.append((time.monotonic(), msg.linear.x)), 20)
        original_emit = guardian.audit.emit
        def record(kind, payload):
            audit.append({"at": time.monotonic(), "kind": kind, **payload})
            original_emit(kind, payload)
        guardian.audit.emit = record

        def wait(predicate, timeout=8):
            deadline = time.monotonic() + timeout
            while not predicate() and time.monotonic() < deadline:
                executor.spin_once(timeout_sec=0.02)
            if not predicate():
                raise AssertionError(f"ROS loop timed out; latest audit={audit[-5:]}")

        def control(action, attack=None):
            data = {"action": action}
            if attack:
                data["type"] = attack
            controls.publish(String(data=json.dumps(data)))

        wait(lambda: controls.get_subscription_count() == 1)
        started = time.monotonic()
        control("start")
        wait(lambda: motions and motions[-1][1] > 0)
        nominal_time = motions[-1][0] - started
        first_proof = guardian.recovery.last_proof_id
        assert first_proof

        injected = time.monotonic()
        control("attack", "speed_abuse")
        wait(lambda: guardian.registry.active_records() and statuses
            and not statuses[-1][1].mission_allowed and motions[-1][1] == 0)
        containment_time = motions[-1][0] - injected
        stop_time = time.monotonic()
        wait(lambda: time.monotonic() - stop_time > 0.8)
        assert guardian.registry.active_records(), "event TTL incorrectly cleared ongoing attack"
        assert not statuses[-1][1].mission_allowed and motions[-1][1] == 0

        reset_at = time.monotonic()
        control("reset")
        wait(lambda: simulator.model.phase == "IDLE")
        control("start")
        wait(lambda: guardian.recovery.last_proof_id != first_proof
            and motions[-1][1] > 0)
        recovery_time = motions[-1][0] - reset_at
        assert statuses[-1][1].plan_id.startswith("recovery-")

        # Break a relevant live control endpoint, then restore it. A new proof
        # must be issued; the previous authorization may not survive the change.
        rogue = probe.create_publisher(SafetyStatus, "guardian/safety_status", 20)
        wait(lambda: guardian._recovery_graph_fingerprint() == "")
        wait(lambda: not statuses[-1][1].mission_allowed and motions[-1][1] == 0)
        probe.destroy_publisher(rogue)
        wait(lambda: guardian.recovery.pending_proof is not None)
        pending = guardian.recovery.pending_proof.proof_id
        rogue = probe.create_publisher(SafetyStatus, "guardian/safety_status", 20)
        wait(lambda: guardian._recovery_graph_fingerprint() == "")
        wait(lambda: guardian.recovery.pending_proof is None)
        assert guardian.recovery.last_proof_id != pending
        assert not statuses[-1][1].mission_allowed and motions[-1][1] == 0
        probe.destroy_publisher(rogue)
        wait(lambda: motions[-1][1] > 0)
        assert guardian.recovery.last_proof_id != pending

        assert guardian.recovery.ledger.verify()
        records = guardian.recovery.ledger.export()
        assert any(item["evidence"]["kind"] == "verified_attack" for item in records)
        assert any(item["evidence"]["kind"] == "incident_resolution" for item in records)
        return {
            "schema": "guardian-bound-recovery/v1", "platform": "ROS 2 Humble software AMR",
            "physical_actuator_verified": False, "provider_called": False,
            "cases": {
                "nominal_recovery": "PASS", "persistent_attack_beyond_event_ttl": "PASS",
                "healthy_probe_after_reset": "PASS", "live_graph_change": "PASS",
                "graph_change_between_proof_issue_and_use": "PASS",
            },
            "metrics": {
                "startup_to_first_motion_sec": round(nominal_time, 4),
                "injection_to_observed_zero_velocity_sec": round(containment_time, 4),
                "reset_to_first_recovered_motion_sec": round(recovery_time, 4),
                "ledger_records": len(records), "observed_velocity_messages": len(motions),
            },
            "recovery_transitions": [row for row in audit if row["kind"] == "bound_recovery"],
            "evidence": records,
        }
    finally:
        for node in reversed(nodes):
            executor.remove_node(node)
            node.destroy_node()
        if executor is not None:
            executor.shutdown()
        if rclpy.ok():
            rclpy.shutdown()
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
        default=ROOT / "experiments/results/bound_recovery_validation.json")
    args = parser.parse_args()
    report = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"cases": report["cases"], "metrics": report["metrics"],
        "output": str(args.output)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
