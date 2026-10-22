"""Real three-process DDS acceptance, managed and cleaned up by launch_testing.

Run: launch_test experiments/independent_observation_launch_test.py
"""
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import tempfile
import time
import unittest

import launch
import launch_testing
import launch_testing.actions
import launch_testing.asserts
from launch_ros.actions import Node
from launch.actions import RegisterEventHandler
from launch.event_handlers import OnProcessExit
import rclpy
from geometry_msgs.msg import Twist
from std_msgs.msg import String
from guardian_interfaces.msg import IndependentObservation, SafetyStatus
from guardian_core.recovery_feedback import RecoveryFrame, SemanticCoverage, SafetyOracle

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))
from ros_startup_diagnostics import StartupDiagnostics
from recovery_ros_artifacts import begin_capture, retain_capture


def generate_test_description():
    domain = str(170 + os.getpid() % 30)
    artifact_dir = os.environ.get("GUARDIAN_RECOVERY_ARTIFACT_DIR")
    capture_dir = begin_capture(ROOT, artifact_dir, domain=domain) if artifact_dir else None
    os.environ["ROS_DOMAIN_ID"] = domain
    os.environ["ROS_LOCALHOST_ONLY"] = "1"
    feedback, observation = secrets.token_hex(32), secrets.token_hex(32)
    common = {"ROS_DOMAIN_ID": domain, "ROS_LOCALHOST_ONLY": "1",
        "GUARDIAN_FEEDBACK_SECRET": feedback, "GUARDIAN_EVENT_SECRET": ""}
    (ROOT / "output").mkdir(exist_ok=True)
    descriptor, audit_path = tempfile.mkstemp(prefix="recovery-trace-", suffix=".jsonl", dir=ROOT / "output")
    os.close(descriptor)
    guardian = Node(package="guardian_core", executable="guardian_node", output="screen",
        additional_env={**common, "GUARDIAN_OBSERVATION_SECRET": observation},
        parameters=[{"evidence_bound_recovery": True, "independent_observation_required": True,
            "startup_feedback_grace_sec": 5.0, "max_event_age_sec": 0.3, "audit_path": audit_path}])
    adapter = Node(package="guardian_core", executable="amr_simulator", output="screen",
        additional_env={**common, "GUARDIAN_OBSERVATION_SECRET": ""})
    observer = Node(package="guardian_core", executable="recovery_observer", output="screen",
        additional_env={**common, "GUARDIAN_OBSERVATION_SECRET": observation}, respawn=True, respawn_delay=0.2)
    exits = []
    def record_exit(event, context):
        exits.append({"process": event.action.process_details["name"], "returncode": event.returncode})
    return launch.LaunchDescription([RegisterEventHandler(OnProcessExit(on_exit=record_exit)),
        guardian, adapter, observer, launch_testing.actions.ReadyToTest()]), {
            "processes": [guardian, adapter, observer], "exit_history": exits, "audit_path": audit_path,
            "expected_domain": domain, "capture_dir": capture_dir}


class TestIndependentRecovery(unittest.TestCase):
    def test_faults_require_new_independent_evidence(self, proc_info, processes, exit_history, audit_path, expected_domain, capture_dir):
        startup = StartupDiagnostics(expected_domain)
        for process in processes:
            proc_info.assertWaitForStartup(process=process, timeout=15)
            startup.mark(f"process_{processes.index(process)}_started")
        rclpy.init()
        node = rclpy.create_node("independent_recovery_acceptance")
        statuses, motions, observations, states = [], [], [], []
        node.create_subscription(SafetyStatus, "guardian/safety_status", statuses.append, 20)
        node.create_subscription(Twist, "/cmd_vel", lambda m: motions.append((time.monotonic(), m.linear.x)), 20)
        node.create_subscription(IndependentObservation, "guardian/independent_observation", observations.append, 20)
        node.create_subscription(String, "guardian/sim_state", lambda m: states.append(json.loads(m.data)), 20)
        controls = node.create_publisher(String, "/amr_07/sim_control", 20)
        cases, metrics = {}, {}

        def startup_snapshot():
            for name, samples in (("safety_status", statuses), ("motion", motions),
                                  ("independent_observation", observations), ("sim_state", states)):
                if samples:
                    startup.mark(name)
            if controls.get_subscription_count():
                startup.mark("control_subscription")
            return startup.snapshot(node, [proc_info[process].pid for process in processes])

        def wait(predicate, timeout=12):
            deadline = time.monotonic() + timeout
            while not predicate() and time.monotonic() < deadline:
                rclpy.spin_once(node, timeout_sec=0.02)
                if controls.get_subscription_count():
                    startup.mark("control_subscription")
                # Startup only; do not repeatedly inspect /proc during faults.
                for name, samples in (("safety_status", statuses), ("motion", motions),
                                      ("independent_observation", observations), ("sim_state", states)):
                    if samples:
                        startup.mark(name)
            if not predicate():
                diagnostic = startup_snapshot()
                destination = ROOT / f"experiments/results/startup_timeout_{os.getpid()}.json"
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(json.dumps(diagnostic, indent=2), encoding="utf-8")
                self.fail(f"DDS acceptance timed out: status={statuses[-1] if statuses else None}, "
                    f"observation={observations[-1] if observations else None}, state={states[-1] if states else None}; "
                    f"startup={diagnostic}")

        def control(action, **fields):
            controls.publish(String(data=json.dumps({"action": action, **fields})))

        def moving():
            return bool(motions and motions[-1][1] > 0 and statuses and statuses[-1].mission_allowed)

        def stopped():
            return bool(motions and motions[-1][1] == 0 and statuses and not statuses[-1].mission_allowed)

        def hold_stop(seconds=0.8):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                rclpy.spin_once(node, timeout_sec=0.02)
                self.assertTrue(stopped(), "robot resumed while invalid evidence remained")

        try:
            wait(lambda: controls.get_subscription_count() == 1 and states and statuses and observations)
            startup_report = startup_snapshot()
            self.assertTrue(startup_report["domain_match"], startup_report)
            started = time.monotonic()
            control("start")
            wait(moving)
            metrics["startup_to_motion_sec"] = round(time.monotonic() - started, 4)
            self.assertTrue(any(report.valid and report.free_distance > 0 for report in observations))
            cases["three_process_nominal_recovery"] = "PASS"

            injected = time.monotonic()
            control("attack", type="speed_abuse")
            wait(stopped)
            metrics["attack_to_observed_zero_sec"] = round(time.monotonic() - injected, 4)
            hold_stop()
            cases["persistent_attack_beyond_event_ttl"] = "PASS"
            control("reset")
            wait(lambda: states and states[-1]["phase"] == "IDLE")
            reset_at = time.monotonic()
            control("start")
            wait(moving)
            metrics["reset_to_motion_sec"] = round(time.monotonic() - reset_at, 4)
            cases["attack_reset_health_recovery"] = "PASS"

            for fault in ("paused", "stale", "replay", "invalid_scan", "speed_mismatch", "near_obstacle"):
                previous_plan = statuses[-1].plan_id
                at = time.monotonic()
                control("sensor_fault", mode=fault)
                wait(stopped)
                metrics[f"{fault}_to_zero_sec"] = round(time.monotonic() - at, 4)
                hold_stop()
                cases[f"{fault}_blocks_motion"] = "PASS"
                control("sensor_fault", mode="normal")
                wait(moving)
                self.assertNotEqual(statuses[-1].plan_id, previous_plan)
                cases[f"{fault}_repair_requires_new_permission"] = "PASS"

            rogue = node.create_publisher(IndependentObservation, "guardian/independent_observation", 20)
            wait(stopped)
            hold_stop()
            node.destroy_publisher(rogue)
            wait(moving)
            cases["extra_observation_publisher_invalidates_context"] = "PASS"

            previous_plan = statuses[-1].plan_id
            control("sensor_fault", mode="restart_endpoints")
            wait(stopped)
            wait(moving)
            self.assertNotEqual(statuses[-1].plan_id, previous_plan)
            cases["raw_sensor_endpoint_restart_requires_new_permission"] = "PASS"

            previous_session = observations[-1].observer_session
            previous_plan = statuses[-1].plan_id
            restart_at = time.monotonic()
            os.kill(proc_info[processes[2]].pid, signal.SIGINT)
            wait(stopped)
            wait(lambda: observations and observations[-1].observer_session != previous_session)
            wait(moving)
            self.assertNotEqual(statuses[-1].plan_id, previous_plan)
            self.assertTrue(exit_history)
            self.assertTrue(all(item["returncode"] == 0 for item in exit_history), exit_history)
            metrics["observer_restart_to_motion_sec"] = round(time.monotonic() - restart_at, 4)
            cases["observer_process_restart_requires_new_session_and_permission"] = "PASS"

            rows = [json.loads(line) for line in Path(audit_path).read_text().splitlines()]
            trace = [RecoveryFrame.from_dict({k: v for k, v in row.items() if k != "kind"})
                for row in rows if row["kind"] == "recovery_trace"]
            self.assertTrue(trace, "configured audit produced no recovery frames")
            coverage = SemanticCoverage()
            coverage.observe_trace(trace)
            violations = SafetyOracle().check_trace(trace)
            self.assertFalse(violations, violations)
            cases["semantic_recovery_trace_oracle"] = "PASS"
            report = {"schema": "guardian-independent-observation/v1", "cases": cases, "metrics": metrics,
                "startup": startup_report,
                "semantic_feedback": {**coverage.summary(), "frames": len(trace), "violations": []},
                "process_count": len(processes), "restart_exit_history": exit_history,
                "physical_measurement_verified": False,
                "sensor_source": "software AMR model", "provider_called": False,
                "observed_report_count": len(observations),
                "independent_source_samples": [{"odom_timestamp": m.odom_timestamp,
                    "scan_timestamp": m.scan_timestamp, "free_distance": m.free_distance,
                    "speed": m.actual_speed, "valid": m.valid, "epoch": m.command_epoch}
                    for m in observations[-20:]]}
            destination = (capture_dir / "acceptance.json" if capture_dir else
                ROOT / "experiments/results/independent_observation_validation.json")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
        finally:
            node.destroy_node()
            if rclpy.ok():
                rclpy.shutdown()


@launch_testing.post_shutdown_test()
class TestShutdown(unittest.TestCase):
    def test_child_process_exit_codes(self, proc_info, exit_history, audit_path, capture_dir):
        if capture_dir:
            retained = retain_capture(capture_dir, audit_path)
            self.assertEqual(retained["analysis"]["violation_count"], 0, retained["analysis"])
            self.assertIsNotNone(retained["acceptance_report"], "active acceptance did not complete")
        launch_testing.asserts.assertExitCodes(proc_info)
        self.assertTrue(all(item["returncode"] == 0 for item in exit_history), exit_history)
        Path(audit_path).unlink(missing_ok=True)
