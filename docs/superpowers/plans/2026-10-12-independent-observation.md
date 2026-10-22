# Independent observation implementation plan

> **For agentic workers:** Use executing-plans inline, test-driven-development and requesting-code-review. Preserve existing uncommitted work.

**Goal:** Enable independently computed recovery observations and verify the loop in three separate ROS processes.

**Architecture:** Standard odometry/scan inputs feed a standalone observer; Guardian requires both authenticated adapter feedback and observer evidence. Reuse ROS launch_testing for process lifecycle.

**Tech Stack:** ROS 2 Humble, rclpy, nav_msgs, sensor_msgs, launch_testing, Python stdlib HMAC/pytest.

**Spec:** ../specs/2026-10-12-independent-observation-design.md

## Global constraints

- Existing work remains intact on codex/evidence-bound-recovery; no commit, deployment or robot connection.
- Software observations are independently computed, not independent physical measurements.
- Independent mode is opt-in and fails closed; missing independent evidence never falls back to adapter-only recovery.
- Independent observation signing key is distinct from the adapter feedback key.

## Tasks

- [x] 1. Add tests/test_independent_observation.py for source replay/staleness, finite values, synchronization, epoch invalidation, conservative cross-check and HMAC domain isolation. Run with pytest and observe missing implementation failures. Implement guardian_core/independent_observation.py: SensorObservationBuffer.observe_odometry/observe_scan/reset/evaluate, fuse_observations; add observation authentication helpers and IndependentObservation.msg; rebuild interfaces.
- [x] 2. Add ROS tests/test_independent_observation_ros.py for signed reports, replay rejection, missing key and two-source gating. Implement recovery_observer.py using native rclpy sensor QoS and signed command validation; integrate Guardian subscriptions, merging, source times, policy and graph bindings. Run focused core/ROS tests.
- [x] 3. Add scan generation and explicit software sensor fault controls to AmrSimulatorNode, retaining model reset semantics. Register observer executable and independent_recovery.launch.py. Write experiments/independent_observation_launch_test.py using launch_ros.actions.Node and ReadyToTest; isolate localhost DDS, pass signing secrets only to required processes, assert observable motion and report validity, assert child exit codes after shutdown. Run launch_test and save JSON acceptance results.
- [x] 4. Run full pytest, Humble build and diff checks; use an independent reviewer, address material findings, rerun affected verification. Update docs/independent_observation.md, README, PROJECT_GUIDE and HANDOFF with exact commands, measured results, upstream attribution and trust limits. Mark tasks complete only after their verification passes.

## Commands

```bash
bash deploy/run_guardian.sh build --distro humble
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
python3 -m pytest tests/test_independent_observation.py tests/test_independent_observation_ros.py -q
launch_test experiments/independent_observation_launch_test.py
python3 -m pytest tests -q
git diff --check
```

## Review targets

No cached sample gets a renewed source time; invalid/replayed raw input clears usable evidence; two samples must belong to current command epoch. Both sources must postdate an incident. Missing/invalid independent inputs must block running as well as recovery. Observation source endpoints are included in graph binding. Separate signing key and raw DDS trust limitations remain explicit.
