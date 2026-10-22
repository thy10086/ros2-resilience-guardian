# Evidence-bound recovery implementation plan

> **For agentic workers:** Use executing-plans inline, with TDD and an independent code review before delivery. Preserve existing uncommitted work.

**Goal:** Complete the AMR observation → stop/ACK → evidence/context → recovery permission → first motion command loop.

**Architecture:** Reuse existing deterministic safety modules and ROS transport. A small coordinator owns recovery state; ROS glue authenticates telemetry and obtains live graph context. No new runtime dependencies.

**Tech Stack:** Python standard library, rclpy Humble, existing ROS messages and pytest.

**Spec:** ../specs/2026-10-12-evidence-bound-recovery-design.md

## Global constraints

- Preserve existing uncommitted work; no automatic commits or service deployment.
- Only AMR simulator observations can resolve simulator-origin incidents.
- Missing/stale/invalid observations, context changes and watchdog faults fail closed.
- Software loop only; do not claim physical braking or production certification.

## Tasks

- [x] 1. Add failing tests in tests/test_bound_recovery.py for public-checksum forgery, stable recovery, context invalidation, telemetry freshness and unchanged heartbeat anchor. Run `python3 -m pytest tests/test_bound_recovery.py -q` and confirm failure.
- [x] 2. Modify recovery_protocol.py to use independent secret HMAC; create bound_recovery.py coordinator exposing `update(now, telemetry, graph_fingerprint, policy_fingerprint, command_epoch, stopped_ack, unresolved, forced_stop)`. Reuse EvidenceLedger and PredictiveEnvelope. Run core tests.
- [x] 3. Add RecoveryTelemetry.msg, standard HMAC functions in feedback_auth.py, live graph extraction in recovery_graph.py, GuardianNode subscriptions/coordination/status audit, and AmrSimulatorNode authenticated observations. Add failing ROS tests first, rebuild interface/core packages with existing deploy/run_guardian.sh build --distro humble, run ROS tests.
- [x] 4. Add experiments/run_bound_recovery_experiments.py reusing the actual ROS test driver, producing JSON metrics and assertions for nominal recovery, persistent attack and graph changes. Run experiment and full pytest suite.
- [x] 5. Update README, PROJECT_GUIDE, HANDOFF and docs/evidence_bound_recovery.md with theme, command, reuse attribution, measured results and limits. Check compileall and git diff --check; independent review safety integration and resolve material findings.

## Review checklist

Check first resumed command uses the validated proof's next epoch; no automatic event TTL clearance; no live graph discovery reimplementation; no heartbeat-induced anchor churn; preserve watchdog latch; cap telemetry input and evidence storage; no secrets in outputs.
