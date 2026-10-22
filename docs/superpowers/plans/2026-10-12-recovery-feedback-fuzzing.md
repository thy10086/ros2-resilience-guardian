# Recovery feedback fuzzing implementation plan

> **For agentic workers:** Use executing-plans inline, TDD and requesting-code-review. Preserve existing uncommitted work.

**Goal:** Run reproducible recovery-semantic feedback testing with saved corpus, safety oracles and native ROS trace validation.

**Architecture:** Pure semantic trace/coverage/oracle module, deterministic scenario adapter over existing core, Hypothesis-backed CLI. ROS audit frames are consumed by the same trace tools.

**Tech Stack:** Python stdlib, Hypothesis (isolated offline dependency), existing recovery/observation core, ROS 2 Humble launch_testing.

**Spec:** ../specs/2026-10-12-recovery-feedback-fuzzing-design.md

## Constraints

- No commit/deployment/robot connection; continue codex/evidence-bound-recovery.
- Do not replace exact protocol binding with normalized coverage labels.
- No claimed BTreeFuzz algorithm reproduction or physical safety proof.
- Hypothesis stays out of ROS runtime dependencies; control behavior is preserved.

## Tasks

- [x] 1. Add tests/test_recovery_feedback.py for stable normalized states, failure categories, heartbeat de-duplication, bounded coverage, exact oracle violations and healthy liveness. Observe missing-module failures. Implement guardian_core/recovery_feedback.py with RecoveryFrame, SemanticCoverage.observe_trace, SafetyOracle.check_trace.
- [x] 2. Add tests/test_recovery_fuzzing.py for actual coordinator/observation execution, pending-proof mutations, incident/reset and replay stability. Implement experiments/recovery_scenarios.py with Action and execute_scenario(actions). Add experiments/run_recovery_feedback_fuzzing.py using Hypothesis strategies/target/find; exact validated JSON action replay and saved interesting corpus; pin tested dependency in experiments/requirements-fuzzing.txt. Run small fixed-seed guided and unguided campaigns and replay saved corpus.
- [x] 3. Add ROS audit trace assertion test first. Emit recovery_trace only when audit_path is configured, using real input context and decision. Extend existing independent_observation_launch_test.py to validate recorded frames via same semantic coverage/oracle, with all existing process/physical-motion assertions retained. Rebuild Humble and run launch_test.
- [x] 4. Independent code review and fixes; full pytest, compileall and diff checks. Update docs/recovery_feedback_fuzzing.md, BTreeFuzz research record, README, PROJECT_GUIDE and HANDOFF with CLI commands, measured coverage, target limits and exact verification results. Mark tasks complete after evidence.

## Commands

```bash
output/recovery-fuzz-venv/bin/python -m pytest tests/test_recovery_feedback.py tests/test_recovery_fuzzing.py -q
output/recovery-fuzz-venv/bin/python experiments/run_recovery_feedback_fuzzing.py --seed 42 --budget 64 --mode guided
output/recovery-fuzz-venv/bin/python experiments/run_recovery_feedback_fuzzing.py --seed 42 --budget 64 --mode unguided --output experiments/results/recovery_feedback_unguided.json
bash deploy/run_guardian.sh build --distro humble
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
launch_test experiments/independent_observation_launch_test.py
python3 -m pytest tests -q
git diff --check
```
