# Recovery evaluation implementation plan

> **For agentic workers:** Use executing-plans inline, TDD and requesting-code-review. Preserve existing uncommitted work; user approved the four-step evaluation proposal.

**Goal:** Produce reproducible startup diagnosis, seeded-defect qualification, ten-seed comparisons and recovery ablations.

**Architecture:** Existing core/scenario/campaign modules plus isolated experiment mutations, startup diagnostics and batch aggregation.

**Tech Stack:** Existing Hypothesis 6.168.5, Python ast/statistics/stdlib, ROS 2 Humble launch_testing.

**Spec:** ../specs/2026-10-12-recovery-evaluation-design.md

## Constraints

- Keep codex/evidence-bound-recovery; no commit/push/deployment.
- Only repository-owned predefined code is compiled for offline mutations; production classes and ROS defaults stay unchanged.
- No fabricated DDS root cause, performance improvement or physical safety claim.
- Ten seeds 0..9; 1000 generated tests per group; no fixed-scenario warmup in generated comparisons.

## Tasks

- [x] 1. Write tests/test_ros_startup_diagnostics.py asserting whitelisted environment and readiness summary. Observe missing module red. Implement experiments/ros_startup_diagnostics.py, attach to launch test startup and timeout. Run a bounded concurrent reproduction with pytest, then serial ROS acceptance; record exact diagnosis and any justified fix.
- [x] 2. Write tests/test_recovery_mutations.py: each actual code mutant fails a challenge while full control passes; default/production classes unaffected; source drift rejected; proof replay and TTL branches truly exercised. Observe red. Implement experiments/recovery_mutations.py and offline execute_scenario(..., variant='full'); replay_proof action and corresponding seed. Implement qualification report and bounded find reduction with saved variant/actions.
- [x] 3. Write tests/test_recovery_evaluation.py for generated groups excluding fixed seeds, paired statistics and first-defect replay. Observe red. Extend run_campaign with executor/evaluation callback and optional seeds/shrinking. Add experiments/run_recovery_evaluation.py with fixed/guided/unguided batch and ablation reports; save after each run so long experiments are inspectable.
- [x] 4. Run ten seeds x1000 guided/unguided plus fixed reference. Verify discovered/reduced inputs replay; independent review then fixes, full pytest/compileall/diff checks, Humble build and launch acceptance. Update docs/recovery_evaluation.md, README, PROJECT_GUIDE and HANDOFF with exact results/limits. Mark complete only after evidence.

## Commands

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
output/recovery-fuzz-venv/bin/python -m pytest tests/test_ros_startup_diagnostics.py tests/test_recovery_mutations.py tests/test_recovery_evaluation.py -q
output/recovery-fuzz-venv/bin/python experiments/run_recovery_evaluation.py --seeds 0,1,2,3,4,5,6,7,8,9 --budget 1000
bash deploy/run_guardian.sh build --distro humble
launch_test experiments/independent_observation_launch_test.py
output/recovery-fuzz-venv/bin/python -m pytest tests -q
output/recovery-fuzz-venv/bin/python -m compileall -q experiments ros2_ws/src/guardian_core/guardian_core
git diff --check
```
