# Permit boundary feedback implementation plan

> Use test-driven-development and requesting-code-review. The user approved this next step; preserve previous work in codex/evidence-bound-recovery. No commit/push/deployment.

**Goal:** Implement and fairly evaluate trace-derived permit-boundary feedback with existing Hypothesis.

**Spec:** ../specs/2026-10-12-permit-boundary-feedback-design.md

- [x] 1. Add tests/test_permit_boundary_feedback.py for TTL, exact bindings, repair, finite clocks and invariant scores; observe missing-module red. Implement experiments/permit_boundary_feedback.py with bounded set features and target labels, independent from mutants/Oracle.
- [x] 2. Add integration tests for boundary corpus replay, accurate budgets, mode validation, paired comparisons and budget-censored discovery. Observe red. Extend run_recovery_feedback_fuzzing.py and run_recovery_evaluation.py preserving legacy defaults; adapt optional plot to selected groups.
- [x] 3. Run unchanged action strategy with seeds0..9×1000×three generated modes, persist progress and replay every saved counterexample/corpus. Independently review code and outputs; fix any important findings.
- [x] 4. Run full pytest/compileall/diff checks. Update docs/permit_boundary_feedback.md, README, PROJECT_GUIDE, prior evaluation reference and HANDOFF with exact results and limitations; mark complete after evidence.

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
output/recovery-fuzz-venv/bin/python -m pytest tests/test_permit_boundary_feedback.py tests/test_recovery_evaluation.py tests/test_recovery_fuzzing.py -q
output/recovery-fuzz-venv/bin/python experiments/run_recovery_evaluation.py --modes unguided,guided,boundary --seeds 0,1,2,3,4,5,6,7,8,9 --budget 1000 --output-dir experiments/results/permit_boundary_feedback_strict
output/recovery-fuzz-venv/bin/python -m pytest tests -q
output/recovery-fuzz-venv/bin/python -m compileall -q experiments
git diff --check
```
