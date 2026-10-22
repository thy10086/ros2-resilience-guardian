# Feedback target ablation implementation plan

> Use executing-plans, test-driven-development and requesting-code-review. Continue the user-approved follow-up in the existing branch; preserve all earlier uncommitted work. No commit/push/deployment.

**Goal:** Isolate feedback families and evaluate the frozen design on previously unused seeds.

**Architecture:** Add masks around existing trace-derived targets; extend existing evaluation reporting, comparisons and optional plot. No new extractor, generator, recovery logic or mutant.

**Tech Stack:** Existing Python, Hypothesis6.168.5, pytest, optional Matplotlib.

**Spec:** ../specs/2026-10-12-feedback-target-ablation-design.md

- [x] 1. Add tests/test_feedback_target_ablation.py for actual target-label calls, exact budgets and corpus replay; observe red. Add ttl/context_repair masks and active label metadata to the existing runner. Keep all four observed maxima for all modes.
- [x] 2. Add tests for paired ablation/censored results, new modes in a small batch, explicit unseen seed-role and validation-before-writes; observe red. Extend evaluation CLI/report/comparisons and plot, preserving defaults.
- [x] 3. Independent preflight review, then five modes×seeds10..19×1000 in experiments/results/feedback_target_ablation. Save every group; verify50corpora/all counterexamples and inspect independently recomputed outcomes. Do not change targets or distribution after seeing results. Raw exit1 retained, two liveness findings diagnosed below.
- [x] 3a. Preserve failed raw batch/source snapshot and diagnose sparse-frame recovery_stalled. Red/green continuous-stall and six-gap tests, minimal Oracle max-frame-gap correction, independent review; complete five-mode corrected rerun in experiments/results/feedback_target_ablation_corrected with identical targets/inputs/budgets. Verify all saved inputs; rebuild the shared ROS package. Do not merge raw and corrected statistics. Corrected exit0,184examples/50corpora consistent; independent review passed.
- [x] 4. Full pytest/compileall/diff checks and standalone plot visual inspection. Write docs/feedback_target_ablation.md and update README, PROJECT_GUIDE, fifth-round follow-up and HANDOFF. Mark complete only after fresh evidence. 597passed, build/compileall passed, five-mode PNG/SVG visually checked.

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
output/recovery-fuzz-venv/bin/python -m pytest tests/test_feedback_target_ablation.py tests/test_permit_boundary_feedback.py tests/test_recovery_evaluation.py -q
output/recovery-fuzz-venv/bin/python experiments/run_recovery_evaluation.py --modes unguided,guided,boundary,ttl,context_repair --seeds 10,11,12,13,14,15,16,17,18,19 --budget 1000 --seed-role unseen_validation --output-dir experiments/results/feedback_target_ablation_corrected
output/recovery-fuzz-venv/bin/python -m pytest tests -q
output/recovery-fuzz-venv/bin/python -m compileall -q experiments ros2_ws/src/guardian_core/guardian_core
git diff --check
```
