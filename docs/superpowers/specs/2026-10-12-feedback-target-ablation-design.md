# Feedback target ablation and unseen-seed validation

The user approved continuing the fifth-round follow-up: independent target ablation and validation with new seeds. Work in the existing codex/evidence-bound-recovery checkout, preserve all earlier changes. No commit, push or service deployment.

## Frozen experiment

Keep fifth-round BoundaryFeedback extraction, action_strategy, timings, core classes, safety Oracle and offline mutants unchanged. Add target masks only: ttl retains the existing permit_ttl_diversity and permit_expiry_proximity labels; context_repair retains permit_context_diversity and repair_transition_diversity. Boundary keeps all four. These are feedback-family ablations, not a new weighted score and not four labels collapsed into one. Continue collecting all four score maxima and all boundary features for every mode; distinguish active optimization labels in reports.

Run seeds10..19, each 1000 generated executions, five modes unguided/guided/boundary/ttl/context_repair. No fixed input warmup; identical action distribution and execution budget, rotating the five-group order so each starting position occurs twice. These seeds have not been used in prior comparisons; the four defect families and model remain familiar, so this is unseen-seed validation, not evidence of generalization to unseen bugs. Do not pool old seeds0..9 and new seeds10..19 to claim superiority.

Before inspecting this batch's results, fix comparisons: each feedback group vs unguided; ttl and context_repair each vs boundary; ttl vs context_repair; preserve previous boundary-vs-guided comparison. Report per-family detection counts, conditional first-index/time, budget-censored restricted first indices and paired differences, normalized state/edge coverage, boundary coverage and wall time. A negative first-index difference is favorable; missed groups are capped at1000 and separately counted. No significance, physical safety or production-vulnerability claim. Do not alter the goal/default mode after observing this batch.

Qualification/production controls and existing mechanism ablation remain validation fixtures outside search budget. Every saved counterexample and each group's corpus must replay with matching Oracle codes, coverage, boundary features and maxima. Preserve source fingerprints and add explicit seed-role/active-target metadata. Use the existing Hypothesis6.168.5; no new search engine or dependency.

## Change scope

Only experiments/run_recovery_feedback_fuzzing.py, run_recovery_evaluation.py, optional plot, tests and documentation. No production ROS behavior, interface, key, transport or service changes. DDS startup uncertainty is not addressed by this offline experiment.

## Acceptance

Tests capture actual Hypothesis target calls to prove masks use the correct two labels and never inactive labels; exact generation budgets and zero warmup; saved replayable score witnesses; ablation paired/censored statistics; unknown seed-role rejection before writes. Independently review implementation before the full batch, and outcomes after completion. Run full pytest, experiments compileall, plot visual QA and git diff --check. Document exact improvements and regressions, retaining original default unless a later authorized design changes it.

## Diagnosed Oracle correction

The first frozen50k batch completed with exit1 and two full-control recovery_stalled findings (boundary seeds12/16). Six .6-second controller gaps exceed the .5-second permit lifetime; the controller correctly rejects expired proofs. The old Oracle incorrectly inferred an uninterrupted eligible window from sparse healthy sampled frames. Preserve the raw batch, triage and source_snapshot in feedback_target_ablation; do not remove findings or present it as passing.

Correct only the liveness precondition in recovery_feedback.SafetyOracle: introduce a positive finite max_frame_gap_sec=.25 (nominal virtual tick.05 / ROS tick.1, and strictly below scenario proof TTL.5); when consecutive frame time separation exceeds it, restart eligible_since/context. Equality remains continuous. Safety authorization/binding/expiry/replay checks still execute across all gaps, with their proof history retained. Periodic healthy SAFE_STOP traces longer than the bound must still fail; SAFE_STOP itself does not reset the window. No change to feedback targets, scenario distribution, production recovery decisions or default search mode.

Add red/green tests for the actual six-gap reproduction followed by normal recovery, gap-reset then true stall, exact threshold and expiry checking across gaps. Record the Oracle source SHA along with existing sources. Independently review this change, then repeat all five modes/seeds10..19/budget1000 in feedback_target_ablation_corrected. All comparisons must use the corrected-Oracle batch, not mix raw/corrected groups. Package rebuild/compileall applies because the offline Oracle shares a ROS Python package. Retain raw source snapshots for reproduction; source fingerprints are batch-specific.
