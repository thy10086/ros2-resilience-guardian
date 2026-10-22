# Permit boundary feedback design

User approved continuing the next evaluation step after the fourth-round results. Extend the existing offline feedback flow; preserve the current branch and all prior uncommitted changes. No commit, push or service deployment.

## Design

Add an experiment-only trace extractor. Adjacent frames after candidate issuance describe the next consumption opportunity: classify remaining lifetime as fresh/near/at/expired, measure bounded proximity to expiry, compare exact graph/policy/ledger/next-epoch binding and identify invalid-evidence to healthy repair transitions and subsequent recovery. Use four finite Hypothesis target labels: TTL feature diversity, expiry proximity, context feature diversity and repair feature diversity. Features are sets, so repeated heartbeats do not earn extra score. Invalid time/lifetime is rejected.

The extractor reads full-control frames only, never mutant findings, injected family names or saved challenge inputs. Semantic coverage and SafetyOracle remain independent. Preserve guided (legacy coverage) and unguided modes; add boundary mode. Store boundary coverage and maxima for every group, including controls; retain inputs producing new boundary features for replay. Expiry classification uses strict equality/order, including adjacent floating point values, matching the production TTL boundary; no tolerance collapses just-before/just-after.

Compare unguided/guided/boundary, seeds 0..9 and 1000 executions each, same unchanged action strategy and timing configuration, no fixed warmup. Rotate group order across seed positions. Freeze this design before looking at the results. Runtime includes probe/target/report overhead. Detection is of controlled offline mutants; non-detections are budget censored. Report paired coverage and detection counts, including restricted first-index statistics capped at the budget rather than treating missed detections as zero. No significance or physical-safety claim.

## Alternatives

Increasing the old sequence coverage score leaves its observed bias toward long diverse sequences. Injecting curated TTL challenges would improve known-defect hit rates but change the input distribution. Use trace-derived boundary feedback while preserving all input strategies; any later distribution change requires a separate comparison.

## Acceptance

Tests distinguish expiry immediately before/at/after, pending-proof graph/policy/ledger/epoch changes, repair and resumed repair, irrelevant raw identifier/time shifts and duplicate-frame invariance. Unknown/duplicate modes fail before output. Legacy evaluation remains compatible. All groups persist reports and saved counterexamples replay. Run full pytest, compileall and diff checks; independently review code and actual outputs. Production ROS code is unchanged in this round, so no rebuild or repeat ROS transport acceptance is needed.

Hypothesis API reference: https://hypothesis.readthedocs.io/en/latest/reference/api.html#hypothesis.target . Installed version remains 6.168.5; no upgrade or new dependency.

Preflight review identified a tolerance-based classification error. Its partial batch in experiments/results/permit_boundary_feedback is excluded. The reviewed strict-boundary batch is saved separately in experiments/results/permit_boundary_feedback_strict, using the same seeds/budget/input strategy and group rotation.
