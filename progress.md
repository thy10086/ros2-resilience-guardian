# Progress

- 2026-09-23: Resumed approved patent-oriented development from clean main e9c4932. Read planning/TDD/verification skills, checked relevant open-source references, and recorded exact interfaces and validation in docs/patent_implementation_plan.md. No secrets or global environment variables changed.

- 2026-09-23: Added red tests for causal graph provenance, evidence lineage/tamper detection, predictive envelope, assurance counterfactuals, and two-phase recovery; initial collection failed because the new modules were absent.
- 2026-09-23: Implemented five research-core modules and exported their typed APIs. Target patent tests passed with 9 passed; deterministic patent experiment passed all five groups, including 0.315 m/s fixed-envelope versus 0.175 m/s growing-risk prediction and replay/context invalidation.
- 2026-09-23: Added adversarial regression tests for graph cycles/duplicates, lineage expiry and policy binding, ledger export/tamper failure, risk dilution, braking infeasibility, invalid motion input, forged/replayed recovery proofs, risk/context changes, observation gaps, and legacy export compatibility.
- 2026-09-23: Fixed the discovered boundary failures; patent-core tests now pass with 32 passed, and the five-group patent innovation experiment passes again.
- 2026-09-23: Closed the review findings in the recovery and evidence boundaries. Recovery authorization now requires the protocol to remain in `RECOVERY_CANDIDATE`, binds the proof to the latest observation, rejects intervening observations and failed observations, and signs `proof_id` to prevent identifier substitution/replay. Exported ledgers now recheck parent existence, expiry, verification, policy lineage, and hard-stop replacement rules.
- 2026-09-23: Revalidated after the fixes: `tests/test_patent_core.py` passed with 38 tests; the full WSL2 suite passed with 73 tests; both innovation experiment suites passed; Windows compileall, frontend `node --check`, `git diff --check`, and ROS 2 Jazzy `colcon build --symlink-install` passed for both packages.

- 2026-09-18: Inspected repository, current commit, tracked `.env`, ROS 2
  packages, and existing plan.
- 2026-09-18: Queried GitHub repository search for ROS 2 security, SROS 2, and
  intrusion-detection references.
- 2026-09-18: Implemented `DashboardState`, `guardian_dashboard`, static
  dashboard assets, launch integration, and README usage instructions.
- 2026-09-18: Windows syntax/state-cache smoke checks passed.
- 2026-09-18: WSL2 validation passed: `9 passed`; both ROS 2 packages built.
- 2026-09-18: Real dashboard process served `/api/health`, `/api/state`, and
  the HTML page on a local test port.
- 2026-09-18: Created the public GitHub repository and published `main` through
  the GitHub API because the local Git HTTPS transport timed out.
- 2026-09-18: Verified the remote tree has 39 blob files and includes `.env`.
- 2026-09-18: Added and ran deterministic innovation experiments; all four experiment groups passed.
- 2026-09-18: Added detailed experiment rationale and the staged cross-layer fusion plan; updated HANDOFF.md in the same change.
- 2026-09-18: Implemented pure Python cross-layer fusion modules: graph risk propagation, temporal policy monitoring, evidence fusion, safety speed envelope, and recovery gate.
- 2026-09-18: Added a fifth deterministic innovation experiment covering the full cross-layer path; WSL2 validation passed with `15 passed` and the innovation suite passed all 5 groups.
- 2026-09-21: Started the optional Jev semantic security advisor task. Scope is bounded to advisory evidence, offline evaluation, documentation, and handoff updates; existing deterministic safety behavior remains the fallback.
- 2026-09-21: Added `jev_advisor.py`, exported its typed API, and wrote red/green tests for disabled mode, redaction, source gating, timeout/error fallback, response bounds, cache invalidation, and safe audit metadata.
- 2026-09-21: Added the deterministic `jev_semantic_advisor` innovation experiment, tracked `.env` defaults, and documented the early-access/side-channel boundary in `docs/jev_advisor.md`, README, and HANDOFF.md.
- 2026-09-21: WSL2 `python3 -m pytest -q tests` passed with `23 passed`; `experiments/run_innovation_experiments.py` passed all 6 groups; Windows `compileall` passed; ROS 2 `colcon build --symlink-install` built both packages.
- 2026-09-21: An initial combined WSL verification command had a PowerShell quoting error; the command was rerun with a single-quoted shell body and completed successfully.
- 2026-09-21: Began the dashboard Jev connection feature. Confirmed the local
  branch is clean at `daa4c18`, reviewed the existing dashboard and advisor,
  checked the official API examples and CORS behavior, and recorded the
  backend-proxy design plus open-source client references. Added the red
  contract tests before implementing the proxy.
- 2026-09-21: Added the pure `JevDashboardService`, `POST /api/jev/test`, input
  and response bounds, no-redirect provider transport, and the desktop Jev
  panel. The dashboard proxy tests now pass (`35 passed`); ROS 2 build,
  compile checks, fake-provider HTTP smoke, live invalid-key mapping, and
  browser empty/failure/success/clear states were verified. No real key was
  stored or used.
- 2026-09-21: Final validation completed after endpoint/key hardening: WSL2
  `python3 -m pytest -q tests` reported `35 passed`, the six-group innovation
  suite passed, `compileall`, `node --check`, and `git diff --check` passed, and
  `colcon build --symlink-install` built both ROS 2 packages. The dashboard
  process also exits cleanly on Ctrl-C. Ready for the `main` push.
