# Implementation plan

## Dashboard access and local login (2026-09-24)

- [complete] Reproduce the inaccessible 8088 behavior and identify WSL instance reaping plus stale user-service overlap as the causes.
- [complete] Add red/green tests for admin/admin login, session expiry, protected state, login cookie, and logout revocation.
- [complete] Implement in-memory HttpOnly/SameSite sessions, frontend login gate, protected state/Jev routes, and address reuse.
- [complete] Move local runtime to WSL system services, remove the overlapping user units, keep WSL alive with a hidden long-running process, rebuild, and verify Windows HTTP plus ROS status.
- [in_progress] Update handoff, commit on main, push GitHub, and perform final remote/runtime verification.
- [complete] Re-run the full test/build/smoke regression and ignore root-level colcon outputs created by the verification command.
- Scope: local demo authentication and runtime persistence only; no real Jev API call, no robot control changes, and no credentials written to the repository.

## GitHub publication and local runtime (2026-09-24)

- [complete] Verify local main, remote authentication and remote history; preserve tracked .env and exclude generated build/runtime artifacts.
- [complete] Run tests and ROS 2 build; start guardian_node and dashboard without disturbing the existing port 8080 service; verify Windows HTTP access and ROS data flow.
- [complete] Update handoff/runtime evidence, commit on main, push the full project history to origin/main, and verify the remote revision.
- Authorization: the user explicitly requested GitHub upload and local execution after the overnight development deadline. No new research features or live Jev API calls are included.

### Final evidence

- [complete] GitHub API reports `origin/main` matches local `main`, with 87 tracked tree entries including `.env`, `HANDOFF.md`, and `ros2_ws/src/guardian_core/package.xml`.
- [complete] WSL user services `guardian-core.service` and `guardian-dashboard.service` are active; `/guardian/safety_status` returns `NORMAL`, `mission_allowed=true`, and `speed_limit≈0.35`.
- [complete] Windows `http://127.0.0.1:8088/api/health` returns HTTP 200 and `/api/state` reports NORMAL safety/risk state with a live timeline.

## Current heartbeat: strict evidence trust flags (2026-09-24 06:00 CST)

- [complete] Reproduce non-Boolean evidence flags passing ledger validation and ancestor checks before Jev judgment.
- [complete] Require native Boolean `verified` and `hard_stop` at construction and append; validate imported/rehashed records without changing valid Boolean behavior.
- [complete] Add an offline session lineage experiment, run focused/full tests, all five offline scripts and the ROS 2 build, review locally, update handoff/progress/findings, and commit locally on main.
- Reference: inspected `python-jsonschema/jsonschema` `_types.is_bool`, which accepts Boolean instances rather than coercing strings or integers. No dependency or source is imported.
- Scope: evidence trust flags and the existing Jev parent gate; no migration, credentials, provider calls or GitHub upload.

### Validation evidence: strict evidence trust flags

- [complete] Construction, append, live verification, export verification, parent lineage, and replacement checks reject non-native `verified`/`hard_stop` values before state mutation.
- [complete] Rehashed malformed-ancestor experiment returns `LEDGER_BLOCKED/CONTAINING`, performs zero provider calls, and rejects the export despite matching hashes.
- [complete] WSL2 `python3 -m pytest -q tests`: `168 passed`; Jev session, patent-core, all five offline scripts, ROS 2 Jazzy two-package build, Windows compileall/frontend syntax/diff/.env checks passed. A first Bash loop was replaced after a PowerShell variable-escaping syntax error; explicit reruns passed.
- [complete] Independent review is complete with no P0–P2 findings; local `main` commit is the final action and no GitHub upload is performed.

## Current heartbeat: advisor cache completion-time sampling (2026-09-24 05:00 CST)

- [complete] Reproduce a delayed advisor cache lookup reusing an expired assessment.
- [complete] Re-sample advisor TTL time under the cache lock and add the same boundary to the offline efficiency experiment.
- [complete] Run advisor/full tests, all experiments, ROS 2 build, review the diff, update handoff/progress/findings, and commit locally on main.
- Scope: existing Jev advisor cache timing only; no provider credentials, control changes, or GitHub push.

## Validation evidence: advisor cache completion-time sampling

- [complete] Red/green regression: `1 failed` before the lock-time fix, `1 passed` after it.
- [complete] `run_jev_efficiency_experiments.py`: advisor expired-cache race returns `OK` with two provider calls.
- [complete] Full WSL2 test suite, all offline experiments, ROS 2 Jazzy build, final review, and local commit.

## Final validation evidence: advisor cache completion-time sampling

- WSL2 `Ubuntu-24.04` `python3 -m pytest -q tests`: `149 passed`.
- Advisor cache regression and efficiency regressions pass; efficiency experiment reports advisor expired-cache `OK` with two provider calls.
- All four offline experiment suites passed; ROS 2 Jazzy `guardian_interfaces` and `guardian_core` built successfully.
- Windows compileall, frontend `node --check`, `git diff --check`, and tracked `.env` check passed.
- Independent review is the final pre-commit check; local `main` commit follows after staging this record.

## Current heartbeat: concurrent Jev budget/cache rollover (2026-09-24 04:00 CST)

- [complete] Reproduce an older concurrent request resetting a newer budget window after its pre-lock time sample is delayed.
- [complete] Keep the reservation window monotonic without widening provider locks or changing the configured budget algorithm; verify exhaustion and the next legitimate reset.
- [complete] Extend the offline efficiency experiment, run relevant/full tests and ROS 2 build, review the diff, update handoff/progress/findings, and commit locally on main.
- Reference: inspected Go `golang/time/rate` reservation/advance handling (https://github.com/golang/time/blob/master/rate/rate.go); different token-bucket algorithm, reference only, no copied code or new dependency.
- Scope: existing Jev advisory cache and call budget only; no external provider calls or GitHub push.

## Validation evidence: concurrent Jev budget/cache rollover

- [complete] Red/green regression: `2 failed` before the lock-time fix, `2 passed` after it.
- [complete] Red/green cache-lifetime regression: `1 failed` before the lock-time fix, `1 passed` after it.
- [complete] `tests/test_jev_efficiency.py`: `25 passed`; `run_jev_efficiency_experiments.py`: passed with budget routes `REMOTE`, `BUDGET_EXHAUSTED`, `BUDGET_EXHAUSTED`, `REMOTE` and expired-cache route `REMOTE`.
- [complete] Full WSL2 test suite, all offline experiments, ROS 2 Jazzy build, final review, and local commit.

## Final validation evidence: concurrent Jev budget/cache rollover

- WSL2 `Ubuntu-24.04` `python3 -m pytest -q tests`: `147 passed`.
- All four offline experiment suites passed; the efficiency experiment reports the budget routes `REMOTE`, `BUDGET_EXHAUSTED`, `BUDGET_EXHAUSTED`, `REMOTE` and expired-cache route `REMOTE`.
- ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` finished successfully.
- Windows `compileall`, frontend `node --check`, `git diff --check`, and tracked `.env` check: passed.
- Independent review: no P0–P2 findings. Local `main` commit follows after staging this record.

## Current heartbeat: validate parent lifetime after judgment (2026-09-24 02:00 CST)

- [complete] Reproduce expiry during provider execution and parent invalidation on failed provider results.
- [complete] Sample elapsed session-clock time after judgment; validate all results against an active parent before transition/append in the short ledger transaction.
- [complete] Keep soft TTL anchored to the request observation; translate elapsed time for explicit replay timestamps and preserve valid delayed responses.
- [complete] Add an offline delayed-provider scenario, run relevant/full tests, all experiments, ROS 2 build, syntax/diff checks, update HANDOFF/progress/findings, obtain review, and commit locally on main.
- Scope: existing advisory session only. No live API, credentials, control changes, database migrations, or GitHub push.

## Validation evidence: completion-time parent validation

- [complete] Session timing/integrity regressions: `47 passed`.
- [complete] `run_jev_session_experiments.py`: delayed parent expires during provider call and returns `LEDGER_BLOCKED/CONTAINING` without soft evidence.
- [complete] Full WSL2 test suite, all offline experiments, ROS 2 Jazzy build, frontend syntax, diff check, `.env` tracking, and independent review.

## Final validation evidence: completion-time parent validation

- WSL2 `Ubuntu-24.04` `python3 -m pytest -q tests`: `145 passed`.
- `run_jev_session_experiments.py`, `run_jev_efficiency_experiments.py`, `run_innovation_experiments.py`, and `run_patent_innovation_experiments.py`: all passed; delayed parent evidence returned `LEDGER_BLOCKED/CONTAINING` with one provider call.
- ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` finished successfully.
- Windows `compileall`, frontend `node --check`, `git diff --check`, and tracked `.env` check: passed.
- Independent review: no P0–P2 findings. Local `main` commit recorded after validation.


## Current heartbeat: preserve Jev outcomes across reuse (2026-09-24 01:00 CST)

- [complete] Reproduce failed single-flight results being promoted to `CACHED` and cache hits dropping disagreement flags with deterministic tests.
- [complete] Preserve non-success assessment status/reason, mark shared failures `UNAVAILABLE`, and recompute disagreements against each caller's local triage.
- [complete] Verify session review behavior and an offline disagreement comparison, then run full tests, experiments, ROS 2 build, and final diff review.
- [complete] Update HANDOFF/progress/findings and commit locally on `main`; no GitHub push or live provider calls.
- Reference checked: Go `golang/sync/singleflight` returns `val`, `err`, and `shared` independently (https://github.com/golang/sync/blob/master/singleflight/singleflight.go). No external code or dependency is imported.

## Validation evidence: Jev reuse outcomes

- [complete] Targeted failure/success/cache/session regressions: `54 passed`.
- [complete] Full WSL2 test suite, all offline experiments, ROS 2 Jazzy build, frontend syntax, diff check, `.env` tracking, review and local commit.

## Final validation evidence: Jev reuse outcomes

- WSL2 `python3 -m pytest -q tests`: `130 passed`.
- Jev session, efficient judgment, original innovation, and patent innovation experiments: all passed.
- WSL2 ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` finished successfully.
- Windows `compileall`, frontend `node --check`, `git diff --check`, and tracked `.env` check: passed.

## Current heartbeat: layered Jev cache lease hardening (2026-09-24 00:00 CST)

- [complete] Reproduce upper-layer TTL renewal from a lower-layer advisor `CACHED` result.
- [complete] Require a fresh advisor `OK` result before starting a new efficient-judge cache lease.
- [complete] Run full validation, update handoff files, obtain review, and commit locally on `main`.
- Scope: Jev advisory cache semantics only; no external API calls, ROS 2 control changes, or GitHub push.

## Validation evidence: layered Jev cache lease hardening

- [complete] Targeted regression and Jev advisor/efficient-judge tests: `24 passed`.
- [complete] Full WSL2 test suite, all offline experiments, ROS 2 Jazzy build, frontend syntax, diff check, `.env` tracking, review and local commit.

## Final validation evidence: layered Jev cache lease hardening

- WSL2 `python3 -m pytest -q tests`: `119 passed`.
- Jev session, efficient judgment, original innovation, and patent innovation experiments: all passed.
- WSL2 ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` finished successfully.
- Windows `compileall`, frontend `node --check`, `git diff --check`, and tracked `.env` check: passed.

## Current heartbeat: Jev adapter clock hardening (2026-09-23 23:00 CST)

- [complete] Reproduce invalid/non-finite and finite rollback clocks at the advisor and efficient-judge boundaries.
- [complete] Add failing regressions for finite audit timestamps, cache leases, latency, and budget timing.
- [complete] Implement finite non-decreasing clock reads, run full validation, update handoff files, and commit locally on `main`.
- Scope: Jev advisory timing only; no external API calls, ROS 2 control changes, or GitHub push.

## Validation evidence: Jev adapter clock hardening

- [complete] Targeted advisor/efficient-judge tests: `22 passed`.
- [complete] Full WSL2 test suite, all offline experiments, ROS 2 Jazzy build, frontend syntax, diff check, `.env` tracking, review and local commit.

## Final validation evidence: Jev adapter clock hardening

- WSL2 `python3 -m pytest -q tests`: `118 passed`.
- Jev session, efficient judgment, original innovation, and patent innovation experiments: all passed.
- WSL2 ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` finished successfully.
- Windows `compileall`, frontend `node --check`, `git diff --check`, and tracked `.env` check: passed.

## Current heartbeat: soft-evidence lifetime and live parent binding (2026-09-23 22:00 CST)

- [complete] Reproduce cached parent-rebinding TTL renewal and reuse of expired/superseded parent evidence.
- [complete] Keep the original soft-evidence deadline when rebinding cached advice; require an active, policy-matching parent before judgment and append.
- [complete] Run targeted/full tests and ROS 2 build, update HANDOFF and commit locally on main.
- Scope: existing advisory library only; no external API calls or GitHub push. An attempted read of cachetools TTLCache source timed out; no external implementation is imported.

## Validation evidence: parent-evidence lifetime (2026-09-23)

- [complete] Add focused tests for missing, future, expired, unverified, cross-policy, superseded and ancestor-expired parents, parent replacement during provider calls, cached rebind lease preservation, and expired-cache non-renewal.
- [complete] Extend `experiments/run_jev_session_experiments.py` with a deterministic parent rebind and lease-expiry comparison.
- [complete] Run WSL2 targeted/full pytest, session/efficiency/innovation/patent experiments, ROS 2 Jazzy build, frontend syntax, diff check, and tracked `.env` check.

## Final validation evidence: parent-evidence lifetime (2026-09-23)

- WSL2 `python3 -m pytest -q tests`: `114 passed`.
- `run_jev_session_experiments.py`: passed; 1 provider call for the parent rebind, original and rebound lease deadlines both `5.0`, no active soft evidence at the deadline.
- `run_jev_efficiency_experiments.py`, `run_innovation_experiments.py`, and `run_patent_innovation_experiments.py`: all passed.
- WSL2 ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` finished successfully.
- Windows `compileall`, frontend `node --check`, `git diff --check`, and tracked `.env` check: passed.

## Monotonic session-time hardening (2026-09-23)

- [complete] Reproduce finite timestamp rollback and TTL/query-interval corruption.
- [complete] Clamp each observation to the current session `last_seen` before state or ledger updates.
- [complete] Run full tests, experiments, compile checks, ROS 2 build, and handoff updates before the local `main` commit.

## Validation evidence: monotonic session time (2026-09-23)

- Timestamp rollback regression passed.
- `python3 -m pytest -q tests`: `100 passed`.
- Session, efficient Jev, original innovation, and patent innovation experiments, compileall, ROS 2 build, frontend syntax, and diff check passed.

## Observation-time input hardening (2026-09-23)

- [complete] Reproduce malformed explicit timestamp failure in `JevIncidentSession.observe`.
- [complete] Fall back to the injected clock for invalid/non-finite values and retain a finite final fallback.
- [complete] Run tests, experiments, compile checks, ROS 2 build, and handoff updates before the local `main` commit.

## Validation evidence: observation-time input (2026-09-23)

- Invalid-time regression passed.
- `python3 -m pytest -q tests`: `99 passed`.
- Session, efficient Jev, original innovation, and patent innovation experiments, compileall, ROS 2 build, frontend syntax, and diff check passed.

## Direct Jev advisor provenance hardening (2026-09-23)

- [complete] Reproduce truthiness-based `source_verified` transport bypass at the base advisor API.
- [complete] Require a native Boolean `True` before advisor configuration, cache, or transport handling.
- [complete] Run full tests, experiments, compile checks, ROS 2 build, and handoff updates before the local `main` commit.

## Validation evidence: direct advisor provenance (2026-09-23)

- Direct non-Boolean source regression passed with zero transport calls.
- `python3 -m pytest -q tests`: `98 passed`.
- Session, efficient Jev, original innovation, and patent innovation experiments passed; compileall passed.

## Strict source-verification hardening (2026-09-23)

- [complete] Reproduce the non-boolean `source_verified` session-reuse bypass.
- [complete] Preserve strict boolean provenance in the session signature and fail closed through `SKIPPED_UNVERIFIED`.
- [complete] Re-run tests, experiments, compile checks, ROS 2 build, and documentation verification before the local `main` commit.

## Validation evidence: strict source verification (2026-09-23)

- Source-type regression passed.
- `python3 -m pytest -q tests`: `97 passed`.
- Session, efficient Jev, original innovation, and patent innovation experiments passed; compileall passed.
- ROS 2 Jazzy `colcon build --symlink-install`, frontend `node --check`, and `git diff --check` passed.

## Bounded Jev session context hardening (2026-09-23)

- [complete] Reproduce oversized summary and context-tail behavior with a focused regression.
- [complete] Reuse `SemanticContext.to_state()` bounds and normalization for session identity and query signatures.
- [complete] Re-run the full test, experiment, compile, and ROS 2 validation set; update handoff before the local `main` commit.

## Validation evidence: bounded session context (2026-09-23)

- Bounded-context regression passed.
- `python3 -m pytest -q tests`: `96 passed`.
- Session, efficient Jev, original innovation, and patent innovation experiments passed.
- WSL2 Python compileall passed; ROS 2 build and frontend syntax check remain part of the final validation pass.

## Review hardening: Jev incident sessions (2026-09-23)

- [complete] Reproduce same-session concurrency, ledger capacity, numeric semantic, and parent-rebind failures with focused tests.
- [complete] Serialize one session without blocking independent sessions; enforce `max_sessions` on every write path.
- [complete] Include all normalized semantic inputs and parent evidence identity in the query signature.
- [complete] Rebind cached successful advice only when the parent evidence changes; preserve soft-evidence TTL semantics for ordinary reuse.
- [complete] Serialize only the ledger `verify()+append()` transaction across independent sessions, without holding a lock during provider calls.
- [complete] Run the complete test suite, experiments, compileall, and documentation checks; keep work local on `main`.

## Validation evidence: Jev review hardening (2026-09-23)

- `tests/test_jev_incident_session.py`: `13 passed`.
- `python3 -m pytest -q tests`: `95 passed`.
- Session, efficient Jev, original innovation, and patent innovation experiments: all reported `passed: true`.
- WSL2 Python compileall: passed.

## Current task: Jev incident session and ledger binding (2026-09-23)

- [complete] Specify and test incident aggregation, hysteresis, query gating, and bounded session expiry.
- [complete] Bind successful Jev advice to verified parent evidence as short-lived soft ledger records.
- [complete] Add burst/oscillation/provider-fault experiments and document the patent distinction.
- [complete] Run full validation and update HANDOFF; do not push GitHub in this task.

## Validation evidence: Jev incident sessions (2026-09-23)

- WSL2 `python3 -m pytest -q tests`: `90 passed`.
- `tests/test_jev_incident_session.py`: 8 passed; `tests/test_jev_efficiency.py`: 9 passed.
- `run_jev_session_experiments.py`, `run_jev_efficiency_experiments.py`, `run_innovation_experiments.py`, and `run_patent_innovation_experiments.py`: passed.
- Bundled Python `compileall`, frontend `node --check`, and `git diff --check`: passed.
- WSL2 ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` built successfully.

## Current task: efficient Jev judgment orchestration (2026-09-23)

- [complete] Specify and test local triage, stable incident fingerprints, single-flight deduplication, bounded cache/budget, and quality metrics.
- [complete] Implement the efficient judgment layer while preserving `JevSemanticAdvisor` and dashboard compatibility.
- [complete] Add deterministic efficiency comparisons and document API/key boundaries.
- [complete] Run full tests, experiments, compile checks, ROS 2 build, review, and update HANDOFF before committing on `main`.

## Validation issue

- An earlier attempt returned `Wsl/Service/E_ACCESSDENIED`; WSL2 is now available and the commands above have completed successfully.

## Current validation evidence

- 9 new Jev efficiency behavior tests passed by direct invocation with the bundled Python runtime.
- `compileall`, frontend `node --check`, and `git diff --check` passed.
- `run_jev_efficiency_experiments.py`, `run_innovation_experiments.py`, and `run_patent_innovation_experiments.py` passed.
- Full pytest and current ROS 2 build are complete; see the validation evidence above.

## Approved design decision

Use an offline-first `JevEfficientJudge` orchestration layer. Deterministic local policy remains authoritative for safety; Jev is called only for verified, semantically ambiguous incidents. Stable fingerprints exclude event IDs and sequence counters so repeated observations can reuse results. Concurrent identical requests use single-flight coalescing, while TTL/LRU cache and a configurable call budget bound provider usage. Critical local risk is enforced immediately and Jev may only add asynchronous explanation metadata.

## Current task: provenance-bound predictive safety research (2026-09-23)

- [complete] Implement the user-approved architecture in docs/patent_implementation_plan.md.
- [complete] Test graph provenance, evidence integrity, predictive braking and two-phase recovery.
- [complete] Run controlled comparisons; prepare technical disclosure with implementation mapping.
- [complete] Run full verification, update HANDOFF, and create the main commit.

## Verification record: provenance-bound predictive safety research (2026-09-23)

- [complete] Implement the user-approved architecture in `docs/patent_implementation_plan.md`.
- [complete] Test graph provenance, evidence integrity, predictive braking and two-phase recovery.
- [complete] Run controlled comparisons; prepare technical disclosure with implementation mapping.
- [complete] Fix review findings for stale recovery proofs, proof-ID replay, and exported-ledger lineage validation.
- [complete] Validate WSL2/ROS 2 and update handoff before the `main` commit.

## Current validation evidence

- WSL2 `python3 -m pytest -q tests/test_patent_core.py`: `38 passed`.
- WSL2 `python3 -m pytest -q tests`: `73 passed`.
- `experiments/run_innovation_experiments.py`: 6 groups passed.
- `experiments/run_patent_innovation_experiments.py`: 5 groups passed.
- Windows `compileall`, frontend `node --check`, and `git diff --check`: passed.
- WSL2 ROS 2 Jazzy `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` built successfully.

## Current task: optional Jev semantic security advisor

- [complete] Define a bounded, fail-safe Jev integration that cannot directly actuate or release the robot.
- [complete] Add red tests for request construction, response normalization, timeout/error fallback, and bounded evidence.
- [complete] Implement the optional advisor with standard-library HTTP transport and no mandatory runtime dependency.
- [complete] Add offline replay/experiment coverage and document configuration, privacy, and safety boundaries.
- [complete] Run Python tests, innovation experiments, ROS 2 build/smoke checks where available, and update handoff artifacts.

## Current validation evidence

- WSL2 `python3 -m pytest -q tests`: `23 passed`.
- WSL2 `python3 experiments/run_innovation_experiments.py`: 6 deterministic groups passed, including `jev_semantic_advisor` with a stub provider.
- Windows `python -m compileall -q ros2_ws/src/guardian_core/guardian_core tests/test_jev_advisor.py`: passed.
- WSL2 `colcon build --symlink-install`: `guardian_interfaces` and `guardian_core` built successfully.

## Current design decision

Jev is an advisory semantic evidence source after deterministic event verification and before any future, explicitly enabled evidence-fusion policy. The default path remains rule-only. A Jev result may inform review/containment analysis, but it cannot clear a verified violation, release `SAFE_STOP`, or directly publish a robot command. Network failures, malformed responses, low confidence, and missing configuration are ignored by the deterministic safety path.

## Current task: ROS 2 security dashboard and GitHub delivery

- [complete] Inspect existing repository and preserve `.env` in Git.
- [complete] Review open-source ROS 2 security and intrusion-detection projects.
- [complete] Add read-only web dashboard and ROS 2 state bridge.
- [complete] Add dashboard launch/entry points and documentation.
- [complete] Build, test, and verify browser/API behavior.
- [complete] Authenticate with a user-provided GitHub token and publish `main`.

## Design decision

Use a standard-library Python HTTP server inside `guardian_core`. It subscribes to
the existing ROS 2 state topics and exposes `/api/state`; a static HTML/CSS/JS
dashboard polls that endpoint. This keeps the laptop deployment lightweight and
avoids adding a Node/FastAPI dependency while preserving a clear upgrade path.

## Delivery

The public repository is `https://github.com/thy10086/ros2-resilience-guardian`.
The `main` branch contains the complete local tree, including the tracked `.env`.

## Current task: dashboard Jev connection test

- [complete] Review the current dashboard, official TypeSafe API contract, and comparable open-source clients.
- [complete] Add red tests for request validation, bounded proxy behavior, upstream failures, and credential non-disclosure.
- [complete] Implement a local `/api/jev/test` proxy using the existing `JevSemanticAdvisor` without persisting the submitted key.
- [complete] Add the desktop Jev test panel with loading, connected, unavailable, invalid, and clear states.
- [complete] Run unit, compile, ROS 2 build, and real-browser smoke validation with a deterministic local fake transport.
- [complete] Update documentation and handoff, commit, push `main`, and verify the remote tree.

## Jev dashboard design decision

The browser sends a short test state and an API key to the local dashboard only.
The dashboard forwards the request to the configured, allowlisted HTTPS
TypeSafe endpoint (official by default) and
returns bounded normalized assessment metadata. The key is never placed in
`.env`, local/session storage, ROS messages, audit data, or logs. The endpoint
is a manual advisory test path and cannot change Guardian safety state or robot
commands. The browser does not call TypeSafe directly because the service
rejects the dashboard origin through CORS.

## Innovation validation

- [complete] Add deterministic experiments for zero-trust event verification, stale-plan replacement, safety-state gating, dashboard state aggregation, and audit logging.
- [complete] Record evidence and limitations in `docs/innovation_validation.md` and `HANDOFF.md`.
- [complete] Add detailed explanations for current experiments and a staged cross-layer fusion experiment plan.
- [complete] Implement pure Python graph propagation, temporal policy, evidence fusion, safety envelope and recovery gate.
- [complete] Add and validate the cross-layer fusion experiment; document the ROS 2 integration boundary.
