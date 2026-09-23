# Implementation plan

## Current task: efficient Jev judgment orchestration (2026-09-23)

- [in_progress] Specify and test local triage, stable incident fingerprints, single-flight deduplication, bounded cache/budget, and quality metrics.
- [complete] Implement the efficient judgment layer while preserving `JevSemanticAdvisor` and dashboard compatibility.
- [complete] Add deterministic efficiency comparisons and document API/key boundaries.
- [in_progress] Run full tests, experiments, compile checks, ROS 2 build, review, and update HANDOFF before committing on `main`.

## Validation issue

- WSL2 test/build commands currently return `Wsl/Service/E_ACCESSDENIED` before starting Python. Retry after the WSL service is available; do not treat this as a test pass.

## Current validation evidence

- 9 new Jev efficiency behavior tests passed by direct invocation with the bundled Python runtime.
- `compileall`, frontend `node --check`, and `git diff --check` passed.
- `run_jev_efficiency_experiments.py`, `run_innovation_experiments.py`, and `run_patent_innovation_experiments.py` passed.
- Full pytest and current ROS 2 build remain pending until WSL service access is restored.

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
