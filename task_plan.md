# Implementation plan

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

## Innovation validation

- [complete] Add deterministic experiments for zero-trust event verification, stale-plan replacement, safety-state gating, dashboard state aggregation, and audit logging.
- [complete] Record evidence and limitations in `docs/innovation_validation.md` and `HANDOFF.md`.
- [complete] Add detailed explanations for current experiments and a staged cross-layer fusion experiment plan.
- [complete] Implement pure Python graph propagation, temporal policy, evidence fusion, safety envelope and recovery gate.
- [complete] Add and validate the cross-layer fusion experiment; document the ROS 2 integration boundary.
