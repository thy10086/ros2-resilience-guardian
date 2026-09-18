# Implementation plan

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
