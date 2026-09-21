# Findings

## Repository facts

- The project already has a ROS 2 Jazzy `guardian_node` publishing risk,
  mitigation, and safety messages.
- `.env` is intentionally tracked and contains safe defaults only; secret event
  keys remain commented out.
- The repository is on `main` with commit `0b6cbc5` and has no GitHub remote.

## Open-source references checked on 2026-09-18

- `rajavardhan28/IDS_ROS2`: ROS 2 intrusion-detection reference.
- `seergiromero/ROS2-Intrusion-Detection`: ROS 2 IDS experiments.
- `giacomozanatta/sros2-policy-clustering`: SROS 2 policy-management reference.
- `iotsrg/awesome-ros-security`: curated ROS security references.

The references provide useful detection and policy ideas but do not provide the
same mission-aware closed loop with risk scoring, mitigation planning, safety
states, and a local dashboard.

## Credential constraint

The existing SSH key is not authorized by GitHub (`Permission denied (publickey)`).
Pushing requires either adding its public key to the user's GitHub account or
providing a Personal Access Token for a one-time HTTPS push. Secrets must never
be committed or printed.

## Jev integration facts (2026-09-21)

- The user authorized autonomous implementation of an optional Jev semantic advisor.
- TypeSafe's official API is `POST https://api.typesafe.ai/v1/systemone`; the Python SDK is optional and should not become a hard dependency of the ROS 2 safety core.
- Jev is an early-access hosted service. It must not be placed in the real-time `/cmd_vel` path or become the sole basis for `SAFE_STOP` or recovery release.
- The existing project already has deterministic event verification, graph/fusion logic, and a final `SafetySupervisor`; the safest insertion point is a bounded advisory evidence adapter between verified event summaries and evidence fusion.
- Raw high-rate telemetry, credentials, and unredacted logs must not be sent to the external API. The adapter should accept a compact, caller-supplied incident summary and return normalized typed evidence.
- Final validation on 2026-09-21: 23 tests passed, six deterministic innovation groups passed, and both ROS 2 Jazzy packages built; live Jev accuracy, calibration, latency, cost, and availability remain unmeasured.
