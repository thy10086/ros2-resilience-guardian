# Findings

## Efficient Jev judgment design (2026-09-23)

- Current `JevSemanticAdvisor.evaluate` is synchronous and performs one provider call for every verified cache miss. Its cache key includes the event ID and sequence, so repeated observations from one incident commonly miss the cache.
- The existing adapter already bounds context, response size, timeout, endpoint scheme, and answer types. The new layer should compose it rather than change the provider contract or dashboard request path.
- Safety must remain deterministic: local risk and recovery rules cannot wait for Jev or be cleared by a Jev answer. Jev efficiency work is limited to triage, explanation, duplicate suppression, bounded provider use, and offline measurement.
- Approved design: local triage plus stable incident fingerprint, single-flight duplicate coalescing, TTL/LRU cache and call budget, disagreement metadata, and deterministic metrics. Real API testing remains optional and requires a user-provided temporary credential or endpoint override.

## Patent-oriented research (2026-09-23)

- User approved implementation of the proposed four-module architecture. Existing baseline is clean `e9c4932` on main, including Jev advisory and dashboard test features.
- Read official GitHub repository metadata and README for `ros2/sros2` (DDS-Security tooling) and `nickovic/rtamt` (online/offline STL monitoring); Nav2 metadata confirms the navigation framework. These existing building blocks are prior-art leads, not novelty clearance.
- Research scope: operational dependency paths, not statistically inferred causality; latency-aware stopping under an explicit 1-D braking model; recovery credentials bound to topology, policy, evidence anchor and command epoch.
- Public GitHub content predates this work. New disclosure must distinguish already-public features from the new combination; patent search and professional review remain necessary before filing.

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

## Dashboard Jev connection findings (2026-09-21)

- The official API is `POST https://api.typesafe.ai/v1/systemone` with a Bearer
  key, `state`, `model: "jev-latest"`, and typed questions. The response has
  `answers`, `model`, and optional `usage`.
- A browser request from the local dashboard origin is rejected by TypeSafe's
  CORS policy (`400 Disallowed CORS origin`), so the key must be sent to the
  local dashboard proxy rather than directly to the provider.
- GitHub repository search found community TypeSafe clients such as
  `lu-zero/systemone`, `dwisiswant0/typesafe-sdk-go`, and
  `Premo-Cloud/typesafe-sdk-java`; they confirm the endpoint/header contract
  but do not provide a ROS 2 dashboard integration. Existing ROS 2 references
  remain `rajavardhan28/IDS_ROS2` and `seergiromero/ROS2-Intrusion-Detection`.
- The UI contract is a manual `POST /api/jev/test` with `{api_key, state}`.
  Validation and response limits are enforced locally; upstream errors are
  mapped to bounded status messages and never echo request headers or keys.
- The dashboard transport disables automatic HTTP redirects, so an upstream
  redirect cannot carry the Authorization header to another host. API keys are
  restricted to printable ASCII before entering that header; state text keeps
  Unicode support and is still bounded/redacted by the advisor.

## Patent-core review closure (2026-09-23)

- Recovery authorization is bound to both the protocol state and the latest observation. A proof issued for `g1` is rejected after a `g2` observation, a failed observation, or any intervening observation, even if the caller presents an older observation within the proof TTL.
- `proof_id` is now included in the proof signature material, so replacing the identifier cannot bypass the one-time-use set.
- Export verification reconstructs the same parent and replacement constraints as in-memory verification. A hash-correct export with a missing parent, expired/unverified parent, cross-policy parent, or soft replacement of a hard-stop record is rejected.
- These closure tests are included in `tests/test_patent_core.py`; the final WSL2 run reported 73 total tests passing. The implementation remains a pure Python safety-core validation and does not imply cryptographic identity, DDS authorization, or physical actuator certification.
