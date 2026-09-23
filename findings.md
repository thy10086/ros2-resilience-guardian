# Findings

## Monotonic session-time closure (2026-09-23)

- Follow-up review found that a finite timestamp earlier than a session's `last_seen` could still move the record backward, extend its effective TTL, and create a negative query interval.
- Observations now clamp to the existing session `last_seen` before expiry and query decisions. Soft evidence and returned expiry timestamps therefore remain monotonic per session.
- Added a regression with `10.0` followed by `5.0`; the session keeps the `40.0` expiry and does not write `5.0`. Full validation now reports 100 passed.

## Observation-time input closure (2026-09-23)

- `JevIncidentSession` previously called `float(now)` directly. A malformed explicit timestamp could raise before ledger checks or local containment, allowing an input-driven denial of service.
- Observation time now uses the injected monotonic clock when the supplied value is invalid or non-finite, with `0.0` as the final fallback if the clock itself is unusable. Valid timestamps and TTL behavior are unchanged.
- Added a regression with `now="not-a-time"`; the decision completes normally and uses the trusted clock. Full validation after the fix reports 99 passed.

## Advisor provenance type closure (2026-09-23)

- Direct `JevSemanticAdvisor.evaluate()` previously used truthiness for `source_verified`, so a string such as `"false"` could pass the provenance gate and reach the remote transport.
- The advisor now requires `type(source_verified) is bool` and a true value before checking configuration, cache, or network transport. The efficient judge and incident session apply the same rule and fail closed.
- Added a direct-advisor regression proving a non-Boolean source returns `SKIPPED_UNVERIFIED` with zero transport calls. Full validation after the fix reports 98 passed.

## Strict source-verification closure (2026-09-23)

- Review found that `bool(context.source_verified)` collapsed the string `"false"` and integer `0` into the same signature as verified `True`. A previously verified session could therefore reuse an old Jev result during the minimum query interval.
- The normalized signature now stores only a native boolean or `None` for an invalid type. Any change from verified `True` to `False` or a non-boolean forces a fresh local decision; `SKIPPED_UNVERIFIED` transitions to `CONTAINING` and never calls the provider.
- Added a regression that starts with a verified observation and then supplies `source_verified="false"`; it confirms the old Jev result is not reused. The full suite now reports 97 passed.

## Jev incident session review closure (2026-09-23)

- Independent review found four P2 risks: same-session updates could race, ledger-blocked writes bypassed `max_sessions`, three normalized semantic values did not trigger a re-query, and parent evidence changes could reuse an old binding.
- The session manager now allocates a lock per session and serializes the complete decision path only for that session. The shared session map uses one bounded write-back helper for both normal and ledger-blocked paths, so LRU capacity is always enforced.
- The context signature now includes normalized `graph_risk`, `mission_criticality`, `event_confidence`, `source_verified`, and `parent_evidence_id`, while continuing to exclude event IDs, sequence numbers, and free-form summaries from incident identity.
- A parent change forces a new session decision. A cached successful Jev assessment may be rebound once to the new verified parent, while ordinary cache reuse never refreshes soft-evidence expiry. The advice remains `hard_stop=False` and Jev remains advisory-only.
- Regression coverage now includes deterministic two-thread same-session serialization, blocked-session capacity, numeric semantic changes, and parent rebinds. The session suite is 12 passed and the complete test suite is 94 passed after the fixes.

## Cross-session ledger integrity closure (2026-09-23)

- A second review found that independent session locks still allowed two different incidents to execute `EvidenceLedger.verify()` and `append()` concurrently. That could compute the same previous hash and invalidate the append-only chain, turning a concurrency burst into a system-wide `LEDGER_BLOCKED` condition.
- Added a short-lived manager-level ledger lock around the verification-plus-append transaction. It does not cover provider calls or local judgment, so independent incident sessions retain parallel query execution.
- Added a deterministic two-session concurrency test with an instrumented ledger; it proves appends do not overlap and the final chain verifies. The session suite is now 13 passed and the complete suite is 95 passed.

## Bounded session-context closure (2026-09-23)

- The remote advisor already bounded text and list fields, but the new session ID and context signature initially read raw values. A crafted long component, temporal code, or active-component list could therefore consume unbounded local CPU and memory before the request was sent.
- Session identity and query signatures now reuse `SemanticContext.to_state()` normalization, then apply the same sorting/deduplication and invalid-numeric markers used by session gating. Event IDs, sequence numbers, and summaries remain excluded.
- Added a regression with 10,000-character summaries and long temporal-code tails; the bounded prefix reuses the same session and provider call. The full suite now reports 96 passed after this hardening.

## Jev incident session design (2026-09-23)

- Approved next step: aggregate repeated verified contexts into an incident session before Jev advice is written to the ledger.
- Session state must be deterministic and fail-safe: `OBSERVING`, `REVIEW_REQUIRED`, `CONTAINING`, and `EXPIRED`; risk increases enter review immediately, while recovery from review requires a hysteresis margin and a stable window.
- A Jev result is soft evidence only. It must reference an existing verified parent evidence ID, use a distinct source (`jev`), have a short expiry, and never supersede or clear hard-stop evidence.
- Provider failures, malformed advice, budget exhaustion, and invalid context preserve deterministic local state and do not append a ledger record.
- Session review found two required fail-closed rules: ledger integrity must be checked before local-fast-path routing, and semantic context changes must force a new query even when the numeric risk is unchanged. Both are now enforced and covered by regression tests.

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

## Jev parent-evidence lifetime findings (2026-09-23)

- A parent ID alone is insufficient for a soft Jev lease: the parent must be active at the observation time, verified, policy-matching, non-Jev, and backed by a valid parent lineage. Missing, future, expired, unverified, superseded, cross-policy, or ancestor-expired parents now fail closed before the judge or provider is called.
- The parent is checked twice: once before semantic judgment and again inside the short ledger transaction. This closes the race where a verifier record is superseded while the provider is still running.
- Rebinding a cached successful result to a replacement parent is allowed only while the original soft-evidence deadline remains in the future. The replacement record inherits the absolute deadline; a cache hit after that deadline cannot renew or resurrect evidence. A fresh provider success is required for a new lease.
- The deterministic session experiment now reports the rebind deadline and verifies that the provider is called once, the replacement expires at the original deadline, and no Jev record remains active at that deadline.

## Jev adapter clock findings (2026-09-23)

- The session layer already protected observation timestamps, but the advisor and efficient judge still consumed their injected clocks directly. A malformed or non-finite value could enter `observed_at`, cache expiry, budget-window, or latency arithmetic; a finite clock rollback could shorten an advisor lease or create a negative elapsed interval.
- Both layers now keep a separate clock lock and clamp every read to a finite non-decreasing value. The first invalid read uses `0.0`; later invalid reads reuse the last valid value. This is an input-timing guard only and does not alter local safety triage.
- Regression tests cover a NaN-first advisor clock, advisor rollback, efficient-judge NaN timing, and efficient-judge rollback with cache reuse. Provider and control permissions are unchanged.

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
