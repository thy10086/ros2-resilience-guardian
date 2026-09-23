# Jev semantic security advisor

## Purpose

`guardian_core.jev_advisor` is an optional semantic side-channel for the ROS 2
Resilience Guardian. It sends a small, allowlisted incident summary to TypeSafe
Jev and normalizes the response into bounded attack classification, mission
impact, confidence, and human-review advice.

The advisor is disabled by default and does not replace `EventVerifier`,
`RiskEngine`, `MitigationPlanner`, `SafetySupervisor`, `EvidenceFusion`, or
`RecoveryGate`.

## Efficient judgment layer

`guardian_core.jev_efficiency.JevEfficientJudge` wraps the advisor for event
streams. It applies deterministic local triage before any provider call:

- verified low-risk events in `NORMAL` state use `LOCAL_SAFE` and do not call
  Jev;
- deterministic critical risk uses `LOCAL_ENFORCED` immediately and does not
  wait for a semantic provider;
- only verified, semantically ambiguous events use the bounded Jev path.

Non-boolean verification flags, non-finite/out-of-range risk values, and
malformed temporal evidence fail closed into local enforcement or unverified
skipping; they are never normalized into a safe remote request.

The base advisor applies the same strict provenance rule: only a native Boolean
`True` can pass `source_verified`. `False` and every non-Boolean value return
`SKIPPED_UNVERIFIED` before cache or transport handling.

For ambiguous events, the layer removes event ID and sequence counters from a
stable incident fingerprint, retains model and policy version, and normalizes
component/code ordering. The fingerprint is used for a bounded TTL/LRU cache.
Concurrent requests with the same fingerprint share one provider call through
single-flight coalescing. A rolling call budget returns a deterministic local
fallback when the provider budget is exhausted. The output includes route,
local score, optional normalized Jev advice, disagreement metadata, and
bounded P50/P95 latency and call-efficiency counters.

The local route is authoritative for safety. `DISAGREEMENT` is an explanation
flag only; a Jev answer cannot clear `SAFE_STOP`, raise a speed limit, or
approve recovery. The offline comparison is reproducible with:

```bash
python3 experiments/run_jev_efficiency_experiments.py
```

It compares the existing sequence-sensitive advisor cache with the stable
fingerprint layer. A real API key is not required for this experiment.

## Safety boundary

The current implementation is intentionally a library and offline experiment;
it is not called from the 100 ms `guardian_node` timer or an ROS subscription
callback. A future live adapter must call it asynchronously when the verified
event-set signature changes.

The following rules are part of the contract:

- An event that failed source, timestamp, sequence, replay, or signature checks
  is never sent to Jev.
- Jev cannot publish a ROS command, set `mission_allowed`, increase a speed
  limit, clear an active attack, release `SAFE_STOP`, or approve recovery.
- Network errors, timeouts, invalid responses, expired results, and missing keys
  fall back to the deterministic Guardian path. Callers must apply a confidence
  threshold to advice before treating it as a soft review signal; the current
  adapter does not feed low-confidence results into a safety decision.
- A result can recommend human review or provide soft evidence for a later,
  explicitly configured fusion policy. That policy is not enabled by this
  change.

## Request and response

The adapter uses the TypeSafe HTTP endpoint once per uncached context:

```text
POST https://api.typesafe.ai/v1/systemone
```

It asks three typed questions: `attack_type` (`Choice`), `mission_impact`
(`Choice`), and `needs_human_review` (`Noul`). The response is reduced to a
`JevAssessment`; raw responses and credentials are never included in its audit
payload.

The cache key includes the model and the complete normalized context, including
the event sequence. A new event sequence therefore cannot reuse an old result.

The advisor and efficient judge use a finite, non-decreasing injected clock for
cache expiry, call budgets, latency metrics, and `observed_at`/`expires_at`.
Malformed, NaN, or infinite clock values fall back to the last valid value (or
`0.0` on first use), and a clock rollback is clamped. This keeps an adapter
clock fault from rewinding a lease, creating negative latency, or prematurely
resetting a provider budget.

The efficient judge re-samples its clock while holding the cache/reservation
lock. A request paused after cache lookup therefore cannot use an older
timestamp to revive an expired cache entry or reset a newer fixed budget
window; a legitimate cache miss or budget reset occurs only when a later
request reaches the corresponding locked boundary.

The two cache layers have separate lease ownership. The efficient judge only
starts a new efficient-layer TTL from a fresh advisor `OK` response. An advisor
`CACHED` response can be observed after the efficient cache expires, but it is
never written back as a new efficient-cache lease; otherwise a lower cache
could keep the upper cache alive indefinitely without a new provider result.

Single-flight followers preserve the owner's assessment status and reason when
the owner failed; only usable `OK`/`CACHED` advice is marked `COALESCED` and
relabelled `CACHED`. Cache hits recompute the local-vs-Jev disagreement for the
current caller, so a conflict remains reviewable across event IDs.

## Dashboard connection test

The local dashboard exposes a manual, advisory proxy at:

```text
POST http://127.0.0.1:8080/api/jev/test
Content-Type: application/json
```

The request body is a short-lived JSON object:

```json
{"api_key":"<your TypeSafe key>","state":"verified high-rate command anomaly"}
```

The dashboard forwards the state to the configured HTTPS TypeSafe endpoint and
returns only normalized assessment metadata. Production defaults use the fixed
official endpoint; non-official hosts are rejected, and HTTP is accepted only
for explicit localhost test transports. A successful response has HTTP 200 and includes
`status: "OK"`, `connected: true`, `assessment`, and `latency_ms`. Invalid input
returns 400 (or 413 when the body exceeds 64 KiB); an upstream rejection or
malformed provider response returns 502; a timeout returns 504. The state text is
limited to 4096 characters.

The browser never calls TypeSafe directly. TypeSafe rejects the local dashboard
origin through its CORS policy, so the standard-library dashboard proxy keeps the
API key in the local request and the provider `Authorization` header. The key is
not placed in `.env`, browser storage, ROS messages, audit records, responses, or
logs, and the dashboard does not retain it after the request. The panel is a
connectivity and semantic-advice check only: its result cannot change a Guardian
safety state, speed limit, recovery decision, or robot command.

## Python usage

The TypeSafe SDK is not a package dependency. The adapter uses the standard
library, so the ROS 2 package and offline tests work without network access or
an installed SDK.

```python
from guardian_core import JevAdvisorConfig, JevSemanticAdvisor, SemanticContext

advisor = JevSemanticAdvisor(
    JevAdvisorConfig(
        enabled=True,
        api_key="read-this-from-a-local-secret-store",
        timeout_sec=1.5,
    )
)

assessment = advisor.evaluate(SemanticContext(
    event_id="event-17",
    component="nav",
    attack_type="UNSAFE_COMMAND",
    event_confidence=0.9,
    source_verified=True,
    temporal_codes=("REPLAY",),
    graph_risk=0.81,
    mission_criticality=0.9,
    active_components=("nav", "base"),
    safety_state="CONTAINING",
    sequence=17,
    summary="verified command anomaly",
))

if assessment.recommends_review():
    print("queue human review", assessment.audit_payload())
```

Do not send raw sensor streams, credentials, signatures, or unredacted logs.
The context class only serializes bounded fields and redacts common secret
patterns in the summary. API keys must stay outside source control and outside
the dashboard frontend.

## Configuration defaults

The tracked `.env` contains only disabled, non-secret defaults. The dashboard
reads the endpoint, model, and timeout as ROS parameters (with the corresponding
`JEV_*` environment values as defaults), but it never reads an API key from the
environment. The browser supplies a key for one manual test, and the dashboard
passes it to an explicit `JevAdvisorConfig` outside the control loop. The default
endpoint requires HTTPS; HTTP is accepted only for localhost test transports.

## Deterministic validation

The offline innovation suite uses a stub transport and does not call TypeSafe:

```bash
python3 -m pytest -q tests
python3 experiments/run_innovation_experiments.py
```

The `jev_semantic_advisor` experiment verifies a typed response, cache reuse,
source rejection, bounded scores, and an audit row. A live API smoke test is
deliberately not part of the default suite because Jev is an early-access
hosted service and network behavior is not deterministic. The dashboard proxy
contract is covered by `tests/test_dashboard_jev.py`; those tests use a fake
transport and verify request limits, 401/429/timeout mappings, malformed
responses, and key non-disclosure.
