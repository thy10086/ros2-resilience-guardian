# Review fixes and live agent adapter implementation plan

> **For agentic workers:** Use Superpowers TDD and independent review. User authorized the five review fixes and URL/API Key operation on 2026-10-19; continue the previously approved four-role architecture.

**Goal:** Fix R1–R5 and make the existing restricted graph usable with a configured OpenAI-compatible model from the detection page.

**Architecture:** Keep LangGraph and the fixed test catalog. A parent-side HTTP broker owns the credential; the network-denied coordinator requests typed role replies over inherited pipes. Test workers retain their existing restrictions. The authenticated dashboard submits one bounded asynchronous job and polls or cancels it.

**Spec:** `docs/superpowers/specs/2026-10-19-artex-ros2-agent-review-design.md`, phase 2/3, plus `docs/code_logic_review_2026-10-19.md` R1–R5.

## Constraints and decisions

- Preserve the dirty `codex/evidence-bound-recovery` workspace. Do not commit, publish, read stored credentials, or contact a robot.
- Fixture mode remains explicit; a live-provider error never falls back to fixture.
- Only the six existing tests may run. Model statements cannot alter Oracle results, source findings, permissions or recovery authorization.
- Reuse LangGraph, Python's HTTP client, dashboard authentication, fixed worker supervision and existing role contracts. No second general agent framework.
- Provider URL is explicitly chosen by the authenticated operator; allow HTTPS and explicit loopback HTTP, refuse embedded credentials, query strings, fragments and redirects. Never accept URLs from model output.
- Live budget: 180 s run deadline, 15 s per HTTP request, at most 16 calls and 12 test executions. Fixture budget remains 30 s. No automatic retry or hidden billable call.
- Do not persist the new Key or put it in reports, child environment, command line, browser storage or provider prompts.
- Validate a local HTTP protocol fixture first. Without user-supplied provider configuration, this proves integration, not real model quality.

## Tasks

- [x] R1/R2: Add regression tests for actuator lease expiry/replay and delayed acquisition evidence; implement monotonic execution leases and source freshness at use. Owned by `fix_execution_freshness`.
- [x] R3/R4: Reject incomplete imported frames; check authorized NORMAL output epoch. Add negative and healthy-trace regressions. Owned by `fix_trace_oracle`.
- [x] R5: Keep uploaded static targets and findings in the aggregate and nonzero CLI status, without calling static suspicion a confirmed runtime violation. Owned by `fix_static_aggregate`.
- [x] Provider: Local real HTTP tests must fail before adding `OpenAICompatibleProvider`; then check JSON/refusal/size/error/secret handling and no retries. Wire `complete(role, data)` through a credential-free coordinator pipe and preserve cancellation/deadline supervision.
- [x] Dashboard: Test authenticated create/get/cancel and session ownership, missing config and capacity; add one-job service and a detection-page form with URL, Key, model discovery/manual choice, sample or strict JSON input, run/cancel/download and explicit separate target verdicts.
- [x] Verify: Run feature regressions, full suite with correct Humble overlay, actual browser form/run/cancel/error checks using a labelled local protocol fixture. Obtain independent read-only review and fix findings. Save new validation receipts without overwriting old reports; update usage and handoff.

## Final verification — 2026-10-20

- Full suite: 874 passed /311.08s, zero failures/errors/skips; Humble build, compileall, JS syntax and whitespace checks passed.
- Independent scoped reviews verified frozen-clock high-water recovery, logout admission races and server-preserved report download.
- Four browser downloads, four registered executions independently rechecked against raw frames/witnesses and trace/artifact/context/plan/source identities. Receipt: `output/verification/live-verification-20261020.json`.
- Ruling: preserve downloaded number tokens on the server path — client JSON.stringify normalizes integral floats and invalidates the existing canonical digests. New authenticated report endpoint and raw-text Blob download are verified end-to-end.
- This completes implementation and local protocol validation. Real-provider model quality and equal-budget comparisons are future evaluations, not claims made by this delivery. Existing dirty branch preserved; no commit/push/deployment.
