# Progress

- 2026-09-24: Added the protection test workbench and its bounded replay endpoint. It maps event verification, attack registry, risk engine, mitigation planner and safety supervisor to a visible per-step table; no ROS 2 commands or Jev provider calls are made. The focused HTTP and pure replay regressions passed before deployment verification.

- 2026-09-24: Rebuilt `ros2_ws`, restarted `guardian-dashboard.service`, and verified deployed Key save/read/clear, five samples, and critical replay `CONTAINING/ISOLATE_COMPONENT/0.15 m/s`. Browser refresh now visibly shows the protection workbench, import buttons, flow mapping and results table. Full WSL2 suite passed `192 tests`; all offline experiments, ROS 2 build, frontend syntax, compileall, diff and `.env` checks passed. Local commit remains; no GitHub push or live Jev call.

- 2026-09-24: User reported missing import and successful Jev call followed by failed Key save. Reproduced stale browser document and authenticated deployed Key API 404; previous source tests did not verify process reload. Implementing a visible protection replay workflow and verifying deployment end to end.

- 2026-09-24: Final validation completed for the sample workflow. WSL2 dashboard integration tests passed `6 passed`, the full suite passed `175 passed`, both ROS 2 packages built successfully, all five offline experiment scripts passed, and Windows compileall/frontend syntax/diff/.env checks passed. The live local dashboard returned `/api/health` 200 and served the sample-file and saved-key controls. Existing ROS 2 build output included non-fatal compiler clock-skew warnings only. Changes are ready for a local `main` commit; no GitHub push or live Jev call was made.

- 2026-09-24: Added the dashboard sample-file workflow for local Jev experiments. TXT/LOG/CSV/JSON files are read in the browser with 64 KiB/4096-character bounds and are sent only after the user clicks “测试连接”. Added an HTTP integration regression covering login, session-only Key save, Jev test without an `api_key`, response redaction, clear, and fail-closed reuse. The focused dashboard authentication suite passes `6 passed`; full regression and ROS 2 build are next.

- 2026-09-24: Fixed the dashboard login input race: the one-second state poll was calling `showLogin()` on every unauthenticated 401 and clearing the password field while the user typed. The frontend now tracks authentication state and pauses `/api/state` polling until login succeeds; browser regression can type `admin/admin` and reach the dashboard.

- 2026-09-24: Revalidated the local dashboard after the login/runtime fix: WSL `python3 -m pytest -q tests` passed 171 tests, both selected ROS 2 packages built successfully, and the Windows 8088 smoke flow returned health 200, unauthenticated state 401, admin/admin login 200, authenticated state 200, and post-logout state 401. Added root-level colcon output ignores because the verification build was run from the repository root.

- 2026-09-24: Reproduced the user's 8088 failure: the WSL system was being reaped when no foreground WSL process remained, and stale user/system dashboard units overlapped. Added TDD coverage for local admin/admin sessions; authentication implementation and frontend gate are green. WSL system services now run without the duplicate user units, and a hidden `sleep infinity` process keeps the distro alive for Windows localhost forwarding.

- 2026-09-24: Started user-requested GitHub publication and local startup from clean main f5ac099. WSL Ubuntu-24.04 and the user service manager are available; port 8080 is already occupied, so select an unused local dashboard port and document the override. Windows gh is not installed; verify existing Git authentication before choosing a fallback.
- 2026-09-24: Local ROS 2 runtime is active through WSL user services `guardian-core.service` and `guardian-dashboard.service`; dashboard uses `127.0.0.1:8088`. ROS topics publish NORMAL safety state and Windows HTTP health check returns 200. GitHub API confirms stored Credential Manager authentication has push permission; publication is the remaining action after this documentation commit.
- 2026-09-24: Pushed `f628425f328709320f283a1d6d373577295dd392` to GitHub `origin/main`; GitHub tree contains 87 files including tracked `.env`. Final local smoke checks report both WSL services active, ROS `safety_status=NORMAL`, and Windows dashboard `/api/health` HTTP 200. This runtime uses port 8088 because 8080 was already occupied.
- 2026-09-24: Final documentation update is pushed to `origin/main`; remote and local `main` now match. The preceding runtime evidence remains valid.

- 2026-09-24 06:00 CST: Closed evidence trust-flag coercion. `Evidence` construction and ledger append/verify/export/lineage/replacement paths now require native Boolean `verified` and `hard_stop`; rehashed malformed ancestors cannot hide semantic corruption. New patent-core, Jev-session, and offline lineage regressions pass; the full suite reports `168 passed`, all offline experiments and ROS 2 Jazzy builds are green, and local `main` commit is the remaining final action.
- 2026-09-24 06:15 CST: Final rerun completed all five offline scripts (`run_guardian_scenario.py`, innovation, Jev efficiency, Jev session, and patent innovation) with `passed: true` where applicable. The first combined loop was rejected by Bash because PowerShell expanded the loop variable incorrectly; explicit script invocations passed, so no product defect was inferred.

- 2026-09-24: Added a realistic warehouse AMR pallet-transfer case. The fixture models `/cmd_vel` speed abuse, a repeated sequence replay, a subsequent unsafe command, and a `/gripper/command` semantic mismatch. The offline Guardian result is `ACCEPTED → REPLAY → ACCEPTED → ACCEPTED`, ending in `CONTAINING / ISOLATE_COMPONENT / 0.15 m/s`. Added `docs/warehouse_amr_case.md` with field mapping, Jev boundary, front-end import procedure, and research limitations; README now links the case and commands. Focused tests, full suite, ROS 2 build, static checks, and local commit remain to be executed.

- 2026-09-24: Validation completed for the warehouse case. Focused tests passed `2`; the industrial script reported `accepted=3/rejected=1`, `REPLAY` on the duplicate sequence, and final `CONTAINING / ISOLATE_COMPONENT / 0.15 m/s`. All five offline experiments passed, both ROS 2 packages built, and static/fixture/`.env` checks passed. A first full pytest run without sourcing ROS 2 failed at collection (`rclpy` and `guardian_interfaces` unavailable); the documented command now sources `/opt/ros/jazzy/setup.bash` and `ros2_ws/install/setup.bash`, after which the full suite passed `203 tests`.

- 2026-09-24: Committed the warehouse AMR industrial case, fixtures, tests, README and handoff updates to local `main` as `61e766a` (`feat: add warehouse AMR safety case`). No GitHub push was attempted.

- 2026-09-24: The dashboard health probe briefly refused connections while WSL had no foreground process; starting the documented hidden `sleep infinity` keepalive let systemd restart both ROS 2 services. Three HTTP health polls over 15 seconds returned `200`, confirming stable local runtime.

- 2026-09-24: Integrated the warehouse AMR case into the web protection laboratory. Added a first-class `warehouse_amr` sample with robot/mission/topic/threat metadata and bounded Jev context; the UI now renders an industrial case card, runs the existing replay endpoint, and transfers the Jev summary to the semantic page without changing Guardian state. Browser smoke verified login, built-in case selection, final `CONTAINING / ISOLATE_COMPONENT / 0.15 m/s`, and the Jev transfer message.

- 2026-09-24: Final regression for the web integration passed `204 tests`; ROS 2 packages rebuilt successfully, frontend/static and secret checks passed, and the deployed dashboard served the industrial card and replay after restart. The remaining action is the local `main` commit; no provider call or GitHub push is performed.

- 2026-09-24 05:00 CST: Closed the same delayed-cache timestamp race in `JevSemanticAdvisor`. The red regression reproduced an expired advisor assessment returning `CACHED`; cache expiry now re-samples the protected clock under `_cache_lock`, and the offline efficiency experiment confirms `OK` with two provider calls. Full validation reports `149 passed`, all four offline experiment suites and ROS 2 Jazzy build pass, Windows checks pass, and local commit is the remaining final action. The first full run needed a longer rollback-clock fixture because the new locked sample is intentional; the adjusted test passes.

- 2026-09-24 04:00 CST: Final validation for concurrent Jev budget/cache rollover passed: WSL2 full suite `147 passed`, all four offline experiment suites passed, ROS 2 Jazzy built both packages, Windows compileall/frontend syntax/diff/.env checks passed, and independent review found no P0–P2 findings. Local `main` commit is the remaining final action.

- 2026-09-24 04:00 CST: Closed concurrent budget and cache rollover. Deterministic two-thread regressions reproduced an older request resetting a newer fixed budget window and reviving an expired efficient-cache entry (`2 failed` and `1 failed` before the fixes). Cache expiry and reservation time now sample under the judge lock, and the provider cache lease uses the fresh reservation time. The focused regressions pass `3/3`, the Jev efficiency suite passes `25/25`, and the offline efficiency experiment verifies both the budget boundary and expired-cache race. An initial experiment fixture run failed because `context()` lacked a `summary` parameter; the fixture was corrected and rerun successfully. One combined pytest `-k` attempt also used invalid expression syntax and was rerun with a valid selector.

- 2026-09-24: Closed completion-time parent validation gaps. The session now measures elapsed provider time, revalidates parent lineage after every judgment result, blocks delayed writes after parent/ancestor expiry or replacement, and consumes remaining soft TTL for valid delayed advice without mixing explicit replay time with the internal clock. Added 15 timing/integrity regressions and delayed-parent experiment; session tests pass `47/47`. Full WSL2 validation reports `145 passed`, all four offline experiment suites pass, ROS 2 Jazzy builds both packages, and Windows compileall/frontend syntax/diff/.env checks pass. Independent review found no P0–P2 findings. The first generic WSL invocation failed because it selected stopped `docker-desktop` and had no `bash`; rerunning with `-d Ubuntu-24.04` passed.

- 2026-09-24: Fixed two reuse-result defects found by independent review. Single-flight followers now preserve failed Jev status/reason instead of promoting failures to `CACHED`; cache hits and followers recompute local-vs-Jev disagreement, preserving `REVIEW_REQUIRED`. Added failure, success, cache, and session regressions; Jev/session tests now pass `54/54`. WSL2 full tests report `130 passed`; all four offline experiment suites and the ROS 2 Jazzy two-package build pass. Independent review and local commit remain for this heartbeat.

- 2026-09-24: Independent review found layered-cache TTL renewal: `JevEfficientJudge` could re-cache an advisor `CACHED` result after its own TTL expired. Added a red/green regression and changed `_put_cache` to accept only fresh `OK` results. Jev advisor/efficient-judge tests now pass `24/24`; WSL2 full tests report `119 passed`, all four offline experiment suites and the ROS 2 Jazzy two-package build pass. Independent review and local commit remain for this heartbeat.

- 2026-09-23: Found and fixed direct clock handling in `JevSemanticAdvisor` and `JevEfficientJudge`. Invalid/non-finite clocks now fall back to the last finite value (or `0.0` initially), and finite rollback is clamped. Added four regressions; advisor/efficient-judge tests pass `22/22`. WSL2 full tests report `118 passed`; all four offline experiment suites and the ROS 2 Jazzy two-package build pass. Independent review is the final step before local commit.

- 2026-09-23: Closed the parent-evidence lifetime gap found during Jev session review. Active parent validation now runs before judgment and again during ledger append; cached parent rebinds inherit the original soft-evidence deadline, and expired cached advice cannot renew or resurrect a ledger record. Added parent expiry/replacement coverage and extended the deterministic session experiment. WSL2 full tests report `114 passed`; all four offline experiment suites and the ROS 2 Jazzy two-package build pass.

- 2026-09-23: Closed finite timestamp rollback after review. Session observations now clamp to `last_seen`; the rollback regression and full suite pass with `100 passed`, while all experiments and ROS 2 validation remain green.

- 2026-09-23: Hardened session observation-time parsing. Invalid or non-finite explicit timestamps now fall back to the injected clock instead of throwing; the regression, all experiments, and full suite pass with `99 passed`.

- 2026-09-23: Closed the same provenance type-confusion at the direct `JevSemanticAdvisor` boundary. Non-Boolean `source_verified` values are now rejected before cache/network handling; the direct-advisor regression and full suite pass with `98 passed`.

- 2026-09-23: Closed a source-verification type confusion found in review. Strict native-boolean handling now forces re-evaluation and `CONTAINING` for `False` or non-boolean values; the regression and full suite pass with `97 passed`.

- 2026-09-23: Hardened the Jev session boundary against oversized context fields. Session IDs and signatures now reuse the advisor's bounded `to_state()` representation, preserve invalid numeric markers, and exclude free-form summaries, event IDs, and sequence numbers. A long-input regression passed; full tests now report `96 passed`.

- 2026-09-23: Independent review of the Jev session layer found four P2 issues. Added per-session serialization, unified bounded session write-back, complete normalized semantic signatures, and parent-evidence-change rebind semantics.
- 2026-09-23: Added four regression tests for same-session concurrency, ledger-blocked capacity, mission/confidence-triggered re-query, and parent evidence rebinding. Red phase reproduced all four failures; the green phase passed session tests `12/12` and full tests `94 passed`.
- 2026-09-23: Session experiments, efficient Jev experiments, the six-group innovation suite, the five-group patent suite, and Python compileall all passed after review hardening. Development remains local on `main`; no GitHub push was made.
- 2026-09-23: Follow-up review found cross-session `EvidenceLedger.verify()+append()` could race. Added a manager-level ledger transaction lock and a two-session instrumented-ledger regression; session tests now pass `13/13` and full tests `95 passed`.

- 2026-09-23: User approved the next Jev depth phase: incident-session aggregation with short-lived soft evidence bound to the existing evidence ledger. Development starts offline without a real API or GitHub push.
- 2026-09-23: Added `JevIncidentSession` with incident aggregation, query throttling, risk/semantic-change triggers, review hysteresis, TTL expiry, and short-lived Jev evidence bound to verified parent records. Ledger integrity failures now block even local-fast-path observations.
- 2026-09-23: Session tests initially exposed missing ledger-wide fail-closed handling and semantic-context change detection; both were fixed. New session tests now pass 8/8, including tampered-ledger local path and same-risk temporal-code change.
- 2026-09-23: Final session-phase validation passed: full WSL2 suite `90 passed`; session and efficiency experiments, the original six-group innovation suite, and the five-group patent suite passed; compileall, frontend syntax, git diff check, and ROS 2 Jazzy two-package build passed.

- 2026-09-23: User approved the offline-first efficient Jev judgment design. Baseline inspection found synchronous per-event calls, sequence-sensitive cache keys, and no in-flight deduplication or provider budget; implementation starts with red tests and keeps Jev advisory-only.
- 2026-09-23: Added red contract tests for local fast paths, critical local enforcement, stable fingerprint reuse, single-flight coalescing, budget fallback, disagreement reporting, invalid-input fail-closed behavior, and provider-failure metrics. The first WSL2 invocation was blocked by `Wsl/Service/E_ACCESSDENIED`; no pytest result was produced by that invocation.
- 2026-09-23: Implemented `JevEfficientJudge`, `JevEfficiencyPolicy`, route/result types, bounded metrics, and the deterministic `run_jev_efficiency_experiments.py` comparison. Added exports and Jev documentation; Python execution remains pending until the WSL service is available again.
- 2026-09-23: Thread-bundled Python validation passed: the 9 new Jev efficiency tests passed by direct invocation, `compileall` passed, the Jev efficiency comparison passed with 12 baseline calls versus 1 efficient call (91.7% reduction), and the existing six-group and five-group innovation suites passed. Frontend syntax and `git diff --check` passed.
- 2026-09-23: Full pytest and ROS 2 colcon commands remain pending because WSL returns `Wsl/Service/E_ACCESSDENIED` before Python/colcon starts; the bundled runtime does not include pytest. No full-suite or current ROS 2 build result is claimed for this change.

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
# 2026-09-24 持久 Key 与 Jev 研究工作区

- 已确认工作区起点 f1bae00 / main 干净，dashboard/core 服务 active；本轮不上传。
- 已读取规划、调试、TDD、完成前验证技能及相关实现；复核开源类似项目。
- 正在补充持久凭据与对照实验的失败用例。

- 已实现 `JevKeyStore`：本机账号文件、0600/0700 权限、原子替换、拒绝 symlink/错误权限、失败不覆盖旧值；`DashboardAuth` 仅在认证请求内读取，logout 不删除持久记录。
- 已实现 `dashboard_research.py` 与 `/api/research/suite`；研究页显示重复事件、分流、未验证来源、超时、会话复用、父证据失效和五个 ROS 2 防护样例。
- 已完成桌面四页 hash 工作区，删除会话保存复选框，增加明确“保存 / 更新 Key”和“忘记已保存 Key”。
- 验证：定向凭据/研究/dashboard 测试 28 passed；全量 WSL2 `201 passed`；研究 suite 7/7；ROS 2 Jazzy `colcon build --symlink-install` 两包成功；Windows compileall、node check、diff check 成功。
- 真实 8088 HTTP：四个标签和研究 API 可见；合成 Key 保存后结束 dashboard 进程由 systemd 自动重启，重新登录仍显示 saved；清除后再次重启显示未保存。浏览器刷新工作区显示研究 7/7 PASS，Key 保存状态也验证后已清除。
- 本轮没有真实 Jev provider 调用、没有 GitHub push、没有写入系统环境变量或输出密钥；`.env` 仍受 Git 跟踪。
- 既有回归实验复核：`run_innovation_experiments.py`、`run_jev_efficiency_experiments.py`、`run_jev_session_experiments.py`、`run_patent_innovation_experiments.py` 均返回 `passed: true`；效率实验仍为基线 12 次→1 次、91.7% 减少，事件会话为 9 次复用，账本阻断和五组专利化实验均通过。
