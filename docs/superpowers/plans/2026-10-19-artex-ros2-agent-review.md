# ARTEX ROS 2 Agent Review — 第一阶段实施计划

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans task by task. 用户已确认本方案第一阶段；持续执行，不再逐项询问。不提交或推送。

**Goal:** 用明确标为 fixture 的四角色 LangGraph 流程，真实执行六项注册恢复场景、验证触发见证与安全期望，输出绑定输入/计划/源码/产物的可复核报告。

**Architecture:** 独立 `experiments/agent_review` 包；现有生产恢复协议和 Oracle 不变。goals/planner/worker/reviewer 只产受限数据；程序节点验证权限、执行、复算和保存。测试子进程以 pyseccomp/libseccomp 禁网络并限制资源，由父进程终止/回收；无任意代码执行。

**Tech Stack:** Python 3.10、LangGraph 1.2.16、pyseccomp 0.1.2、现有 Guardian 场景与 pytest。安装在独立 `output/agent-review-venv`，不改变 ROS 运行依赖。

**Spec:** `docs/superpowers/specs/2026-10-19-artex-ros2-agent-review-design.md`，用户已批准第一阶段。真实模型适配与页面留在后续阶段，不能在首笔报告标为已实现。

## Global Constraints

- 全 run 6 个唯一目录测试、12次含复放执行、16次角色调用、2轮规划、3个并发worker；30秒总截止、单项2秒。
- 首笔仅fixture，真实工具执行不能stub；不读取Key或调用provider/ROS/沙箱源码执行；无前端修改。
- 只接受原始 files/frames 或固定自有模型样例；默认样例明确属于自有虚拟恢复模型。未知字段/工具/引用失败关闭。
- 保留全部既有未提交工作，当前 `codex/evidence-bound-recovery` 分支就地实现；新worktree无法包含既有未提交核心，不拆散当前闭环。
- WSL不允许unshare。Ruling: 使用开源pyseccomp强制禁止网络系统调用，配合只运行固定代码与rlimit、清理环境、父进程硬截止；不宣称完整容器/敌对代码沙箱。
- VALID只表示测试前置/触发成立，安全期望FAIL不能改成NOT_EXERCISED；逐finding复核，静态与提交轨迹重算不冒充重新触发。

## 文件与共享接口

- `experiments/agent_review/contracts.py`：严格JSON、canonical digest、EvidenceBundle/Intent、作用域与角色校验。
- `experiments/agent_review/catalog.py`：六个固定场景、见证和断言。
- `experiments/agent_review/worker.py`：固定执行入口、seccomp/rlimit、真实trace/events输出。
- `experiments/agent_review/runner.py`：子进程有界IO、超时/取消/源码绑定，公开 `run_registered_test(test_id, *, timeout_sec=2.0, cancel=None)` 返回JSON兼容dict。
- `experiments/agent_review/orchestration.py`：LangGraph四角色fixture、计划审定、并发与最终程序复核，公开 `run_review(payload, *, timeout_sec=30.0, cancel=None, provider=None)`。
- `experiments/run_agent_review.py`：有界输入与排他输出CLI；`--sample` 自有固定模型；`--input` files或frames；`--output`必须不存在。
- `experiments/recovery_scenarios.py`：仅增加可选 `witnesses=None` 内部list观测参数，旧返回值/默认行为不变。
- 新增 `tests/test_agent_review_contracts.py`、`tests/test_agent_review_runner.py`、`tests/test_agent_review.py`，使用实际执行或受控测试专用故障，不提供HTTP/模型可注入任意代码hook。

### Task 1: Evidence and capability contracts

接口：`make_bundle(payload)` 接受恰好一种 `{files:[...]}`、`{frames:[...]}` 或 `{sample:"guardian_recovery_virtual_model"}`；返回只含可序列化数据的dict，含context_digest/evidence/summary/target/source_manifest。`approve_plan(role, proposals, bundle, goal_ids, seen=())`只允许planner，产出带server ID的intent dict数组，拒绝extra执行字段/无效refs/重复目录ID；`digest(value)`、`strict_loads(text)`供其他模块调用。目录ID固定为 healthy_resume/ttl_gap/graph_change/policy_change/epoch_change/proof_replay。

- [x] 先写测试：非法字段、伪造/跨bundle引用、角色越权、重复JSON key/NaN拒绝；同字节摘要稳定、源码变化摘要改变；EXTRACTED与用户来源不被提升认证。
- [x] 运行上述测试，记录缺失功能导致失败。
- [x] 实现验证、冻结用到的核心/目录/提示词源码摘要；返回外部模型摘要时不含源码全文/本地绝对路径。
- [x] 运行定向测试并审查，记录结果。

```python
with pytest.raises(ValueError):
    approve_plan("worker", [{"test_id":"healthy_resume"}], bundle, ["g1"])
```

### Task 2: Actual registered execution with witnesses

接口：`catalog.run_case(test_id)` 仅内部Python入口，返回 `{test_id,frames,witnesses,validity,assertion_result,assertion_failures}`；父runner公开接口只接受固定test_id，无variant/source/path/module参数。worker以固定包入口和stdin传test_id运行；只在启动期建立固定路径，不接受外部导入路径。trace原样由parent重新检查。

- [x] 先写六场景真实执行测试，正常恢复与proof重放必须有真实见证。
- [x] 写先验缺失NOT_EXERCISED与错误接受proof的VALID+FAIL负例；正常一直停车应FAIL。
- [x] 先观察缺失功能失败，再添加兼容观测接口与目录断言。
- [x] 写/运行真实子进程的网络拒绝与环境凭据移除验收、超时/取消/大输出有界读取测试；不得只断言mock被调用。
- [x] 实现seccomp失败关闭、rlimit、父进程限额/kill/wait、临时cwd与源码前后摘要检查，跑定向回归并审查。

```python
result = run_registered_test("proof_replay")
assert result["validity"] == "VALID"
assert result["assertion_result"] == "PASS"
assert result["witnesses"]["proof_replay_attempts"] == 1
```

### Task 3: LangGraph closed loop, CLI and verification

接口：fixture provider接收 `(role, public_context)` 并返回受限JSON对象；不是可注册执行工具。全run调用最多16次；注入provider仅Python测试层使用，CLI只允许fixture内置应答。四角色身份固定由graph指定，不能由provider输出覆盖。正常控制由程序加入。

- [x] 写端到端报告断言，要求六场景执行、真实trace重算、四角色活动和fixture标识；未支持llm明确不可用。
- [x] 写恶意角色提案、伪造产物/结论、重复领取、超预算、输入源码漂移、取消后迟到结果与逐finding A/B部分复现拒绝路径。
- [x] 观察失败后实现StateGraph与Send worker路由、注册执行、复算/复放，结构化结果分离role意见与Oracle和断言。
- [x] 实现CLI `--sample --output <new-file>` 与严格JSON导入，输出用排他创建；文件/轨迹来自输入数据，不开放任意工具参数。
- [x] 跑首笔演示，保存报告与依赖版本；独立审查代码与报告，修复实质问题。
- [x] 运行新测试及既有tests全套、compileall、diff检查。更新说明、设计实施状态、计划与HANDOFF。无前端/ROS运行变化时不重复浏览器/DDS验收。

```python
report = run_review({"sample":"guardian_recovery_virtual_model"})
assert report["provider_mode"] == "fixture"
assert report["actuation"] == "none"
assert report["execution_status"] == "COMPLETE"
assert len(report["executions"]) == 6
```

## 审阅与记录

| 共享边界 | 一致性检查 |
| --- | --- |
| Task1 → Task3 | bundle/intent为JSON dict，role/tool身份仅宿主生成，字段全拒绝未知 |
| Task2 → Task3 | run_registered_test公开只允许test_id，rawframes供parent Oracle复核；错误行为不影响validity |
| Task1 ↔ Task2 | source_manifest需包括目录/worker/核心，执行前后重算；先完成各模块后生成最终演示 |
| Task1自身 | 仅严格输入与摘要，不引入模型/ROS依赖 |
| Task2自身 | 可选witness list保持现有场景返回兼容；限制依赖独立venv |
| Task3自身 | fixture真实执行与llm未配置清楚区分；只实现首笔CLI，不宣称前端集成 |

执行记录使用本计划独立ledger；任务审查包含范围/契约与代码质量。未授权提交/推送，所有成果保持可review的本地改动。
