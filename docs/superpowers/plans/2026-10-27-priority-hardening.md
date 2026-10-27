# 分梯度安全修复与运行验收 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Track steps with checkboxes.

**Goal:** 落实10月25日审计前两梯度，修复已复现的核心、检测、研判和部署问题，并启动本机软件闭环验收。

**Architecture:** 保留Guardian确定性安全链与旁路agent隔离。先修A01/A03/A04/A05，再补A06/A07/A08/A09/A10/A11及按属性的证据充分性展示。复用已有标准库HTTP主管与固定传输进程，不新增远程执行能力。

**Tech Stack:** Python/rclpy、LangGraph、Hypothesis、stdlib HTTP、pytest、Playwright。

**Spec:** `docs/code_logic_review_2026-10-25.md`，尤其第8节；用户本轮明确要求按优先级实施和运行。

## Global Constraints

- 遵循PROJECT_GUIDE：原目录main原地修改，保留既有审计报告和HANDOFF改动；不额外创建worktree，不自动提交推送。
- 不读取真实凭据，不调用真实外部模型，不连接硬件；软件ROS测试使用隔离域。
- 工具白名单、租期、HMAC、防重放、主管预算不得放宽；静态嫌疑不升级成运行漏洞。
- 每个逻辑修复先写能复现的失败测试，再最小修复及相关回归。最后完整测试、Humble构建、真实浏览器验证。
- 第三梯度A02认证重启接入、DSL/有界再规划、外部机器人与模型收益实验在本轮只登记后续验收，不冒充已实现。

## Task 1: 恢复包络年龄与重复事件

**Files:** `bound_recovery.py`, `predictive_envelope.py`, `amr_simulator.py`, `tests/test_bound_recovery.py`, `tests/test_amr_simulator.py`。
**Interfaces:** 保持已有构造与消息兼容；增加保守距离/年龄计算，普通事件来源序号跨场景reset递增。

- [x] 回归覆盖0.49秒/.35m/s/.34m反例、年龄单调性、零龄对照、重复攻击与专用replay。
- [x] 先运行新增测试记录RED；修复后记录GREEN及相关测试。
- [x] 核查采集年龄与固定sensor latency不重复折算，保守速度假设显式说明。

```python
assert not stale_decision.mission_allowed
assert new_event.sequence > previous_event.sequence
```

## Task 2: 静态控制路径与本地语料边界

**Files:** `dashboard_code_security.py`, `ros_graph_security.py`, `dataset_security.py`, 对应三份tests，必要时新增共享名称解析模块。
**Interfaces:** 默认根namespace的相对控制名可识别；不确定namespace/remap明确保留缺口。门控识别和写入失效同源。

- [x] 新增相对cmd_vel、门控重写以及根/文件符号链接的RED测试。
- [x] 实现共享资源名称/门控语义，拒绝本地扫描越根文件链接。
- [x] 正常控制器、带namespace文件、ZIP已有边界回归通过。

```python
assert inspect_source(relative_controller)["assurance"]["publish_paths"]
assert changed_guard_path["guarded"] is False
```

## Task 3: 研判证据、分批复核和安装定位

**Files:** `experiments/agent_review/orchestration.py`, `contracts.py`, `prompts.py`, `dashboard_agents.py`, 对应agent/dashboard tests。
**Interfaces:** 确定性finding/assessment绑定保持；角色上下文按风险/类型有界选择；分批review仍计入16次总调用预算；源与安装布局均能定位受信研究运行环境。

- [x] 新增第9/128文件风险可见、128个合法CPP输入可完成、伪造/重复/缺少分批review拒绝的RED测试。
- [x] 分批复核以输入字节和回复大小为边界，预算不足明确INCOMPLETE并保留部分结果。
- [x] 修复受信运行根定位，禁止客户端指定解释器；验证实际安装布局。

```python
assert report["execution_status"] == "COMPLETE"
assert len(report["reviews"]) == len(report["findings"])
```

## Task 4: 统一HTTP总截止与研究CI

**Files:** 新共享 `guardian_core/http_transport.py`, `dashboard_jev.py`, `experiments/agent_review/provider_http.py`, `.github/workflows/ros2.yml`, 对应HTTP/部署测试。
**Interfaces:** 共享固定stdlib子进程，凭据仅stdin；绝对单调截止、终止并回收、字节上限、无代理/重定向；保留Jev HTTP错误映射与agent既有传输协议。

- [x] 先复现持续滴流头/正文超时，以及401/过大正文/进程回收行为。
- [x] 抽取已有HTTP worker为共享实现，接入旧Jev代理与agent wrapper。
- [x] CI增加隔离研究venv、两requirements和关键套件零跳过校验，保留ROS运行时独立。

```python
assert response.http_status == 504
assert elapsed < timeout + process_cleanup_margin
```

## Task 5: 属性证据充分性与检测页

**Files:** `dashboard_recovery.py`, `frontend/recovery.js`, `tests/test_dashboard_recovery.py`, `tests/test_frontend_workspace.py`。
**Interfaces:** 保留原verdict兼容；新增逐属性结果，明确恢复授权可检查、物理运动包络缺原始证据、来源未经认证。前端整体提示不得把不完整证据显示为全面安全。

- [x] 新增属性状态和1e100反例的范围提示测试；不凭默认策略常量推断上传轨迹安全。
- [x] 报告返回属性依据/缺失证据，页面显示检测范围与不可判定项。
- [x] 原上传/agent数据带入及旧样例保持可用。

```python
assert report["property_assessments"]["motion_envelope"]["status"] == "INSUFFICIENT_EVIDENCE"
```

## Task 6: 集成、运行、交接

**Files:** 正式软件演示启动入口、部署/研究/检测文档、README、HANDOFF；验证产物放 `output/priority-20261027/`。

- [x] 独立复核各子任务的spec与代码质量，发现问题后定向返修。
- [x] 相关测试通过后执行一次完整研究环境pytest，Humble两包构建与JS语法检查。
- [x] 先检查8080；已有健康服务时复用，否则隐藏启动软件组合演示，保留既有安全条件。
- [x] Playwright登录、相对话题漏报修复、恢复证据范围、多agent离线闭环/下载和移动布局验收。
- [x] 更新逐项修复状态、测试证据、服务地址和第三梯度边界；不改写10月25日历史审计事实。
