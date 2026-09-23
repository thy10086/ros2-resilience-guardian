# ROS 2 Resilience Guardian

面向 Webots/ROS 2 机器人的任务感知零信任安全韧性守护器。项目基于 RobResilience 的实验思想，加入攻击事件验证、攻击生命周期、动态风险评估、缓解重规划和独立安全状态机。

完整的系统交接、操作记录和后续提交规范见 [HANDOFF.md](HANDOFF.md)。

## 现在能运行什么

- 纯 Python 核心引擎：不依赖 ROS 图形界面，可测试攻击验证、风险计算、3b 多波攻击重规划和安全状态机。
- 跨层安全核心：对 ROS 2 数据路径做图风险传播、来源/时序策略检查、多源证据融合、风险自适应速度包络和恢复门控。
- ROS 2 Jazzy 包：`guardian_interfaces` 消息包和 `guardian_core` 节点包。
- 本地 Web 安全驾驶舱：只读映射风险、攻击组件、缓解方案和安全状态。
- 驾驶舱内置 Jev 连接测试：通过本地后端代理验证 TypeSafe API，并显示有界的语义判断结果。
- `guardian_node` 订阅 `guardian/attack_events`，输出 `guardian/risk_state`、`guardian/mitigation_command` 和 `guardian/safety_status`。
- `experiments/run_innovation_experiments.py` 现在包含 6 组确定性实验，新增跨层融合和 Jev 语义顾问的离线验收。
- 离线实验：`python3 experiments/run_guardian_scenario.py --scenario 3b`。
- 可接入现有 Webots PR2：把攻击事件送入 Guardian，再由 `safety_supervisor` 控制速度、隔离或停车。

## 设计原则

1. 攻击事件必须经过来源、时间戳、序列号和重放检查。
2. `active_attacks`、IDS 已确认集合和当前缓解集合分开维护。
3. 新攻击出现时取消旧方案并重新规划。
4. 任务完成、恢复失败、超时和安全停车使用不同的结果状态。
5. 核心安全判断与任务控制器解耦。

## WSL2 + ROS 2 Jazzy

```bash
cd /mnt/c/Users/user/Documents/Codex/2026-09-10/ban/ros2-resilience-guardian
source /opt/ros/jazzy/setup.bash
cd ros2_ws
colcon build --symlink-install
source install/setup.bash
```

运行核心离线实验：

```bash
cd /mnt/c/Users/user/Documents/Codex/2026-09-10/ban/ros2-resilience-guardian
python3 experiments/run_guardian_scenario.py --scenario 3b
```

运行测试：

```bash
python3 -m pytest -q tests
```

启动 ROS 2 守护节点：

```bash
ros2 run guardian_core guardian_node
```

启动安全驾驶舱（需要先启动 `guardian_node`）：

```bash
ros2 run guardian_core guardian_dashboard
# 浏览器打开 http://127.0.0.1:8080
```

也可以一次启动守护节点和前端桥接：

```bash
ros2 launch guardian_core guardian.launch.py
```

驾驶舱通过 `GET /api/state` 提供当前状态，订阅 `/guardian/risk_state`、
`/guardian/mitigation_command` 和 `/guardian/safety_status`。默认只监听
`127.0.0.1`，不会把控制接口暴露到局域网；后续接入 Webots 时应继续由
`safety_status` 输出边界驱动实际控制器。

打开页面后，在“Jev 连接测试”面板中输入 TypeSafe API Key 和一段简短的
测试状态，点击“测试连接”即可执行一次旁路请求。浏览器只把请求发给本地
`POST /api/jev/test`，由 dashboard 后端默认调用固定的
`https://api.typesafe.ai/v1/systemone`（仅允许显式 localhost 测试 endpoint），因此不会触发 TypeSafe 的浏览器 CORS
限制。API Key 只存在于本次请求的内存和 HTTPS 请求头中，不会写入 `.env`、
浏览器存储、ROS 消息、审计记录或日志；点击“清空”会移除页面中的输入。
该面板只返回攻击类型、任务影响、分数、置信度和人工复核建议，不会改变
Guardian 安全状态、速度限制或机器人命令。

该接口接受 `{ "api_key": "...", "state": "..." }` JSON，请求体上限为
64 KiB，状态文本上限为 4096 个字符。成功返回 HTTP 200；输入错误返回
400/413；上游拒绝或返回非法内容返回 502；超时返回 504。真实 API Key
不应提交到版本库，也不应放入 `.env`。

详细设计见 [docs/design.md](docs/design.md)，实验和指标见 [docs/experiments.md](docs/experiments.md)。

创新功能验证见 [docs/innovation_validation.md](docs/innovation_validation.md)，可直接运行：

```bash
python3 experiments/run_innovation_experiments.py
```

运行专利化安全核心的五组对照实验：

    python3 experiments/run_patent_innovation_experiments.py

可选的 Jev 语义安全顾问见 [docs/jev_advisor.md](docs/jev_advisor.md)。它只对已经通过确定性验证的事件摘要做分类和人工复核建议，默认关闭，不进入 `guardian_node` 的实时控制循环，也不能解除停车或直接控制底盘；非布尔或未验证来源会在缓存和网络之前被拒绝。advisor 和高效判断层对注入时钟执行有限、单调不减保护，避免非法时间、TTL 回退、负延迟和预算窗口倒退；高效层只接受 advisor 的新鲜 `OK` 结果启动自己的缓存租约，不会用下层 `CACHED` 结果续租。离线实验使用 stub provider，不需要 API Key。Jev 高效判断层增加本地风险分流、稳定事件指纹、TTL/LRU 缓存、并发 single-flight、调用预算和冲突指标；运行 `python3 experiments/run_jev_efficiency_experiments.py` 可复现实验。

Jev 事件会话层进一步聚合连续告警、对风险和语义变化重新查询、用滞回窗口稳定人工复核状态，并把有期限的 Jev 软证据绑定到确定性父证据；同一会话的决策和账本写回串行化，不同事件仍可并行，账本的哈希链写入只在短临界区内串行，账本异常分支也受会话容量上限约束。父证据必须当前有效、已验证、策略匹配且父链完整；父证据在 provider 调用期间被替代时会在写回前再次阻断。缓存结果切换父证据只保留原软证据截止时间，到期缓存不能复活账本证据，只有新的 provider 成功结果才能建立新租约。会话 ID 和签名复用 Jev 适配器的有界上下文表示，避免超长输入放大会话层资源消耗；非布尔或未验证来源会强制进入本地 `CONTAINING`，不会复用旧 Jev 结果。实验命令为 `python3 experiments/run_jev_session_experiments.py`，设计见 [docs/jev_session_design.md](docs/jev_session_design.md)。

跨层融合扩展的实验设计见 [docs/fusion_experiment_plan.md](docs/fusion_experiment_plan.md)，实现边界和后续 ROS 2 接入步骤见 [docs/fusion_implementation_plan.md](docs/fusion_implementation_plan.md)。当前跨层模块已完成纯 Python 离线验证，但还没有直接接管真实底盘、Webots 或 ROS 2 live graph introspection。

专利化研究方案、现有技术边界和对照实验见 [docs/patent_disclosure.md](docs/patent_disclosure.md)、[docs/patent_prior_art.md](docs/patent_prior_art.md) 和 [docs/patent_experiments.md](docs/patent_experiments.md)。当前新增的因果图、证据账本、预测安全包络、反事实解释和双阶段恢复协议已完成纯 Python 离线验证，尚未宣称完成实机认证或专利授权。
## Current implementation status

Implemented in this repository:

- Event verifier with trusted-source, timestamp, sequence/replay and optional HMAC checks.
- Event-sourced attack registry with expiry and per-component aggregation.
- Paper-compatible `delta`, `psi`, `gamma` metrics plus bounded runtime risk.
- Dynamic mitigation planner that re-plans on every event-set change.
- Independent safety supervisor with explicit `NORMAL`, `CONTAINING`, `RESUMABLE` and `SAFE_STOP` decisions.
- ROS 2 Jazzy interfaces and `guardian_node` publishers/subscribers.
- Headless multi-wave scenario driver and tests.

Integration boundary:

`guardian/safety_status` is intentionally an output boundary. A Webots or hardware adapter must apply its speed limit and stop decision to the actual robot controller. This keeps the safety policy testable and prevents the Guardian from directly owning robot-specific APIs.
