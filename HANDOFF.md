# ROS 2 Resilience Guardian 交接文档

> 本文件是项目的持续交接记录。每次代码、实验、部署或仓库配置发生变化时，必须在同一个提交中更新本文件的“变更日志”和必要的运行说明，然后再提交到 `main`。

## 1. 项目定位

本项目是一个面向室内移动机器人导航的 ROS 2 系统级安全防护原型。它以 RobResilience 论文中的韧性思想为基础，扩展出“事件验证 → 攻击生命周期 → 动态风险评估 → 缓解重规划 → 安全状态机 → Web 监控”的闭环。

当前目标环境是单台笔记本上的 WSL2、Ubuntu 24.04、ROS 2 Jazzy 和 Webots。核心判断与机器人控制器解耦，便于先做离线实验，再接入 Webots 或真实底盘。

## 2. 已完成的系统能力

### 2.1 安全核心

- `EventVerifier` 校验可信来源、时间戳新鲜度、序列号重放和可选 HMAC 签名。
- `AttackRegistry` 维护攻击事件生命周期、过期事件和组件聚合状态。
- `RiskEngine` 计算论文兼容的 `delta`、`psi`、`gamma`，并输出受边界约束的运行时风险分数。
- `MitigationPlanner` 根据当前攻击集合动态重规划隔离、降级和安全停车动作。
- `SafetySupervisor` 使用明确的 `NORMAL`、`DEGRADED`、`CONTAINING`、`RESUMABLE`、`SAFE_STOP` 状态决定速度上限、任务是否允许继续和停车原因。
- `SecurityGraph` 沿 ROS 2 节点—话题—执行器路径传播有界风险，并标记受影响的关键节点。
- `TemporalPolicyMonitor` 检查来源、未来时间、过期、重放、最小周期和最大间隔策略。
- `EvidenceFusion` 将事件可信度、来源信任、时序违规、图风险、任务关键性和物理不一致融合为 `ALLOW`、`CONTAIN` 或 `SAFE_STOP`，同时返回原因。
- `SafetyEnvelopeController` 根据融合风险、可用距离和传感器新鲜度计算速度上限和停车状态。
- `RecoveryGate` 要求无活动攻击、图稳定、传感器新鲜、策略有效、命令清空和驻留时间完成后才允许恢复。
- `JevSemanticAdvisor` 提供可选的语义安全旁路：只接收已验证事件的限长摘要，返回有界的攻击类型、任务影响、置信度和人工复核建议；默认关闭，不参与实时控制。

### 2.2 ROS 2 集成

- `guardian_interfaces` 提供 `AttackEvent`、`RiskState`、`MitigationCommand` 和 `SafetyStatus` 消息。
- `guardian_node` 订阅 `/guardian/attack_events`，发布风险、缓解和安全状态话题。
- `guardian_dashboard` 订阅三个状态话题，维护线程安全缓存并提供本地 HTTP API。
- `guardian.launch.py` 可同时启动核心守护节点和驾驶舱。

### 2.3 Web 安全驾驶舱

静态页面位于 `ros2_ws/src/guardian_core/guardian_core/frontend/`，显示：

- 当前安全状态和任务是否允许继续；
- 风险分数、`psi`、`delta`、`gamma`；
- 活动攻击组件和关键组件；
- 当前缓解动作、计划 ID、速度限制；
- 风险评估、缓解规划和安全监督时间线。

后端默认只监听 `127.0.0.1:8080`，提供：

- `GET /`：静态驾驶舱页面；
- `GET /api/health`：服务健康检查；
- `GET /api/state`：当前状态和时间线 JSON。

驾驶舱是只读监控入口。实际机器人速度和停车动作仍必须由 Webots 或硬件适配器消费 `SafetyStatus` 后执行。

## 3. 关键目录和文件

| 路径 | 用途 |
| --- | --- |
| `ros2_ws/src/guardian_core/guardian_core/verifier.py` | 事件来源、时间戳、重放和签名验证 |
| `ros2_ws/src/guardian_core/guardian_core/risk_engine.py` | 风险指标与运行时风险 |
| `ros2_ws/src/guardian_core/guardian_core/planner.py` | 动态缓解规划 |
| `ros2_ws/src/guardian_core/guardian_core/supervisor.py` | 安全状态机 |
| `ros2_ws/src/guardian_core/guardian_core/guardian_node.py` | ROS 2 守护节点 |
| `ros2_ws/src/guardian_core/guardian_core/dashboard.py` | ROS 2 到 HTTP 的桥接服务 |
| `ros2_ws/src/guardian_core/guardian_core/dashboard_state.py` | 驾驶舱线程安全状态缓存 |
| `ros2_ws/src/guardian_core/guardian_core/frontend/` | HTML、CSS、JavaScript 页面 |
| `experiments/run_guardian_scenario.py` | 离线多波攻击场景 |
| `experiments/run_innovation_experiments.py` | 零信任、重新规划、状态机、审计和跨层融合验证 |
| `ros2_ws/src/guardian_core/guardian_core/graph_model.py` | ROS 2 数据路径风险传播 |
| `ros2_ws/src/guardian_core/guardian_core/policy_monitor.py` | 运行时来源和时序规则 |
| `ros2_ws/src/guardian_core/guardian_core/evidence_fusion.py` | 多源证据融合和解释 |
| `ros2_ws/src/guardian_core/guardian_core/safety_envelope.py` | 风险与制动距离约束的速度上限 |
| `ros2_ws/src/guardian_core/guardian_core/recovery_gate.py` | 多条件恢复门控 |
| `ros2_ws/src/guardian_core/guardian_core/jev_advisor.py` | 可选 Jev 语义顾问、缓存、响应归一化和安全审计元数据 |
| `docs/fusion_experiment_plan.md` | 图传播、时序规则、证据融合和安全速度的后续实验设计 |
| `docs/innovation_validation.md` | 当前创新实验的结果、原理和判定过程 |
| `docs/jev_advisor.md` | Jev 旁路的使用方式、隐私边界和离线验证说明 |
| `tests/` | 核心引擎和驾驶舱状态缓存测试 |
| `.env` | 已跟踪的安全默认配置；不要写入真实密钥 |

## 4. 环境和运行命令

```bash
cd /mnt/c/Users/user/Documents/Codex/2026-09-10/ban/ros2-resilience-guardian
source /opt/ros/jazzy/setup.bash
cd ros2_ws
colcon build --symlink-install
source install/setup.bash
```

运行测试：

```bash
cd /mnt/c/Users/user/Documents/Codex/2026-09-10/ban/ros2-resilience-guardian
python3 -m pytest -q tests
```

启动完整系统：

```bash
ros2 launch guardian_core guardian.launch.py
```

然后访问 `http://127.0.0.1:8080`。

只启动驾驶舱：

```bash
ros2 run guardian_core guardian_dashboard
```

运行离线场景：

```bash
python3 experiments/run_guardian_scenario.py --scenario 3b
```

## 5. 已执行的验证

- Windows Python 语法编译和 `DashboardState` 状态缓存 smoke test 通过。
- WSL2 中 `python3 -m pytest -q tests` 通过，当前结果为 `23 passed`，包含 Jev 适配器的禁用、脱敏、缓存、错误回退、配置校验、响应类型校验和未验证事件跳过测试。
- ROS 2 Jazzy `colcon build --symlink-install` 成功构建 `guardian_interfaces` 和 `guardian_core`。
- 真实 `guardian_dashboard` 进程已验证 `/api/health`、`/api/state` 和 HTML 页面可访问。
- 已确认 `.env` 被 Git 跟踪，远程 GitHub 树中也存在 `.env`。
- 创新层验证报告见 `docs/innovation_validation.md`；脚本输出保存在被忽略的 `experiments/results/innovation_validation.json`。
- `python3 experiments/run_innovation_experiments.py` 通过 6 组实验；新增 `jev_semantic_advisor` 离线 stub 实验，验证类型化回答、缓存、未验证来源跳过和 JSONL 审计；报告见 `docs/innovation_validation.md`。
- 纯 Python 图传播、时序规则、证据融合、安全速度包络和恢复门控已经实现并通过单元测试；它们仍未接入真实 ROS 2 live graph、`guardian_node`、SROS 2/DDS 权限或 Webots 底盘。

## 6. GitHub 发布状态

- 仓库：[thy10086/ros2-resilience-guardian](https://github.com/thy10086/ros2-resilience-guardian)
- 默认分支：`main`
- 发布方式：GitHub API 写入 Git 对象；本机 Git HTTPS 通道曾出现连接超时。
- 本地 `origin` 仅保存 SSH 地址：`git@github.com:thy10086/ros2-resilience-guardian.git`。
- GitHub Token 不得写入仓库、`.env`、远程 URL、脚本或日志。曾用于发布的临时 Token 应在发布后撤销。

## 7. 后续开发建议

1. 接入 Webots 适配器，让 `SafetyStatus.speed_limit` 和 `mission_allowed` 真正影响导航控制器。
2. 增加攻击事件验证结果的审计 API，并在驾驶舱显示被拒绝事件。
3. 加入 SROS 2 policy、密钥轮换和 DDS 身份映射的端到端实验。
4. 增加多波攻击、误报率、检测延迟、安全停车时间和任务完成率的可重复报告。
5. 在只读监控稳定后，再设计带 RBAC、二次确认和审计记录的控制操作入口。

## 8. 每次提交交接清单

提交前必须完成：

1. 更新本文件的变更日志，写明日期、提交目的、修改文件、行为变化和验证结果。
2. 若命令、端口、消息接口或环境变量变化，同步更新本文件第 2、4、5 节和 README。
3. 运行相关测试、ROS 2 构建和必要的 API/页面 smoke test。
4. 确认 `git status` 没有遗漏，确认 `.env` 仍在 `git ls-files .env` 输出中。
5. 只提交到 `main`，提交信息使用清晰的动词和范围。

建议使用以下记录模板：

```markdown
### YYYY-MM-DD — <commit subject>

- 改动：
- 文件：
- 验证：
- 风险或后续：
```

## 9. 变更日志

### 2026-09-18 — 初始安全守护器

- 改动：创建纯 Python 安全核心、攻击验证、风险引擎、缓解规划、安全状态机、ROS 2 消息和守护节点。
- 文件：`guardian_core`、`guardian_interfaces`、离线实验、测试、配置和安全说明。
- 验证：核心测试和 ROS 2 Jazzy 构建通过。

### 2026-09-18 — `feat: add ROS 2 security dashboard`

- 改动：新增线程安全状态缓存、标准库 HTTP/ROS 2 桥接、静态安全驾驶舱、启动入口和页面测试。
- 文件：`dashboard.py`、`dashboard_state.py`、`frontend/`、`setup.py`、`guardian.launch.py`、`tests/test_dashboard_state.py`、`README.md`。
- 验证：WSL2 `9 passed`；两个 ROS 2 包构建成功；真实页面、`/api/health` 和 `/api/state` 可访问。

### 2026-09-18 — GitHub 发布

- 改动：创建公开仓库 `thy10086/ros2-resilience-guardian`，将完整 39 个文件发布到 `main`，保留已跟踪 `.env`。
- 验证：远程默认分支为 `main`；远程树包含 39 个 blob 文件和 `.env`；本地远程地址未包含 Token。

### 2026-09-18 — 本次交接文档

- 改动：新增本文件，补充系统结构、运行命令、验证证据、发布状态、后续方向和每次提交更新规则；README 增加交接文档入口。
- 验证：提交前执行 `git diff --check`，并在同步后核验远程文件树和 `main` 分支。

### 2026-09-18 — 创新功能验证

- 改动：新增 `experiments/run_innovation_experiments.py` 和 `docs/innovation_validation.md`，验证零信任事件门、计划生效前多波重新规划、安全状态机、驾驶舱状态聚合和审计 JSONL。
- 验证：4 类实验全部通过；5 类不可信事件被拦截；旧计划被新关键攻击替换；隔离后残余风险下降并恢复为 `RESUMABLE`。

### 2026-09-18 — 跨层融合实验说明

- 改动：补充当前四类实验的原理和逐步判定过程，新增跨层融合实验计划，覆盖 ROS 2 图传播、时序规则、多源证据融合、安全速度包络和恢复门控。
- 验证：文档明确区分已实现功能与待实现研究模块；现有实验脚本和 ROS 2 构建结果保持不变。

### 2026-09-18 — `feat: add cross-layer fusion safety core`

- 改动：新增 `SecurityGraph`、`TemporalPolicyMonitor`、`EvidenceFusion`、`SafetyEnvelopeController` 和 `RecoveryGate`；将五层安全链路加入确定性创新实验；补充纯 Python 到 ROS 2 适配的边界说明。
- 文件：`ros2_ws/src/guardian_core/guardian_core/{graph_model,policy_monitor,evidence_fusion,safety_envelope,recovery_gate}.py`、`tests/test_fusion_layers.py`、`experiments/run_innovation_experiments.py`、`docs/innovation_validation.md`、`docs/fusion_implementation_plan.md`、`README.md`、`progress.md`、`task_plan.md`。
- 验证：跨层实验 1 组通过；创新实验共 5 组通过；WSL2 `python3 -m pytest -q` 为 `15 passed`，并覆盖未知权重、非法风险阈值和非法时间戳边界；ROS 2 live graph、Webots 控制和 SROS 2 仍未宣称完成。

### 2026-09-21 — `feat: add optional Jev semantic security advisor`

- 改动：新增标准库实现的 `JevSemanticAdvisor`，对已验证事件摘要执行可选的 Jev `Choice`/`Noul` 判断；加入字段白名单、敏感文本脱敏、HTTPS endpoint 校验、响应大小限制、超时回退、缓存、有限数值归一化和安全审计元数据；默认不启用，不修改 ROS 2 控制循环和安全状态机。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_advisor.py`、`ros2_ws/src/guardian_core/guardian_core/__init__.py`、`tests/test_jev_advisor.py`、`experiments/run_innovation_experiments.py`、`docs/jev_advisor.md`、`docs/innovation_validation.md`、`README.md`、`.env`、`task_plan.md`、`findings.md`、`progress.md`。
- 验证：Windows `compileall` 通过；WSL2 `python3 -m pytest -q tests` 为 `23 passed`；创新实验共 6 组通过，Jev 实验使用 stub provider 并验证缓存、未验证来源跳过和 JSONL 审计；ROS 2 `colcon build --symlink-install` 成功构建两个包；未进行真实 API 调用，也未宣称 Jev 已接入实时 ROS 2 或 Webots 控制。
- 风险或后续：如需在线使用，应实现异步 worker、结果过期和置信度门控，并先以离线回放评估准确率、校准、延迟、成本和数据隐私；Jev 结果不得单独解除 `SAFE_STOP` 或批准恢复。
