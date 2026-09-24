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
- `JevEfficientJudge` 在 Jev 之前执行本地快速分流，并提供稳定指纹、TTL/LRU 缓存、single-flight 合并、调用预算和冲突指标；仍然只作为旁路建议。
- `JevIncidentSession` 在高效判断和证据账本之间聚合事件、执行查询滞回，并将有期限的 Jev 软证据绑定到确定性父证据；账本异常时强制 `CONTAINING`。
- `JevIncidentSession` 的同一会话决策和账本写回使用独立锁串行化，不同会话仍可并行；账本 `verify()+append()` 使用短全局临界区防止哈希链竞态；风险、任务关键性、事件置信度、来源验证和父证据变化会触发重新判断，会话容量在所有写回路径上受 `max_sessions` 限制。
- 会话身份和查询签名复用 `SemanticContext.to_state()` 的有界文本、列表和数值规范化，防止超长输入在本地哈希和集合操作中放大资源消耗。
- `source_verified` 只接受原生布尔值；`False` 或非布尔值不能复用已验证会话，统一经过 `SKIPPED_UNVERIFIED` 本地拒绝并进入 `CONTAINING`。
- `JevSemanticAdvisor` 直连入口也执行同一严格检查，在缓存和网络之前拒绝非布尔或 `False` 来源，避免绕过事件会话层直接外发未验证上下文。
- 会话观测时间遇到非法或非有限显式输入时回退到注入的内部时钟，内部时钟也无效时才使用 `0.0`，避免调用方格式错误让安全判断异常退出。
- 同一会话的有限观测时间也必须单调不减；早于 `last_seen` 的输入会被钳制，避免 TTL 延长、负查询间隔或倒退软证据时间。
- Jev 软证据写回前后都会验证父证据：父记录必须 active、已验证、策略版本匹配、不是 Jev 软证据，且完整父链可验证；父记录缺失、过期、未来生效、被替代或祖先失效时，判断在 provider 前直接阻断。
- 父证据在 provider 调用期间被替代时，追加阶段的第二次检查会拒绝写回。缓存判断切换到新父证据时继承旧软证据的绝对截止时间；过期缓存不能刷新或复活软证据，只有新的 provider 成功结果能建立新租约。
- `JevSemanticAdvisor` 与 `JevEfficientJudge` 的注入时钟现在都经过有限、单调不减的保护；非法、NaN、无穷或回退时间不会制造负延迟、倒退缓存 TTL 或提前重置调用预算。
- advisor 和高效判断层的缓存租约彼此独立；高效层只接受新鲜 `OK` 结果启动自己的 TTL，advisor 返回的 `CACHED` 结果不会续租高效层，避免下层缓存让上层缓存无限存活。
- single-flight 等待者会保留 owner 的失败状态和原因；只有可用的 `OK`/`CACHED` 建议才标记为 `COALESCED`，缓存命中和并发复用都会按当前本地 triage 重新计算 Jev 冲突，避免 `REVIEW_REQUIRED` 信号丢失。
- 会话用完成时刻重新验证父证据和完整 lineage；provider 期间过期、被替代、祖先失效或账本篡改时，成功和失败结果都不会写回软证据。显式回放时间保留调用方原点，provider 等待耗时从软证据剩余 TTL 中扣除。
- EvidenceLedger 的 `verified` 与 `hard_stop` 现在只接受原生布尔值；新记录、父链、替代关系和导出验证遇到非布尔信任标记都会失败关闭，哈希一致不能掩盖字段语义异常。
- 高效判断层在缓存/预算状态锁内重新采样时间，暂停在缓存查找阶段的旧请求不能复活过期建议、回滚并重置较新的固定窗口；新的预约时间也用于 provider 缓存租约起点。
- 基础 `JevSemanticAdvisor` 也在 `_cache_lock` 内重新采样有限单调时钟，防止暂停的旧请求绕过 advisor 自身 TTL；两层缓存均要求完成时刻仍在租约内。

本轮专利化安全核心新增：

- CausalGraph 为 ROS 2 节点—话题—执行器路径生成带出处的图指纹、风险路径和图变更记录。
- EvidenceLedger 保存父子证据、策略版本、哈希链锚点和替代关系；账本验证失败时 AssuranceController 强制 SAFE_STOP。
- PredictiveEnvelope 把控制/传感器延迟、制动距离、不确定度和风险增长纳入预测速度包络。
- AssuranceController 输出证据保障等级和只读反事实解释；硬停车证据不能被普通证据平均稀释。
- RecoveryProtocol 使用 RECOVERY_PROBING → RECOVERY_CANDIDATE → RESUMABLE 和绑定图/策略/账本/命令代次的一次性凭据。

### 2.2 ROS 2 集成

- `guardian_interfaces` 提供 `AttackEvent`、`RiskState`、`MitigationCommand` 和 `SafetyStatus` 消息。
- `guardian_node` 订阅 `/guardian/attack_events`，发布风险、缓解和安全状态话题。
- `guardian_dashboard` 订阅三个状态话题，维护线程安全缓存并提供本地 HTTP API。
- `guardian_dashboard` 提供本地登录和 `/api/jev/test` 代理；默认本地实验账号用户名和密码均为 `admin`，会话只保存在内存中。
  和短状态文本执行 Jev 连接测试；结果只作为旁路建议。
- `guardian.launch.py` 可同时启动核心守护节点和驾驶舱。

### 2.3 Web 安全驾驶舱

静态页面位于 `ros2_ws/src/guardian_core/guardian_core/frontend/`，显示：

- 当前安全状态和任务是否允许继续；
- 风险分数、`psi`、`delta`、`gamma`；
- 活动攻击组件和关键组件；
- 当前缓解动作、计划 ID、速度限制；
- 风险评估、缓解规划和安全监督时间线。
- Jev 连接测试状态、标准化攻击类型、任务影响、分数、置信度和人工复核建议。

后端默认只监听 `127.0.0.1:8080`；本次本地系统服务配置监听 `127.0.0.1:8088`，提供：

- `GET /`：静态驾驶舱页面；
- `GET /api/health`：服务健康检查；
- `POST /api/login`、`GET /api/session`、`POST /api/logout`：本地 dashboard 会话登录、检查和退出；
- `GET /api/state`：当前状态和时间线 JSON。
- `POST /api/jev/test`：使用本次请求提供的 API Key 和状态文本调用固定
  TypeSafe endpoint，返回有界连接/评估结果。

驾驶舱仍是只读监控入口。Jev 测试只返回语义建议，实际机器人速度和停车动作仍必须由 Webots 或硬件适配器消费 `SafetyStatus` 后执行。
API Key 不从环境变量读取，也不会写入浏览器存储、ROS 消息、审计数据或日志；
浏览器只调用本地代理，以避开 TypeSafe 的 CORS 限制。

## 3. 关键目录和文件

| 路径 | 用途 |
| --- | --- |
| `ros2_ws/src/guardian_core/guardian_core/verifier.py` | 事件来源、时间戳、重放和签名验证 |
| `ros2_ws/src/guardian_core/guardian_core/risk_engine.py` | 风险指标与运行时风险 |
| `ros2_ws/src/guardian_core/guardian_core/planner.py` | 动态缓解规划 |
| `ros2_ws/src/guardian_core/guardian_core/supervisor.py` | 安全状态机 |
| `ros2_ws/src/guardian_core/guardian_core/guardian_node.py` | ROS 2 守护节点 |
| `ros2_ws/src/guardian_core/guardian_core/dashboard.py` | ROS 2 到 HTTP 的桥接服务 |
| `ros2_ws/src/guardian_core/guardian_core/dashboard_jev.py` | 有界 Jev dashboard 代理、输入校验和错误映射 |
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
| `ros2_ws/src/guardian_core/guardian_core/jev_efficiency.py` | Jev 高效判断编排、本地分流、稳定指纹、single-flight、预算和效率指标 |
| `ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py` | Jev 事件会话聚合、查询门控、滞回和账本软证据绑定 |
| `docs/jev_session_design.md` | Jev 事件会话状态、查询时机和软证据约束 |
| `docs/fusion_experiment_plan.md` | 图传播、时序规则、证据融合和安全速度的后续实验设计 |
| `docs/innovation_validation.md` | 当前创新实验的结果、原理和判定过程 |
| `docs/jev_advisor.md` | Jev 旁路的使用方式、隐私边界和离线验证说明 |
| `ros2_ws/src/guardian_core/guardian_core/causal_graph.py` | 带出处的运行时因果风险图和图指纹 |
| `ros2_ws/src/guardian_core/guardian_core/evidence_ledger.py` | 父子证据、哈希链锚点和完整性验证 |
| `ros2_ws/src/guardian_core/guardian_core/predictive_envelope.py` | 延迟补偿、风险增长和制动距离安全包络 |
| `ros2_ws/src/guardian_core/guardian_core/assurance.py` | 保障等级、硬停车和反事实解释 |
| `ros2_ws/src/guardian_core/guardian_core/recovery_protocol.py` | 双阶段恢复和上下文绑定凭据 |
| `experiments/run_patent_innovation_experiments.py` | 专利化架构的五组确定性对照实验 |
| `docs/patent_disclosure.md` | 技术交底书草案和权利要求方向 |
| `docs/patent_prior_art.md` | SROS 2、Nav2 Collision Monitor、RTAMT 等参考边界 |
| `docs/patent_experiments.md` | 新架构实验结果、限制和后续指标 |
| `tests/` | 核心引擎、驾驶舱、Jev 代理和专利化内核契约测试 |
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

默认启动文件使用 `8080`。如果端口已被其他服务占用，本次本地系统服务使用 `8088`：

```bash
systemctl status guardian-core.service guardian-dashboard.service
systemctl restart guardian-core.service guardian-dashboard.service
# 浏览器打开 http://127.0.0.1:8088
```

本次验证中 `8080` 已被其他本地进程占用，因此 dashboard 以 `host=127.0.0.1`、`port=8088` 运行。服务单元位于 WSL 系统目录 `/etc/systemd/system/`，不是仓库文件；停止命令为 `systemctl stop guardian-core.service guardian-dashboard.service`。Windows 端需要保持一个 WSL 实例运行，否则 WSL 会自动回收整个 ROS 2 进程组；可用 `Start-Process wsl.exe -ArgumentList @('-d','Ubuntu-24.04','--','sleep','infinity') -WindowStyle Hidden` 保持实例。

只启动驾驶舱：

```bash
ros2 run guardian_core guardian_dashboard
```

启动后访问 `http://127.0.0.1:8088`，先使用 `admin/admin` 登录，再在“Jev 连接测试”面板输入 TypeSafe
API Key 和简短状态文本即可执行一次测试。请求也可直接发送到
`POST /api/jev/test`，JSON 形如
`{"api_key":"<key>","state":"verified command anomaly"}`。请求体上限为
64 KiB，状态文本上限为 4096 个字符；400/413 表示输入错误，502 表示上游
拒绝或非法响应，504 表示超时。真实 API Key 不得写入仓库或 `.env`。

运行离线场景：

```bash
python3 experiments/run_guardian_scenario.py --scenario 3b
```

## 5. 已执行的验证

- Windows Python 语法编译和 `DashboardState` 状态缓存 smoke test 通过。
- WSL2 中 `python3 -m pytest -q tests` 通过，当前结果为 `73 passed`，包含 Jev 适配器、跨层融合、因果路径、账本完整性、预测包络、保障解释和双阶段恢复测试。
- ROS 2 Jazzy `colcon build --symlink-install` 成功构建 `guardian_interfaces` 和 `guardian_core`。
- 真实 `guardian_dashboard` 进程已验证 `/api/health`、`/api/state` 和 HTML 页面可访问。
- 已确认 `.env` 被 Git 跟踪，远程 GitHub 树中也存在 `.env`。
- 创新层验证报告见 `docs/innovation_validation.md`；脚本输出保存在被忽略的 `experiments/results/innovation_validation.json`。
- `python3 experiments/run_innovation_experiments.py` 通过 6 组实验；新增 `jev_semantic_advisor` 离线 stub 实验，验证类型化回答、缓存、未验证来源跳过和 JSONL 审计；报告见 `docs/innovation_validation.md`。
- WSL2 Ubuntu-24.04 中 `python3 -m pytest -q tests` 通过，当前结果为 `35 passed`；新增 `tests/test_dashboard_jev.py` 覆盖 Jev 代理请求限制、成功响应、401/429、超时、非法响应、控制字符 key、provider echo 脱敏、endpoint allowlist、redirect 防护和 API Key 不泄露。Windows Python `compileall` 也通过。
- 使用确定性 fake transport 的 dashboard HTTP smoke test 验证 `/api/jev/test` 成功响应、坏 JSON 的 400 和超大请求的 413；真实无效 key 请求实际到达 TypeSafe 并返回 401，页面显示安全失败状态；前端 `node --check` 通过。
- 纯 Python 图传播、时序规则、证据融合、安全速度包络和恢复门控已经实现并通过单元测试；它们仍未接入真实 ROS 2 live graph、`guardian_node`、SROS 2/DDS 权限或 Webots 底盘。
- 专利化五组实验 `python3 experiments/run_patent_innovation_experiments.py` 已通过：固定包络 `0.315 m/s` 对比风险增长预测包络 `0.175 m/s`；图变更、篡改、恢复凭据重放和反事实解释均有结果。
- `python -m compileall` 和 ROS 2 Jazzy `colcon build --symlink-install` 已通过；新增模块仍是纯 Python 安全内核，没有宣称已接入实机控制或 DDS 权限执行。

## 6. GitHub 发布状态

- 仓库：[thy10086/ros2-resilience-guardian](https://github.com/thy10086/ros2-resilience-guardian)
- 默认分支：`main`
- 发布方式：使用 Windows Git Credential Manager 中已保存的 `thy10086` 凭据，经本机 HTTPS 代理同步到 `origin/main`；认证信息不写入远程 URL、仓库或日志。
- 本地 `origin` 使用 HTTPS 地址：`https://github.com/thy10086/ros2-resilience-guardian.git`。SSH 公钥认证仍不可用，因此不使用 SSH 推送。
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

### 2026-09-21 — `feat: add dashboard Jev connection test`

- 改动：在本地只读驾驶舱增加 Jev 连接测试面板和 `POST /api/jev/test` 代理；后端默认调用官方 TypeSafe endpoint，仅允许显式 localhost 测试 override，限制请求体和状态文本长度，归一化成功结果，并将上游拒绝、非法响应和超时映射为有限 HTTP 状态。
- 文件：`ros2_ws/src/guardian_core/guardian_core/dashboard_jev.py`、`dashboard.py`、`frontend/index.html`、`frontend/app.js`、`frontend/styles.css`、`tests/test_dashboard_jev.py`、`README.md`、`docs/jev_advisor.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 安全边界：API Key 只由用户在单次浏览器请求中提供，暂存于进程内并放入上游 `Authorization` header；不写入 `.env`、浏览器存储、ROS 状态、审计记录、响应或日志。Dashboard transport 禁止自动 HTTP 重定向，且只允许官方 endpoint 或显式 localhost 测试 endpoint。Jev 结果不能改变安全状态、速度限制、恢复门控或机器人命令。
- 验证：WSL2 `python3 -m pytest -q tests` 为 `35 passed`；`python -m compileall -q ros2_ws/src/guardian_core/guardian_core tests` 和 `node --check ros2_ws/src/guardian_core/guardian_core/frontend/app.js` 通过；fake transport HTTP smoke test 验证成功、400 和 413 路径，真实无效 key 验证上游 401 映射，浏览器验证空 key、失败、成功和清空状态。未用真实 API Key 做线上成功调用。
- 风险或后续：TypeSafe 是早期体验远程服务，真实延迟、配额和准确率未评估；生产部署应继续只绑定本机、使用短生命周期密钥，并在需要时增加异步队列、速率限制和更严格的 endpoint allowlist。

### 2026-09-23 — `feat: add provenance-bound predictive safety core`

- 改动：新增带出处因果图、哈希链证据账本、延迟补偿预测安全包络、保障反事实解释和上下文绑定双阶段恢复协议；增加专利化技术交底、现有技术边界和五组确定性对照实验。
- 文件：新增 causal_graph.py、evidence_ledger.py、predictive_envelope.py、assurance.py、recovery_protocol.py、test_patent_core.py、run_patent_innovation_experiments.py 以及 docs/patent_*.md；更新 guardian_core 导出、README、task_plan、findings、progress。
- 验证：全量 WSL2 测试 73 passed；原有六组创新实验和新五组专利化实验通过；Windows compileall 通过；ROS 2 Jazzy 两包构建完成；.env 仍被 Git 跟踪。
- 边界：新增模块仍是纯 Python 研究内核，未接入真实 ROS 2 live graph、DDS 权限执行、Webots 底盘或实机制动；交底书不是专利法律意见，正式申请前需检索和专业审查。

### 2026-09-23 — 修复恢复凭据与导出账本审查缺口

- 改动：恢复协议授权现在要求当前状态仍为 `RECOVERY_CANDIDATE`，并检查最新观测的上下文、时间和风险必须与 proof 一致；中间观测、图/策略/账本变化、失败观测都会使旧 proof 失效。proof ID 纳入签名材料，修改 ID 或复制已使用 proof 不能再次授权。`EvidenceLedger.verify_export` 现在重建父证据 lineage，检查父证据存在、已验证、未过期、策略一致，以及 `supersedes` 的来源和硬停车约束。
- 文件：`ros2_ws/src/guardian_core/guardian_core/recovery_protocol.py`、`evidence_ledger.py`、`tests/test_patent_core.py`、`progress.md`、`task_plan.md`。
- 验证：专利核心测试 `38 passed`；全量 WSL2 测试 `73 passed`；原有六组和专利化五组实验全部通过；Windows `compileall`、前端 `node --check`、`git diff --check` 通过；ROS 2 Jazzy 两包 `colcon build --symlink-install` 成功。
- 风险或后续：当前 proof 签名仍属于进程内完整性校验，尚未接入 DDS 身份、硬件密钥或外部可信执行环境；恢复协议和账本模块仍需接入真实 ROS 2 节点后做端到端时序与故障注入验证。
- 发布状态：本地 `main` 已创建提交；尝试推送 `origin/main` 时 GitHub 返回 `Permission denied (publickey)`，因此本轮变更尚未同步到远程。未复用旧令牌，也未将凭据写入仓库、远程地址或日志。

### 2026-09-23 — `feat: add efficient Jev judgment orchestration`

- 改动：新增本地风险分流、稳定事件指纹、TTL/LRU 复用、并发 single-flight、滚动调用预算、Jev/本地冲突标记和 P50/P95 效率指标；增加离线对照实验。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_efficiency.py`、`tests/test_jev_efficiency.py`、`experiments/run_jev_efficiency_experiments.py`、`docs/jev_advisor.md`、`README.md`、`HANDOFF.md`、`task_plan.md`、`findings.md`、`progress.md`。
- 安全边界：低风险和关键风险由确定性本地规则立即处理；Jev 不参与停车、速度限制、恢复批准或 ROS 2 命令发布。预算耗尽、并发等待超时和 provider 错误都保留本地安全结果。
- 验证：9 个新增 Jev efficiency 行为测试通过直接调用；`compileall`、前端 `node --check` 和 `git diff --check` 通过；离线对照实验通过，原始 12 次远程调用降为 1 次，调用减少 91.7%，低风险和关键风险分别走 `LOCAL_SAFE`/`LOCAL_ENFORCED`。原有六组和专利化五组实验也通过。
- 验证：全量 WSL2 测试 `90 passed`；会话测试 8 passed；高效判断测试 9 passed；事件会话、高效判断、原有六组创新和专利化五组实验全部通过；Windows compileall、前端 `node --check`、`git diff --check` 通过；ROS 2 Jazzy 两包 `colcon build --symlink-install` 成功。
- 未覆盖：真实 API 的延迟、准确率和配额仍需用户提供临时凭据后做受控实验；会话层尚未接入真实 ROS 2 异步 worker。

### 2026-09-23 — `feat: add Jev incident sessions and ledger-bound advice`

- 改动：新增事件会话聚合、最小查询间隔、风险和语义变化触发、`REVIEW_REQUIRED` 滞回恢复、会话 TTL，以及绑定确定性父证据的短期 Jev 软证据。账本校验失败会阻断 Jev 并保持 `CONTAINING`，本地低风险快路径也不能绕过该检查。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`experiments/run_jev_session_experiments.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`task_plan.md`、`findings.md`、`progress.md`。
- 验证：新增会话测试 8 passed；高效判断测试 9 passed；事件会话实验和高效判断实验通过；全量测试正在重跑。实验显示洪泛事件 10 次观测中 9 次会话复用，风险上升进入 `REVIEW_REQUIRED`，稳定窗口后回到 `OBSERVING`，账本异常进入 `LEDGER_BLOCKED/CONTAINING`。
- 边界：Jev 仍不发布 ROS 2 命令、不改变 `SafetySupervisor`、速度包络或恢复协议；当前会话层是纯 Python 离线模块，尚未接入真实 ROS 2 异步 worker。

### 2026-09-23 — Jev incident session review hardening

- 改动：按独立审查结果修复四类会话层缺陷。新增每会话独立锁，保证同一事件的读取、Jev 查询或复用、软证据追加和状态写回不会丢失；不同事件不会被全局锁串行阻塞。账本损坏分支复用统一的 LRU 写回逻辑，持续异常时不会突破 `max_sessions`。
- 语义：会话签名现在包含规范化的 `graph_risk`、`mission_criticality`、`event_confidence`、`source_verified` 和 `parent_evidence_id`，仍排除 event ID、sequence 和自由文本摘要。父证据变更会触发重新查询；若高效判断命中已成功的 Jev 缓存，只允许重新绑定到新的已验证父证据，普通缓存复用不会刷新软证据 TTL。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：会话测试 `12 passed`；全量 WSL2 测试 `94 passed`；事件会话、高效判断、原有六组创新和专利化五组实验均报告 `passed: true`；WSL2 Python compileall 通过。当前改动只在本地 `main`，没有上传 GitHub。
- 安全边界：Jev 仍是旁路建议，不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。当前验证是离线 Python 与既有 ROS 2 包构建，未宣称真实 API 准确率、实机或 Webots 运行结果。

### 2026-09-23 — Cross-session ledger integrity hardening

- 改动：独立复审发现不同事件会话仍可能并发破坏账本哈希链。新增管理器级 `_ledger_lock`，只包住 `EvidenceLedger.verify()` 与 `append()` 的短事务；远程 Jev 调用、本地判断和不同会话的其他状态更新仍可并行。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：跨会话账本竞态测试先失败后通过；会话测试 `13 passed`；全量 WSL2 测试 `95 passed`。事件会话、高效判断、原有六组创新和专利化五组实验仍报告 `passed: true`；ROS 2 Jazzy 两包构建、Python compileall、前端语法检查和 `git diff --check` 通过。当前改动只在本地 `main`，没有上传 GitHub。
- 安全边界：锁只保证账本完整性，不授予 Jev 控制权；Jev 仍不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。
- 本地提交：`394a197 fix: harden Jev incident session concurrency`；工作区已清洁，`.env` 仍被 Git 跟踪。

### 2026-09-23 — Bounded Jev session context hardening

- 改动：会话 ID 和上下文签名不再直接读取原始上下文字段，统一复用 Jev 适配器的 `to_state()` 有界表示；时序码和活动组件去重排序，数值字段保留非法标记以触发重新判断，摘要、事件 ID 和序列号继续排除。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：新增超长上下文回归通过；全量 WSL2 测试 `96 passed`；会话、高效判断、原有六组创新和专利化五组实验及 compileall 已通过，ROS 2 构建和前端语法检查正在本轮最终复核。当前仍只在本地 `main` 开发，不上传 GitHub。
- 安全边界：有界规范化只限制本地判断资源，不改变确定性安全状态机；Jev 仍不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。

### 2026-09-23 — Strict source-verification hardening

- 改动：修复 `bool("false")`/`bool(0)` 与 `True` 等价导致的会话复用绕过。会话签名保留严格原生布尔值，非法来源类型强制重新判断；`False` 或非布尔结果走 `SKIPPED_UNVERIFIED` 并进入 `CONTAINING`。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：来源类型回归先失败后通过；全量 WSL2 测试 `97 passed`；会话、高效判断、原有六组创新和专利化五组实验、compileall、ROS 2 Jazzy 两包构建、前端语法检查和 `git diff --check` 均通过。仍只在本地 `main` 开发，不上传 GitHub。
- 安全边界：非布尔来源不会触发远程调用，也不能解除已有的 `CONTAINING` 或 `SAFE_STOP` 状态。

### 2026-09-23 — Direct Jev advisor provenance hardening

- 改动：修复基础 `JevSemanticAdvisor.evaluate()` 的真值判断漏洞。现在只有原生布尔 `True` 才能进入配置、缓存和传输逻辑；`"false"`、`0` 等值统一返回 `SKIPPED_UNVERIFIED`。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_advisor.py`、`tests/test_jev_advisor.py`、`docs/jev_advisor.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：直接适配器回归先失败后通过；全量 WSL2 测试 `98 passed`；会话、高效判断、原有六组创新和专利化五组实验、compileall、ROS 2 Jazzy 两包构建、前端语法检查和 `git diff --check` 均通过。仍只在本地 `main` 开发，不上传 GitHub。
- 安全边界：此修复只收紧来源门控，不改变 Jev 旁路权限；Jev 仍不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。

### 2026-09-23 — Observation-time input hardening

- 改动：新增有限时间解析路径。`now` 为非数字、`NaN`、无穷或不可转换对象时使用注入时钟，只有时钟也无效时才回退到有限的 `0.0`；正常 TTL 和软证据过期规则保持不变。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`docs/jev_session_design.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：非法时间回归先失败后通过；全量 WSL2 测试 `99 passed`；会话、高效判断、原有六组创新和专利化五组实验、compileall、ROS 2 Jazzy 两包构建、前端语法和 `git diff --check` 均通过。仍只在本地 `main` 开发，不上传 GitHub。
- 安全边界：时间回退只处理输入格式错误，不授予 Jev 控制权，也不会让未来时间延长软证据寿命。

### 2026-09-23 — Monotonic session time hardening

- 改动：修复有限但倒退的时间戳会回写 `last_seen`、延长 TTL 和制造负查询间隔的问题。现在同一事件会话的观测时间在读取记录后钳制到已有 `last_seen`。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`docs/jev_session_design.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：时间回退回归先失败后通过；全量 WSL2 测试 `100 passed`；会话、高效判断、原有六组创新和专利化五组实验、compileall、ROS 2 Jazzy 两包构建、前端语法和 `git diff --check` 均通过。仍只在本地 `main` 开发，不上传 GitHub。
- 安全边界：钳制只保护会话时间线和软证据时效，不改变 Jev 旁路权限或解除安全状态。

### 2026-09-23 — Jev parent-evidence lifetime hardening

- 改动：将父证据生命周期纳入 Jev 会话的前置门控和账本写回事务。父证据必须当前 active、已验证、策略版本一致、来源/类型属于确定性证据，并通过完整 lineage 校验；父证据失效时不查询 provider。provider 运行期间再次验证父证据，发现替代或过期则进入 `LEDGER_BLOCKED/CONTAINING`。缓存的成功判断重新绑定父证据时沿用原软证据绝对截止时间，截止后缓存命中不能续租或复活，新的软证据必须来自新的 provider 成功结果。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`experiments/run_jev_session_experiments.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：新增父证据缺失/过期/未来/未验证/策略不一致/被替代/祖先失效、调用期间替代、缓存重绑定 TTL 和过期不续租回归；WSL2 全量测试 `114 passed`；事件会话、高效判断、原有创新和专利化实验全部通过；ROS 2 Jazzy 两包构建成功；Windows `compileall`、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查通过。
- 安全边界：Jev 仍是旁路建议，不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复；本轮没有外部 API 调用或 GitHub 上传。

### 2026-09-23 — Jev adapter clock hardening

- 改动：为 `JevSemanticAdvisor` 和 `JevEfficientJudge` 增加有限、单调不减的时钟读取。非法或非有限时钟值回退到上一有效时间，首次异常回退到 `0.0`；回退时间被钳制，保护缓存过期、滚动调用预算、延迟指标和软证据时间戳。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_advisor.py`、`ros2_ws/src/guardian_core/guardian_core/jev_efficiency.py`、`tests/test_jev_advisor.py`、`tests/test_jev_efficiency.py`、`docs/jev_advisor.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：新增非法时钟和回退时钟回归；Jev advisor/efficient judge 定向测试 `22 passed`；WSL2 全量测试 `118 passed`；事件会话、高效判断、原有创新和专利化实验全部通过；ROS 2 Jazzy 两包构建成功；Windows `compileall`、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查通过。
- 安全边界：时钟保护只维护缓存、预算、审计时间和旁路软证据的时序一致性，不赋予 Jev 控制机器人、解除 `SAFE_STOP` 或批准恢复的权限。

### 2026-09-24 — Jev layered-cache lease hardening

- 改动：修复高效判断层在自身 TTL 到期后接收 advisor `CACHED` 结果并重新写入上层 TTL 的问题。现在 `_put_cache` 只允许新鲜 `OK` 结果建立高效层缓存租约；下层缓存结果仍可返回给会话，但不能让高效层无限续租。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_efficiency.py`、`tests/test_jev_efficiency.py`、`docs/jev_advisor.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：新增分层缓存 TTL 回归，修复前复现上层 `CACHE` 续租，修复后 Jev advisor/efficient-judge 定向测试 `24 passed`；WSL2 全量测试 `119 passed`；事件会话、高效判断、原有创新和专利化实验全部通过；ROS 2 Jazzy 两包构建成功；Windows `compileall`、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查通过。
- 安全边界：缓存租约修复只限制语义建议复用成本和时效，不改变 Jev 旁路权限或机器人安全状态机。

### 2026-09-24 — Jev reuse outcome hardening

- 改动：修复 single-flight 等待者将 `INVALID`/`UNAVAILABLE`/`DISABLED` 等失败结果误标为 `CACHED` 的问题；失败共享结果现在保留原 status/reason 并返回 `UNAVAILABLE` 路由。修复普通缓存命中丢失 `disagreement` 的问题，缓存和并发复用均按当前调用方的确定性本地分流重新计算冲突，使会话仍能进入 `REVIEW_REQUIRED`。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_efficiency.py`、`tests/test_jev_efficiency.py`、`tests/test_jev_incident_session.py`、`docs/jev_advisor.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：新增 5 种失败状态的并发复用、成功冲突复用、普通缓存冲突和会话复核回归；定向 Jev/会话测试 `54 passed`；WSL2 全量测试 `130 passed`；事件会话、高效判断、原有创新和专利化实验全部通过；ROS 2 Jazzy 两包构建成功；Windows `compileall`、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查通过。
- 安全边界：结果传播修复只恢复失败和冲突的审计语义，Jev 仍不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。

### 2026-09-24 — Jev completion-time parent validation

- 改动：修复 provider 执行期间父证据过期或 lineage 失效仍可能通过初始时间检查的问题。会话在判断完成后用内部时钟测量经过时间，将其映射到显式回放时间的原点，并在统一账本临界区重新验证 parent/ancestor/ledger；失败 provider 也必须通过该检查。软证据的截止时间仍从观测时刻计算，但迟到结果只能使用剩余租约，已耗尽的 TTL 不会写入。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_incident_session.py`、`tests/test_jev_incident_session.py`、`experiments/run_jev_session_experiments.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：新增 provider 延迟导致父/祖先过期、替代、篡改、失败返回和显式回放时间边界测试；session 测试 `47 passed`，WSL2 Ubuntu-24.04 全量测试 `145 passed`，延迟父证据实验返回 `LEDGER_BLOCKED/CONTAINING` 且 provider 仅调用一次；四组离线实验、ROS 2 Jazzy 两包构建、Windows compileall、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查均通过。独立复审未发现 P0–P2 风险。
- 安全边界：完成时刻校验只收紧软证据有效性，不授予 Jev 控制机器人、解除 `SAFE_STOP`、修改速度限制或批准恢复的权限。

### 2026-09-24 — Concurrent Jev budget rollover hardening

- 改动：修复高效判断层在 cache lookup 后被挂起的旧请求使用过时时间重置新调用预算窗口的问题。预算时间现在在 reservation lock 内重新采样，provider 缓存租约也从该新鲜时间开始；没有改变固定窗口配置、provider 权限或本地安全分流。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_efficiency.py`、`tests/test_jev_efficiency.py`、`experiments/run_jev_efficiency_experiments.py`、`docs/jev_advisor.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：并发预算回归修复前 `2 failed`、修复后 `2 passed`；高效判断定向测试 `24 passed`，离线效率实验通过并验证 `REMOTE → BUDGET_EXHAUSTED → BUDGET_EXHAUSTED → REMOTE` 路由。全量测试、ROS 2 构建、最终复审和本地提交待本轮完成。
- 安全边界：预算修复只防止 Jev 资源窗口被旧并发请求回滚，不改变 Jev 旁路权限；Jev 仍不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。

### 2026-09-24 — Concurrent Jev budget/cache rollover hardening

- 改动：在同一并发时序中，高效层的旧缓存查找也可能以过时时间复活已过期建议。现在缓存过期判断和预算预约都在状态锁内重新采样有限单调时钟，provider 租约从新鲜预约时间开始。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_efficiency.py`、`tests/test_jev_efficiency.py`、`experiments/run_jev_efficiency_experiments.py`、`docs/jev_advisor.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：预算竞态回归修复前 `2 failed`、修复后 `2 passed`；过期缓存竞态回归修复前 `1 failed`、修复后 `1 passed`；高效判断定向测试 `25 passed`，离线效率实验验证预算窗口和过期缓存两条路径；WSL2 全量测试 `147 passed`，四组离线实验、ROS 2 Jazzy 两包构建、Windows compileall、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查均通过，独立复审无 P0–P2。
- 安全边界：本轮只限制 Jev 缓存和调用预算的并发时序，不改变 Jev 旁路权限；Jev 仍不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。

### 2026-09-24 — Advisor cache completion-time hardening

- 改动：修复基础 advisor 在 cache key 计算后被挂起时，使用旧时间复用已过期 `CACHED` 结果的问题。缓存锁内重新采样有限单调时钟后，过期结果会重新进入 provider；高效层和 advisor 的 TTL 时序规则保持一致。
- 文件：`ros2_ws/src/guardian_core/guardian_core/jev_advisor.py`、`tests/test_jev_advisor.py`、`experiments/run_jev_efficiency_experiments.py`、`docs/jev_advisor.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：advisor 竞态回归修复前 `1 failed`、修复后 `1 passed`；离线效率实验报告 advisor 过期缓存路径 `OK` 且 provider 调用 `2` 次；WSL2 全量测试 `149 passed`，四组离线实验、ROS 2 Jazzy 两包构建、Windows compileall、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查均通过。第一次全量运行仅因既有回退时钟夹具值不足而失败，扩展为持续回退值后通过。
- 安全边界：本轮只收紧语义建议缓存时效，不改变 Jev 旁路权限，也不授予其控制 ROS 2 或解除安全状态的能力。

### 2026-09-24 — Strict evidence trust-flag hardening

- 改动：`Evidence` 的 `verified` 与 `hard_stop` 现在必须是原生 Boolean。候选证据在账本任何状态修改前先校验；父证据、活动 lineage、替代关系、实时 `verify()` 和 `verify_export()` 都拒绝非布尔信任标记。即使旧记录被攻击者重新计算哈希，字段语义错误仍会使账本验证失败。
- 文件：`ros2_ws/src/guardian_core/guardian_core/evidence_ledger.py`、`tests/test_patent_core.py`、`tests/test_jev_incident_session.py`、`experiments/run_jev_session_experiments.py`、`docs/jev_session_design.md`、`README.md`、`HANDOFF.md`、`findings.md`、`progress.md`、`task_plan.md`。
- 验证：非布尔构造、候选写回不变、重哈希记录实时/导出校验、父子/替代 lineage 和 Jev 新建/复用会话回归均通过；WSL2 `python3 -m pytest -q tests` 为 `168 passed`。离线会话实验报告 `non_boolean_ancestor_route=LEDGER_BLOCKED`、`state=CONTAINING`、`provider_calls=0`、`non_boolean_export_accepted=false`；全部五个离线脚本、ROS 2 Jazzy 两包构建、Windows compileall、前端 `node --check`、`git diff --check` 和 `.env` 跟踪检查均通过。首次 Bash 循环因 PowerShell 变量转义失败，改为显式脚本命令后通过。
- 安全边界：此修复只收紧证据信任字段的类型和 lineage 完整性；Jev 仍是旁路建议，不能发布 `/cmd_vel`、解除 `SAFE_STOP`、修改速度限制或批准恢复。没有调用外部 provider、写入密钥或上传 GitHub；提交仅进入本地 `main`。

### 2026-09-24 — GitHub publication and local ROS 2 runtime

- 改动：确认仓库完整历史和 `.env` 均在本地 `main`；将 `origin` 切换为 HTTPS，通过 Windows Git Credential Manager 的已保存用户凭据准备同步；创建 WSL 系统级 `guardian-core.service` 和 `guardian-dashboard.service` 运行 ROS 2 核心与 dashboard。原 `8080` 被其他服务占用，dashboard 使用 `127.0.0.1:8088`。
- 验证：Ubuntu-24.04 `python3 -m pytest -q tests` 为 `168 passed`；ROS 2 Jazzy 两包构建成功；`guardian-core.service`、`guardian-dashboard.service` 均为 `active`；`/guardian/risk_state`、`/guardian/mitigation_command`、`/guardian/safety_status` 可见，`/guardian/safety_status --once` 返回 `NORMAL`、`mission_allowed=true`、`speed_limit≈0.35`；Windows `http://127.0.0.1:8088/api/health` 返回 HTTP 200。
- 发布状态：GitHub API 已确认仓库 `thy10086/ros2-resilience-guardian` 为公开仓库、默认分支为 `main`；完整本地 `main` 已推送到 `origin/main`，远端与本地提交一致，远端树包含 87 个文件且保留 `.env`。不上传任何密钥，Jev 面板未执行真实 provider 调用。

### 2026-09-24 — Dashboard login and WSL runtime persistence

- 改动：新增 dashboard 本地会话认证，默认用户名和密码均为 `admin`；`/api/state`、`/api/jev/test` 需要 HttpOnly、SameSite 会话 Cookie，健康检查保持公开，退出登录立即撤销会话。前端增加登录门、退出按钮和登录过期处理。`DashboardHTTPServer` 允许地址复用，减少服务重启时的端口占用窗口。
- 根因修复：用户访问失败是因为 WSL 没有前台长进程时会回收实例，systemd 和 8088 一起消失。运行配置改为 WSL 系统级服务，并用隐藏的 `sleep infinity` 保持实例运行；服务仍以普通用户 `rob` 执行 ROS 2 进程。
- 文件：`ros2_ws/src/guardian_core/guardian_core/dashboard_auth.py`、`dashboard.py`、`frontend/index.html`、`frontend/app.js`、`frontend/styles.css`、`tests/test_dashboard_auth.py`、`README.md`、`HANDOFF.md`、`task_plan.md`、`findings.md`、`progress.md`。
- 验证：认证定向测试 `3 passed`，全量测试 `171 passed`，ROS 2 Jazzy 两包重新构建成功，Windows `node --check`/compileall/diff 检查通过。HTTP smoke test 验证未登录 `/api/state` 为 401、`admin/admin` 登录为 200、登录后状态读取为 200、退出后再次为 401；Windows `http://127.0.0.1:8088/api/health` 返回 200，状态为 `NORMAL`。
- 安全边界：这是本机实验登录，不是生产身份认证；默认凭据只用于本地 demo，未写入 `.env` 或任何外部日志。Jev 仍为旁路建议，未执行真实 provider 调用，也不能控制机器人。

### 2026-09-24 — Final local access regression

- 验证：WSL `python3 -m pytest -q tests` 为 `171 passed`；`colcon build --symlink-install --packages-select guardian_interfaces guardian_core` 两包构建成功；Windows 8088 smoke test 验证 `/api/health=200`、未登录 `/api/state=401`、`admin/admin` 登录为 200、登录后状态为 200、退出后状态为 401。
- 工程维护：验证命令从仓库根目录运行时会生成根级 `build/`、`install/`、`log/`，已加入 `.gitignore`，避免构建产物污染提交；`.env` 继续由 Git 跟踪。

### 2026-09-24 — Login input race fix

- 根因：未登录页面仍由全局一秒定时器请求受保护的 `/api/state`；每次 401 都调用 `showLogin()` 并清空密码框，导致输入过程被定时刷新打断。
- 改动：`frontend/app.js` 增加内存中的 `authenticated` 状态；未登录时暂停状态轮询，登录成功后恢复轮询，退出或会话过期后再次暂停。认证接口和后端会话策略不变。
- 验证：浏览器 DOM 检查确认用户名、密码控件均可见且未禁用；修复后可输入 `admin/admin` 并进入 dashboard。随后应继续执行 HTTP 登录 smoke test 和全量测试。
