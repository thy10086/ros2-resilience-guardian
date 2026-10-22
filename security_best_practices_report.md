# ROS 2 Resilience Guardian 代码审计报告（修复前基线）

审计日期：2026-09-29
审计边界：只运行、观察和静态审计；本轮未修改功能代码、配置或测试。

> 状态说明：本文记录的是本轮修复前的审计基线，不是当前实现的最终状态。
> 后续修复结果、最新测试数和仍然存在的生产边界以 `HANDOFF.md` 顶部条目及
> `docs/deployment.md` 为准。本文中的 P1-1、P1-2、P1-3、P2-1、P2-2、P2-3
> 和 P2-4 已在后续工作区改动中得到对应处理；SROS2/DDS 身份、硬件反馈、
> HIL/实机验收等生产边界仍未被本地仿真替代。

## 结论摘要

当前项目的纯 Python 安全核心、ROS 2 消息接口和测试体系基本协调，单元测试覆盖了大量输入校验、风险计算、计划生成、反馈序列和部署脚本行为。但当前版本仍不能作为生产机器人安全控制器发布，主要原因不是单个算法错误，而是执行身份、启动握手、实时性上界和真实执行器边界尚未闭合。

最高优先级结论：

1. ROS 2 生产身份边界尚未实现。`MitigationAck` 没有消息级认证，Guardian 只匹配字段；默认配置关闭事件签名，systemd 服务也没有启用 SROS2/DDS 权限。
2. 默认 `all` 启动方式可稳定进入永久 `SAFE_STOP`：启动阶段的 ACK/命令时序存在竞态，模拟器跳过第一个 epoch 后永久锁定排序故障。
3. 模拟器在收到 Guardian 的首个有效安全状态前默认允许运动，启动/重置状态不是 fail-closed。
4. 隔离子集搜索是指数级组合搜索。20 个同时受攻击关键资源的压力探针耗时约 14.75 秒，不能保证 10 Hz 安全循环的实时性。

## 验证结果

| 检查项 | 结果 |
| --- | --- |
| Humble 构建 | 通过，`guardian_interfaces` 和 `guardian_core` 均构建成功 |
| 全量测试 | 通过，`433 passed` |
| Python 编译 | 通过，`compileall` |
| 前端语法 | 通过，`node --check` |
| Git 空白检查 | 通过，`git diff --check` |
| 覆盖率 | 约 85%；Dashboard、上传和部分隔离路径仍有明显未覆盖分支 |
| Dashboard HTTP 健康检查 | `/api/health` 返回 200；未登录状态接口返回 401；登录流程可用 |
| 沙箱运行时 | 当前 WSL 使用 `unshare-userns`，代码执行边界明确标注为本地工程测试，不是多租户隔离 |

测试全绿不代表实时闭环安全。启动竞态、真实 DDS 身份、浏览器暴露边界和组合搜索压力不在现有测试的充分覆盖范围内。

## P0：生产发布阻断

### P0-1 ROS 2 执行身份和 ACK 身份认证缺失

证据：

- [guardian_node.py](ros2_ws/src/guardian_core/guardian_core/guardian_node.py) 的 `on_mitigation_ack()` 只比较 `profile_id`、`adapter_id`、epoch、transmission、计划、动作、组件和反馈序列，没有验证 ACK 的发布者身份或密码学签名。
- [MitigationAck.msg](ros2_ws/src/guardian_interfaces/msg/MitigationAck.msg) 没有签名或认证字段。
- [configs/guardian.yaml](configs/guardian.yaml) 默认 `require_signature: false`。
- [guardian@.service](deploy/guardian@.service) 没有配置 `ROS_SECURITY_ENABLE`、`ROS_SECURITY_STRATEGY`、DDS governance/permissions、域隔离或节点身份。

实证：审计探针构造一个完全匹配当前命令的 ACK，Guardian 将其接受为有效反馈；ACK 没有签名字段。字段匹配可以防重放和错配，但不能证明消息来自真实执行适配器。

影响：

- 同一 ROS 2 域内能够观察命令的未授权节点可以伪造匹配 ACK，阻止反馈 watchdog 进入 `SAFE_STOP`。
- 未授权节点还可能伪造 `MitigationCommand`、`SafetyStatus` 或攻击事件，形成运动授权、拒绝服务或状态污染。
- 这与“生产安全控制器”的信任模型不一致。

生产要求：

- 为 Guardian、执行适配器、传感器监视器和控制器建立独立 DDS 身份。
- 使用 SROS2/DDS-Security permissions 限制每个节点对命令、状态和 ACK 主题的发布/订阅权限。
- 执行适配器只接受授权 Guardian 发布者，并将真实制动器/驱动器反馈与 ACK 分开建模。
- 在完成端到端身份、密钥轮换、权限拒绝和攻击节点测试前，不允许连接真实执行器。

## P1：已复现或会破坏安全闭环的问题

### P1-1 启动 ACK 竞态导致默认 `all` 永久 SAFE_STOP

涉及：

- [guardian_node.py](ros2_ws/src/guardian_core/guardian_core/guardian_node.py)
- [amr_simulator.py](ros2_ws/src/guardian_core/guardian_core/amr_simulator.py)
- [guardian.yaml](configs/guardian.yaml)

复现序列：

1. 模拟器启动时使用 epoch 0 / transmission 0 占位状态。
2. Guardian 发布第一个有效命令 epoch 1。
3. 在默认 `feedback_timeout_sec: 0.5` 内，模拟器可能还没有处理 epoch 1。
4. Guardian watchdog 发布 epoch 2 的 `SAFE_STOP`。
5. 模拟器首次收到 epoch 2，认为 epoch 跳跃，设置 `_ordering_fault` 并永久拒绝后续命令。
6. Guardian 收不到有效 ACK，继续锁存 `SAFE_STOP`。

实际观察到的消息序列包含：

```text
CMD epoch=1 action=NONE
ACK epoch=0 transmission=0
CMD epoch=2 action=SAFE_STOP
SIM epoch=2 ordering fault
```

影响：默认全量启动不能进入可用的正常闭环，Dashboard 的启动、攻击和重置操作都只显示/保持 `SAFE_STOP`。

建议：

- 增加独立的启动握手状态，不要把 epoch 0 占位 ACK 当成正常运行反馈。
- 在发现阶段和第一个有效命令之间设置启动 grace period。
- 对首次合法 epoch 提供明确 bootstrap/resynchronization 协议；发生跳跃时继续 fail-closed，但要有可审计的重新同步路径。
- 加入真实进程启动顺序、DDS discovery 延迟和慢适配器测试。

### P1-2 模拟器启动/重置状态不是 fail-closed

[amr_simulator.py](ros2_ws/src/guardian_core/guardian_core/amr_simulator.py) 初始化时将 `safety_state` 设为 `NORMAL`、`mission_allowed` 设为 `True`、`command_accepted` 设为 `True`，并把安全身份初始化为 `(0, 0)`。在收到 Guardian 的首个安全状态和缓解命令前，点击 `start` 后模型即可产生 `0.20 m/s` 实际速度。

实证：

```text
start -> update(0.1)
actual_speed = 0.2
command identity = (0, 0)
```

影响：真实适配器若沿用相同语义，启动或复位窗口可能在安全授权建立前运动。

建议：初始化和 reset 都应保持停止、任务禁止、未确认命令状态；必须收到经认证且身份匹配的当前命令和安全状态后才允许运动。

### P1-3 隔离候选子集搜索存在指数级实时性风险

[planner.py](ros2_ws/src/guardian_core/guardian_core/planner.py) 使用 `combinations()` 枚举所有非空隔离子集。若没有显式 containment policy，最坏情况接近 `2^N` 次风险评估。

压力探针结果：

```text
20 个关键资源同时受攻击
planner.plan() 约耗时 14.75 秒
```

影响：Guardian 的 10 Hz tick 可能被阻塞，进而延迟状态发布、ACK 处理和 watchdog；资源数量还可由安全 profile 扩展，缺少硬上限。

建议：

- 限制单次规划的活动资源数量和计算预算。
- 使用确定性的最小割/贪心策略，或在超预算时直接 `SAFE_STOP`。
- 将复杂优化移出实时线程，实时线程只消费已验证的有界计划。
- 增加 8、16、20、32 资源的最坏时延和 watchdog 竞争测试。

### P1-4 Dashboard 重置与 Guardian watchdog 生命周期不一致

前端在重置仿真后提示 Guardian 会在攻击 TTL 到期后恢复 `NORMAL`，但 Guardian watchdog 一旦锁存就保持 `SAFE_STOP`，直到进程重启；reset 只调用模拟器的 `__init__()`，不会清除 Guardian 的攻击登记、watchdog latch 或命令 epoch。

涉及：

- [app.js](ros2_ws/src/guardian_core/guardian_core/frontend/app.js)
- [amr_simulator.py](ros2_ws/src/guardian_core/guardian_core/amr_simulator.py)
- [guardian_node.py](ros2_ws/src/guardian_core/guardian_core/guardian_node.py)

影响：用户看到“场景已重置”，但安全闭环不会恢复；这会把演示控制、故障复位和生产恢复混为一谈。

建议：将“仿真 reset”和“安全恢复”分成两个操作；恢复必须接入已有的双阶段恢复协议、真实传感器新鲜度、命令清空、图稳定和人工/授权确认，不应由普通 Dashboard reset 清除锁存。

## P2：重要风险和可观测性缺口

### P2-1 Dashboard 展示的是“已发布”，不是“已执行”

Dashboard 只订阅风险、缓解命令和安全状态，没有订阅 `guardian/mitigation_ack`。`DashboardState` 也没有保存 `profile_id`、epoch、transmission、adapter、feedback sequence 等身份字段。

影响：页面可以显示 Guardian 已发布 `SAFE_STOP` 或隔离命令，但无法显示真实适配器是否接受、执行和持续确认；运维人员容易把命令发布误判成物理执行完成。

### P2-2 Dashboard 允许迟到消息覆盖新状态

`DashboardState._update()` 直接替换类别状态并更新 `updated_at`，没有按 timestamp、epoch 或 transmission 拒绝旧消息。审计探针先写入 timestamp 10 的 `NORMAL`，再写入 timestamp 5 的 `SAFE_STOP`，最终页面状态确实被旧消息覆盖为 timestamp 5。

影响：多发布者、网络重排或恢复时可能出现过期状态覆盖当前状态，造成错误运维判断。

建议：按 profile/adapter/epoch/transmission 建立每类消息的高水位；迟到状态只进入审计时间线，不得覆盖当前快照。

### P2-3 Dashboard 远程暴露边界不安全

当前实现适合 localhost 演示，但没有强制保持本地绑定：

- [dashboard_auth.py](ros2_ws/src/guardian_core/guardian_core/dashboard_auth.py) 默认账号密码为 `admin/admin`。
- [dashboard.py](ros2_ws/src/guardian_core/guardian_core/dashboard.py) 接受任意 `host` 参数。
- 登录 cookie 没有 `Secure` 属性；服务是明文 HTTP。
- JSON 仅设置 `X-Content-Type-Options`；静态资源缺少 CSP、`X-Frame-Options` 等响应头。
- 没有登录失败限速或锁定策略。
- `ThreadingHTTPServer` 和上传/沙箱接口没有全局并发预算。

在 `0.0.0.0` 或局域网绑定时，这些问题会从本地演示风险升级为远程凭据、会话和资源消耗风险。

建议：非 localhost 时拒绝启动，或强制外部 TLS 反向代理并要求非默认凭据；增加 `Secure`/严格 cookie 策略、CSP、登录限速、请求超时和并发预算。

### P2-4 事件登记和审计日志缺少硬上限

`AttackRegistry` 按唯一 `(source, event_id)` 保留活动记录，`AuditLogger` 直接追加文件，没有事件数量、日志大小、轮转或磁盘配额。受信源被攻陷或同域攻击节点持续产生新事件时，可能造成内存、CPU 和磁盘消耗。

建议：为活动事件、每周期事件数、日志文件大小和总磁盘空间设置上限；超过上限时记录一次受控告警并 fail-closed，不要让日志写入异常直接影响主循环。

## P3：工程一致性问题

1. 前端错误提示提到 `guardian-dashboard.service`，仓库中实际没有同名 service 文件，部署文档使用的是 `guardian@.service` 模板。
2. `guardian@.service` 与兼容的 `guardian-simulator.service` 可以被同时启用，造成重复 simulator、重复 `/cmd_vel` 和重复 ACK 发布；部署文档应明确二选一。
3. 本地 `.env` 已被 Git 跟踪，但当前内容只包含非秘密默认项，未发现实际 API Key。后续仍建议让 `.env` 只作为示例文件，真实凭据保持在外部 secret store。

## 尚未验证的生产项目

- 真实底盘、制动器、PLC、安全 IO、硬件急停和独立 watchdog。
- SROS2/DDS-Security 身份、权限拒绝、证书轮换和多机器人隔离。
- Jazzy 实机/目标环境上的构建、发现、时序和 QoS 行为；本轮本机实际验证为 Humble。
- 多节点、多适配器、多机器人同时发布同名主题时的 profile/adapter 隔离。
- 真实网络丢包、延迟、重连、时钟跳变和 executor 抢占。
- Gazebo/Webots/硬件在环中的碰撞、制动距离和传感器新鲜度。

## 建议整改顺序

1. 先建立 SROS2/DDS 身份与权限边界，并完成真实适配器 ACK/制动反馈契约。
2. 修复启动握手和 fail-closed 初始状态，增加真实进程时序测试。
3. 给实时规划增加有界算法和预算，超预算直接安全停车。
4. 分离仿真 reset 与生产恢复，接入双阶段恢复协议。
5. 修复 Dashboard 的 ACK 可观测性、迟到消息处理和远程暴露策略。
6. 增加资源/日志/并发上限，再进行硬件在环和故障注入验收。
