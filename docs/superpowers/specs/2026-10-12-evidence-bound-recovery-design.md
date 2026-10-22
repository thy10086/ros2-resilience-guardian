# 面向 ROS 2 机器人的证据与上下文绑定安全恢复机制：最小闭环

用户已确认采用前轮提出的 AMR 最小闭环，本轮先检索开源工具，再增量集成；保留现有未提交工作，不自动提交或部署服务。

## 范围与复用

复用 rclpy 原生 graph introspection、现有 EventVerifier、EvidenceLedger、PredictiveEnvelope、RecoveryProtocol、命令/ACK HMAC 和 AMR 工程仿真。新代码只承担观测认证、上下文提取和闭环协调。无新增第三方运行依赖。

开源查阅记录（2026-10-12）：

| 工具 | 来源及许可 | 本轮决策 |
| --- | --- | --- |
| ROS 2 rclpy | https://github.com/ros2/rclpy/blob/humble/rclpy/rclpy/node.py ，Apache-2.0 | 直接调用发布者/订阅者发现 API，不另造发现协议；端点身份是观测信息，不是 DDS 身份认证 |
| Python hmac | https://docs.python.org/3/library/hmac.html ，Python 标准库/PSF | 直接用 HMAC-SHA256、compare_digest；复用现有规范 JSON 签名 |
| Nav2 Collision Monitor | https://github.com/ros-navigation/navigation2/tree/humble/nav2_collision_monitor ，Apache-2.0 | 留作后续物理限速基线；本轮已有二维工程仿真，无 Nav2 导航栈，不复制其代码、不冒充其物理验证 |
| ROS 2 launch_testing | https://github.com/ros2/launch/tree/humble/launch_testing ，Apache-2.0 | 后续多进程入口可采用；本轮复用仓库已有真实 ROS 2 executor/pytest 集成设施，不再引入第二套测试框架 |

## 数据与控制链

AMR 发布新的类型化、HMAC 认证的 RecoveryTelemetry：观测序列、当前命令 epoch/传输号、profile/adapter、实际速度、净距、传感器新鲜度、攻击是否持续、旧命令是否清空、探测是否通过。Guardian 用接收端单调时钟决定新鲜度，拒绝重复序列、错配身份和错误签名。

图上下文使用命令、状态和恢复观测三个固定控制话题的 live endpoints，包含端点 GID 与消息类型。只绑定相关图，避免无关 dashboard 节点抖动。发现失败/缺少必要端点禁止恢复。策略指纹绑定 profile、遏制策略和预测/恢复配置。

启用模式默认先停车：确定性事件与本地物理约束触发/保持停车；停止 ACK 和新鲜健康观测齐备后，稳定观察、签发短期一次性凭据，在下一控制周期重新校验上下文后授权第一条恢复命令。计划 ID 包含凭据 ID，现有认证命令与状态将其绑定到执行器接受的 epoch。签发与使用跨周期，以便验证 TOCTOU。

告警不再因 TTL 自动代表攻击解除。仅 amr_simulator 来源事件可由该可信仿真适配器的健康观测解除；其他来源事件保持未解决状态。本轮不实现通用 IDS 解除协议。健康 heartbeat 不逐条追加账本；只在安全相关状态改变时追加，避免全账本锚点持续变化导致无法恢复。账本设置容量边界，达到上限失败停车。

## 安全边界

默认配置为 AMR 开启闭环；节点参数 evidence_bound_recovery 默认 false 保持现有裸节点调用兼容。启用时必须有反馈密钥，且 profile 必须是 amr-default/default-actuator。watchdog 故障、错误配置及账本完整性错误仍保持停车，不被恢复机制解除。

HMAC 证明独立随机密钥替代公开字段 SHA-256 校验和；凭据在 Guardian 进程内消费，不宣称分布式可验证证书。执行器继续校验已有命令签名、epoch/传输号与状态配对。模拟 reset 清理场景并保持停车，不能直接恢复运动。

## 验收

纯核心测试覆盖稳定观察后恢复、签发后图/策略/账本/epoch变化拒绝、凭据重放、伪造签名、观测中断、持续攻击、正常 heartbeat 不改变锚点、容量上限。真实 ROS 2 集成测试覆盖 startup→停车 ACK→健康观测→恢复→运动，以及攻击→停车→超过告警 TTL仍停车→reset→重新观察→恢复。另验证新增相关图端点阻止已签发许可。

验证目标是 Ubuntu-22.04 / ROS 2 Humble 的软件闭环，不是 Gazebo/Webots、真实制动或生产安全认证。
