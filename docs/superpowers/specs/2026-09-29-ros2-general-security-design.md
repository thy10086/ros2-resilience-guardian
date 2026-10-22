# ROS 2 通用安全控制与运行时验证设计

## 目标

将 ROS 2 Resilience Guardian 从 AMR 场景优先的实验实现，演进为面向任意 ROS 2 机器人和控制系统的通用安全控制与运行时验证边界。AMR 仍保留为默认的可运行 profile 和闭环仿真适配器，但 Guardian 核心不再依赖车辆运动学或 `/cmd_vel` 语义。

本设计针对 ROS 2，不承诺 ROS 1 兼容。用户此前所说的“ros12”按 ROS 2 理解。

## 架构

系统分为四个边界：

```text
ROS 2 事件/检测源
        |
        v
EventVerifier -> AttackRegistry -> RiskEngine -> MitigationPlanner
        |
        v
SafetySupervisor -> MitigationCommand + SafetyStatus
        |
        v
受保护的执行适配器 / ros2_control / 硬件安全 IO
        |
        v
MitigationAck -> Guardian watchdog
```

Guardian 只负责跨设备通用的事件可信度、时序、风险、不变量和缓解决策。真实执行器的速度、关节、末端执行器、飞控或工业 IO 语义由 adapter profile 实现。

## 通用安全 profile

新增 `security_profile_json` 启动参数。profile 至少包含：

- `profile_id`：用于审计和状态观测；
- `adapter_id`：允许回传执行确认的适配器身份；
- `trusted_sources`：允许提交 `AttackEvent` 的来源；
- `resources`：资源名到 `tau`、`epsilon`、`mitigatable` 的映射。

资源名不限定为轮组，可以是关节、控制器、传感器、规划器、通信桥、末端执行器或任意受保护 ROS 2 组件。未知或未列入可隔离集合的受攻击资源必须保守进入 `SAFE_STOP`。

AMR profile 仅提供 `left_wheels`、`right_wheels`、机械臂和距离传感器等示例资源。默认策略仍然只允许当前已实现的 `SAFE_STOP`、`ISOLATE_COMPONENT`、`LIMIT_SPEED` 和 `DEGRADED_RUN`。

## 命令与反馈契约

`profile_id` 在 `RiskState` 和 `SafetyStatus` 中回显，用于多机器人、多适配器部署中的状态归属和审计。`command_epoch` 表示缓解动作语义发生变化；同一个 epoch 可以有多次传输。

每次发布 `MitigationCommand` 都递增 `transmission_id`。执行适配器必须在 `MitigationAck` 中回显：

- `adapter_id`；
- `command_epoch`；
- `transmission_id`；
- 命令计划、动作和组件；
- 严格递增的 `feedback_sequence`。

Guardian 只接受与当前适配器、epoch、传输号和动作内容完全匹配，且反馈序列号严格递增的确认。旧 ACK、重复 ACK、旧传输号 ACK 和伪造适配器身份不能刷新 watchdog。DDS/SROS2 权限仍是生产环境中防止未授权节点发布 ACK 的必要条件；字段匹配本身不是身份认证。

## 时间与顺序

- ROS 时间只用于事件时间戳、状态时间戳和可审计时间线；
- watchdog 使用 `time.monotonic()`，不受 `/use_sim_time` 暂停、回拨或跳跃影响；
- 适配器拒绝旧 command epoch；
- 相同 epoch 只允许完全相同的命令幂等重传；
- epoch 跳跃、同 epoch 冲突命令或状态冲突都必须进入本地安全停止；
- `SafetyStatus` 携带命令 epoch、传输号和适配器身份；适配器只有在安全状态与当前命令完全匹配时才允许运动。

## 错误处理

以下情况保持或锁存 `SAFE_STOP`：

- profile JSON 非法、重复键或缺少必需字段；
- 事件来源未知、字段非法、签名失败、时间过期或序列重放；
- 没有可以恢复不变量的可隔离资源；
- 执行反馈超时、错配、重复或倒退；
- 执行适配器收到旧、跳跃或冲突命令；
- 安全状态来自旧 epoch/传输，无法证明与当前命令一致。

恢复不属于本轮自动放行范围，后续必须通过人工授权、RecoveryGate 和真实硬件状态证明。

## 测试策略

新增单元和 ROS 2 集成回归覆盖：

1. 通用 profile 解析、重复键、未知资源和非法资源配置；
2. transmission/feedback 序列防重放；
3. `/use_sim_time` 不影响 watchdog；
4. 适配器旧命令、epoch 跳跃和同 epoch 冲突；
5. 旧 SafetyStatus 不能恢复运动；
6. 既有 AMR 闭环行为和全量 ROS 2 构建继续通过。

## 生产边界

本项目的仿真 ACK 只证明软件状态，不证明制动器或急停回路已经动作。生产 ROS 2 系统还必须部署 SROS2/DDS 权限、独立硬件 watchdog、急停、安全 IO、真实速度/关节反馈和适配器级故障测试。
