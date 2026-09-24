# ROS 2 AMR 闭环工程仿真

本项目的仓储案例现在有两种互补的实验模式：

- 防护实验室：把固定 `guardian-replay/v1` 文件送入同一套校验、登记、风险、缓解和安全监督逻辑，适合复盘每一个事件的判定。
- 工程仿真：启动 `amr_simulator`，让控制台命令进入 ROS 2 话题，再让 Guardian 的安全反馈回到仿真节点，适合证明防护结果改变了实际运动输出。

## 闭环数据流

```text
工程仿真页面
    │ POST /api/simulation/control
    ▼
guardian_dashboard ── /amr_07/sim_control ──▶ amr_simulator
                                               │
                  /cmd_vel ◀──────────────────┤ 安全限幅后的运动
                  /amr_07/odom ◀───────────────┤ 差速轮位置
                  /amr_07/gripper_state ◀─────┤ 托盘/抓取器状态
                                               │ guardian/attack_events
                                               ▼
                                          guardian_node
                                               │
                        safety_status / mitigation_command
                                               └──────────────▶ amr_simulator
```

`amr_simulator` 内部使用小步长差速轮模型：

```text
actual_speed = 0                         （任务停止、任务被禁止或 SAFE_STOP）
actual_speed = min(requested_speed,     （其余情况）
                   guardian_speed_limit)
x(t + Δt) = min(route_length, x(t) + actual_speed × Δt)
```

正常搬运请求 `0.20 m/s`，超速注入请求 `0.62 m/s`。因此页面同时显示请求速度和
实际速度：攻击发生后前者保持 `0.62`，后者由 Guardian 反馈降为 `0` 或安全包络值，
可以直接区分“攻击者想做什么”和“安全边界允许做什么”。

## 可复现实验

| 操作 | ROS 2 事件 | 预期 Guardian 结果 | 可观测证据 |
| --- | --- | --- | --- |
| 启动托盘任务 | 无攻击事件 | `NORMAL`，任务允许 | `phase=DOCK_TO_PALLET`，实际速度约 `0.20` |
| 注入超速 | `UNSAFE_COMMAND`, `sequence=7001` | `CONTAINING`，隔离/限速 | 请求 `0.62`，实际 `0`，速度上限下降 |
| 注入重放 | 两条相同 `sequence=7001` | 第一条接受，第二条 `REPLAY` | 实时时间线和攻击模式 `replay` |
| 注入抓取器故障 | `SEMANTIC_MISBEHAVIOR`, `right_arm` | 右臂进入风险集合 | 抓取力 `45 N → 0 N`，缓解组件包含右臂 |
| 重置场景 | 清除仿真任务和故障模式 | 仿真立即回到 `IDLE`；Guardian 按事件 TTL 过期 | 位置清零、攻击模式为空，默认约 5 秒后 `NORMAL` |

页面操作只允许四个动作和三种攻击类型，后端限制请求体为 4 KiB；仿真节点也会
再次校验字段，未知动作不会进入 ROS 2 图。这样前端是实验控制台，而不是绕过
Guardian 的执行器入口。

## Jev 的边界

Jev 只处理经过 Guardian 事件校验的有界摘要，用于攻击类型、任务影响和人工复核
建议。实时闭环不依赖 API Key，也不把 Jev 输出接到 `/cmd_vel`、速度上限、隔离或
恢复门控。Jev 不可用时，Guardian 仍能完成 `REPLAY`、`CONTAINING`、`SAFE_STOP` 和
实际速度限制；这也是本项目相对于“把大模型放进控制循环”的安全设计改动。

## 当前限制与后续适配

这是笔记本级的确定性工程仿真，不包含轮胎打滑、碰撞动力学、激光雷达噪声或 Webots
渲染。后续可以增加 Webots/`webots_ros2` 适配器，但应只替换运动和传感器适配层，
保留 `guardian/safety_status` 作为最终安全边界，并用同一套攻击事件和验收指标比较
离线回放、数字孪生和物理仿真三种模式。
