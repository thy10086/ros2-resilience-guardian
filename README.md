# ROS 2 Resilience Guardian

面向 Webots/ROS 2 机器人的任务感知零信任安全韧性守护器。项目基于 RobResilience 的实验思想，加入攻击事件验证、攻击生命周期、动态风险评估、缓解重规划和独立安全状态机。

完整的系统交接、操作记录和后续提交规范见 [HANDOFF.md](HANDOFF.md)。

## 现在能运行什么

- 纯 Python 核心引擎：不依赖 ROS 图形界面，可测试攻击验证、风险计算、3b 多波攻击重规划和安全状态机。
- ROS 2 Jazzy 包：`guardian_interfaces` 消息包和 `guardian_core` 节点包。
- 本地 Web 安全驾驶舱：只读映射风险、攻击组件、缓解方案和安全状态。
- `guardian_node` 订阅 `guardian/attack_events`，输出 `guardian/risk_state`、`guardian/mitigation_command` 和 `guardian/safety_status`。
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
python3 -m pytest -q
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

详细设计见 [docs/design.md](docs/design.md)，实验和指标见 [docs/experiments.md](docs/experiments.md)。

创新功能验证见 [docs/innovation_validation.md](docs/innovation_validation.md)，可直接运行：

```bash
python3 experiments/run_innovation_experiments.py
```
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
