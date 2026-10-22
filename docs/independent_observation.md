# 第二轮：多进程与独立观测恢复闭环

## 本轮实现

三个独立 ROS 2 进程组成闭环：Guardian 控制授权，AMR 适配器提供执行反馈与软件传感器，recovery_observer 从标准 Odometry/LaserScan 独立计算速度和前向净距。复用 [ROS 2 launch_testing_ros 官方示例](https://github.com/ros2/launch_ros/blob/humble/launch_testing_ros/test/examples/talker_listener_launch_test.py) 的进程启动/退出测试设施、rclpy 原生图发现及传感器 QoS、项目原 HMAC 和恢复协议；没有新写进程管理框架。

`适配器签名 ACK/状态 + 独立签名观测 → 同拍证据关联 → 图/策略/账本/下一 epoch 核验 → 一次性恢复许可 → 运动`

第一轮入口仍可复现单源基线。第二轮必须显式启用 independent_observation_required=true 和 evidence_bound_recovery=true；它不会在观测器缺失时退回单源模式。

## 观测契约

- 原始里程计为 `/amr_07/odom`，固定 `map/base_link` 坐标系；扫描为 `/amr_07/scan`，固定 `base_scan` 前向扫描。当前只支持前进的平面 AMR，倒车、侧移、旋转与非有限输入撤回证据。接入其他坐标系/运动模式需要明确变换和方向覆盖。
- 激光覆盖前向区域，距离必须有限且在传感器有效范围；NaN、无限无回波、范围外值和不完整扫描均不能证明空间安全。本轮场景障碍位于终点后 5 米，净距随机器人位置变化，不再固定为 5 米。
- 两路原始采集时刻差不超过 0.15 秒；源时间和接收端单调时间都必须新鲜，默认最大年龄 0.5 秒。原始重复、倒退、未来或陈旧时间立即使对应缓存不可用；观测心跳保留原始采集时间，不续期。
- 适配器 RecoveryTelemetry.timestamp 必须标记对应里程计的同一采集时刻。Guardian 两路缓存各最多 8 项，按源时间匹配（浮点容差 1 微秒），避免把异步到达的不同采样周期当成速度矛盾。最新完整配对可在原始有效期内等待下一拍；最新已配对数据矛盾时立即阻断，不使用更早健康配对回退。
- 配对速度差最多 0.03m/s，采用较大速度和独立扫描净距运行预测包络。当前适配器报告不健康或观测器报告无效时立即阻断。数据断流最多等待已有证据年龄窗口，之后停车。
- 新 epoch 清空全部观测缓存，观测器也清空原始缓存并要求新样本。完整配对的原始采集时刻与接收时刻均晚于新告警，才可解除仿真器来源事件；其他 IDS 来源仍不自动解除。

## 认证与重启

独立报告使用单独 `GUARDIAN_OBSERVATION_SECRET`，不得为空或与 `GUARDIAN_FEEDBACK_SECRET` 相同。专用 launch 会从适配器进程环境清除独立签名密钥。Guardian 与 observer 持有观测密钥，observer 另需反馈密钥验证命令；HMAC 是对称认证，不提供远程不可抵赖。

每次 observer 启动生成签名启动会话，报告序号在会话内递增。Guardian 只在发现新的唯一报告发布 GID 且新会话合法时重建水位；退休会话不能再使用，同一会话不能换 GID。退休历史最多 64 个，耗尽后锁存停车并需要审查后重启 Guardian。新会话清空旧报告，端点改变使原恢复许可失效，因此进程重启后仍需新健康窗口和新许可。

控制话题、独立报告、里程计和扫描端点均进入许可图指纹。原始传感器只能有预期的单一发布者；多发布者、端点缺失或重建均阻断/重置恢复。ROS 2 Humble 普通 rclpy 回调不提供报文发布者元数据，这里使用原生图的唯一发布 GID 划分会话，而非逐条报文来源绑定。DDS 节点名/GID 不是密码学身份；原始传感器无消息签名，需要生产 DDS/SROS2 权限和独立可信传感器补足。

## 复现

Ubuntu-22.04 / ROS 2 Humble 下：

```bash
bash deploy/run_guardian.sh build --distro humble
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
launch_test experiments/independent_observation_launch_test.py
python3 -m pytest tests -q
```

实验由 launch_testing 管理 Guardian、适配器、观测器三个子进程，使用临时密钥与 localhost 隔离 DDS 域。报告为 `experiments/results/independent_observation_validation.json`；所有重启/最终退出码都参与验收，避免 respawn 隐藏早期失败。它不启动 Dashboard、不调用外部模型、不连接机器人。

手动启动（在指定软件域中）：

```bash
export ROS_DOMAIN_ID=199 ROS_LOCALHOST_ONLY=1
export GUARDIAN_FEEDBACK_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
export GUARDIAN_OBSERVATION_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
unset GUARDIAN_EVENT_SECRET
ros2 launch guardian_core independent_recovery.launch.py
```

在相同 DDS 域的另一终端发送场景控制即可：

```bash
ros2 topic pub --once /amr_07/sim_control std_msgs/msg/String '{data: "{\"action\":\"start\"}"}'
ros2 topic pub --once /amr_07/sim_control std_msgs/msg/String '{data: "{\"action\":\"sensor_fault\",\"mode\":\"paused\"}"}'
ros2 topic pub --once /amr_07/sim_control std_msgs/msg/String '{data: "{\"action\":\"sensor_fault\",\"mode\":\"normal\"}"}'
```

软件故障模式还包括 stale、replay、invalid_scan、speed_mismatch、near_obstacle，以及一次性 restart_endpoints。reset 仍只重置场景与传感器故障，不重置协议计数或锁存错误。

## 证据与后续

验收报告分别检查正常恢复、持续攻击超过 TTL、reset 健康恢复、六类传感器故障与修复后的新许可、额外报告发布者、原始传感器端点重建、观测进程实际重启。软件时延为单次观测值；重复运行存在调度波动，不能作为实机制动时限。

独立审查修复了前向扫描误用于倒车/侧移与重启后序号水位累积等待，并补充了采集时间配对、旧样本不能解除新事件和关闭上下文时的退出处理。具体最终测试数量和测量值记录在 HANDOFF 与机器报告中。

当前独立性是计算进程、计算逻辑和报告签名密钥分离；里程计与扫描仍来自同一软件 AMR 模型，不能防御该模型或真实硬件的共同故障。未接入物理引擎、真实传感器、硬件急停或生产安全认证。下一阶段为通用事件解除协议和基线/消融重复实验；BTreeFuzz 的反馈引导测试借鉴见 [研究记录](btreefuzz_recovery_testing.md)。
