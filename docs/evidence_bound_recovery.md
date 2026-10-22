# 面向 ROS 2 机器人的证据与上下文绑定安全恢复机制

2026-10-12，第一轮 AMR 最小软件闭环。设计与开源工具查阅记录见 [规格](superpowers/specs/2026-10-12-evidence-bound-recovery-design.md)。

## 机制

Guardian 先发布停车命令，AMR 返回签名 ACK 和类型化 `guardian/recovery_telemetry`。只有新鲜、无攻击、旧命令已清空、探测通过、实际速度为零的观测与当前停车 ACK 配对后，才进入稳定观察。默认稳定窗口 0.5 秒、驻留时间 1 秒、凭据 TTL 0.5 秒。窗口使用接收端单调时钟。

许可绑定控制图、策略、账本锚点与下一命令 epoch。相关图用 rclpy 原生 `get_publishers_info_by_topic` / `get_subscriptions_info_by_topic` 获取 `mitigation_command`、`safety_status`、`recovery_telemetry` 的名称、类型与 GID；缺少必要端点或额外发布者禁止恢复，端点重启改变指纹。无关话题不进入指纹。DDS 名称/GID 不是密码学身份。

许可签发后至少等待一个控制周期，再重新核验和消费。`recovery-<proof_id>` 计划 ID 进入现有 HMAC 认证命令/状态，并让第一条恢复命令恰好使用凭据绑定的 epoch。AMR 继续校验命令/状态签名、epoch/传输号和配对关系。凭据本身在 Guardian 内部消费；本轮不声称执行器独立验证了整个账本或分布式证书。

已验证攻击、相关上下文变化和事件解除进入哈希账本。健康 heartbeat 不逐条记账，避免锚点持续变化。容量默认 1024 条；耗尽后锁存停车，不允许退回旧上下文绕过。账本仅为本进程完整性检查与实验导出，不是远程不可抵赖存储。

事件 TTL 不代表解除。AMR 模式只允许仿真适配器的健康观测解除 `amr_simulator` 来源事件，并要求观测采集与接收时间均晚于新告警；其他来源事件保持未解决。命令 epoch 改变后旧观测立即失效。反馈 watchdog、配置错误和账本错误不会被恢复流程解除。

## 启用与复现

```bash
bash deploy/run_guardian.sh build --distro humble
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
python3 experiments/run_bound_recovery_experiments.py
python3 -m pytest tests/test_bound_recovery.py tests/test_recovery_transport.py tests/test_bound_recovery_ros.py -q
```

独立实验使用临时密钥、隔离 localhost ROS 域，不连接现有机器人或调用 Jev。它启动真实 Guardian/AMR/观测节点，通过 ROS 控制话题注入攻击与 reset，并从 `/cmd_vel` 测量零速度和恢复运动。报告写入 `experiments/results/bound_recovery_validation.json`。

默认配置文件为 AMR 启用该机制；普通 `guardian_node` 未加载配置时仍默认关闭，可显式传 `-p evidence_bound_recovery:=true`。启用模式需要反馈密钥与 `amr-default/default-actuator` profile。攻击事件强制验签；仿真双方使用 `GUARDIAN_EVENT_SECRET`，未单独配置时复用 `GUARDIAN_FEEDBACK_SECRET`。密钥仅来自环境变量，不写入报告。

可配置参数：`recovery_dwell_sec`、`recovery_stable_window_sec`、`recovery_telemetry_max_age_sec`。任务阶段变化进入策略指纹。`RECOVERY_PROBING` / `RECOVERY_CANDIDATE` 对 ROS SafetyStatus 映射为 `RECOVERING`，审计 `bound_recovery` 保存完整阶段；许可消费后的首周期为 `RESUMABLE`，随后 `NORMAL`。

## 本次测量

全量测试 `487 passed`，新增 22 项恢复核心、认证传输、live 图发现与真实 ROS 消息验收。真实消息测试还覆盖观测重放、无签名来源、旧观测不能解除新告警、epoch 改变清空旧观测、任务阶段变化废弃旧凭据和首条恢复命令/状态的 epoch 配对。Playwright 验证了页面登录、攻击停车和 reset 后运动恢复；页面显示攻击请求 `0.62 m/s`、实际 `0.00 m/s`，恢复后实际 `0.20 m/s`。

一次 Ubuntu-22.04 / ROS 2 Humble 软件实验中，五个验收场景通过：启动恢复、持续攻击超过告警 TTL、reset 后健康探测恢复、live 图变化、签发后到使用前图变化。启动到首次运动约 1.399 秒、注入到观测零速度约 0.200 秒、reset 到恢复运动约 1.380 秒。报告含 10 条账本记录及 65 条速度观测；时延是单次软件观测值，不是均值/P99或制动距离保证。

## 复用与下一步

直接复用 ROS 2 rclpy（Apache-2.0）图发现、Python 标准库 hmac、项目已有预测包络和恢复协议、现有 ROS executor/pytest 测试设施。已查阅 Nav2 Collision Monitor 与 ROS 2 launch_testing 的开源实现：前者用于后续物理限速基线，后者适合后续多进程启动测试；本轮没有导航栈，不复制其代码或额外搭建测试框架。

第一轮 AMR 观测是软件模型的自报告，原净距固定 5 米、传感器新鲜度来自仿真。第二轮已增加 [多进程独立观测](independent_observation.md)，从标准里程计/激光计算动态净距，并交叉核验报告；传感器仍来自软件模型，不能代表独立物理健康监测。下一步需要接入真实/物理仿真观测、明确通用 IDS 解除协议、运行多次并比较基线。Jazzy、Gazebo/Webots、HIL、实机制动及生产认证均未在本轮验证。
