# 跨层融合实现计划

**目标：** 在现有零信任事件验证和任务韧性核心上，增加可单元测试的图风险传播、时序规则、证据融合、安全速度包络和恢复门控，并保留现有 ROS 2 API 兼容性。

**架构：** 新模块先作为纯 Python 安全核心存在；ROS 2 节点和 Web 驾驶舱在后续阶段消费这些模块的结构化结果。安全决策不依赖 Web 页面或外部网络服务。

**技术栈：** Python 标准库、现有 pytest、ROS 2 Jazzy；不新增运行时依赖。

## 全局约束

- 当前单台笔记本和 WSL2 环境必须可以运行离线验证。
- 不改变现有 `AttackEvent`、`RiskState`、`MitigationCommand`、`SafetyStatus` 消息字段的语义。
- 每个新模块先写失败测试，再实现最小行为。
- 图传播、速度包络和恢复门控在实现前不宣称已经接入真实底盘。
- 每次提交必须同步更新 `HANDOFF.md` 的变更日志和验证证据。

## 任务 1：图风险传播（纯 Python 已完成）

**文件：**

- Create `ros2_ws/src/guardian_core/guardian_core/graph_model.py`
- Create `tests/test_fusion_layers.py`

**接口：**

- `GraphNode(name, kind, criticality)`
- `GraphEdge(source, target, weight)`
- `SecurityGraph.add_node()`、`add_edge()`、`propagate(base_risk)`
- `GraphRiskAssessment.risk_by_node`、`affected_nodes`、`critical_nodes`

已完成 `SecurityGraph` 的有界固定点传播和关键节点识别，测试覆盖链式传播和风险范围。

## 任务 2：时序规则监控（纯 Python 已完成）

**文件：**

- Create `ros2_ws/src/guardian_core/guardian_core/policy_monitor.py`

**接口：**

- `TopicPolicy(topic, source, min_period_sec, max_gap_sec, max_age_sec)`
- `TemporalPolicyMonitor.observe(topic, source, timestamp, sequence, now)`
- `PolicyViolation(code, topic, reason)`

已完成未知话题、来源、未来时间、过期、重放、过快和过慢消息检查。

## 任务 3：多源证据融合（纯 Python 已完成）

**文件：**

- Create `ros2_ws/src/guardian_core/guardian_core/evidence_fusion.py`

**接口：**

- `EvidenceBundle`
- `EvidenceFusion.evaluate(bundle)`
- 输出风险分数、`ALLOW`/`CONTAIN`/`SAFE_STOP`等级和解释原因。

已完成归一化加权融合、等级阈值和原因列表输出。

## 任务 4：安全速度包络和恢复门控（纯 Python 已完成）

**文件：**

- Create `ros2_ws/src/guardian_core/guardian_core/safety_envelope.py`
- Create `ros2_ws/src/guardian_core/guardian_core/recovery_gate.py`

**接口：**

- `SafetyEnvelopeController.compute(risk, free_distance, sensor_fresh)`
- `RecoveryGate.evaluate(evidence)`

已完成基于制动距离、风险和传感器新鲜度的速度上限计算，以及六项恢复条件的全量门控。

## 任务 5：离线实验和交接（本阶段已完成）

**文件：**

- Modify `experiments/run_innovation_experiments.py`
- Modify `docs/innovation_validation.md`
- Modify `HANDOFF.md`

已将五层链路接入 `run_innovation_experiments.py` 并写入验证报告。本阶段仍未把新结果接入真实 ROS 2 live graph、`guardian_node` 消息或 Webots 控制器。

## 下一阶段：ROS 2 适配

1. 使用 ROS 2 graph API 定期构造 `SecurityGraph`，并把节点、话题和执行器映射到允许的策略清单。
2. 在 `guardian_node` 内调用 `TemporalPolicyMonitor` 和 `EvidenceFusion`，为现有消息增加兼容的诊断输出。
3. 将 `SafetyEnvelopeDecision` 映射到 `SafetyStatus`，由 Webots/底盘适配器执行速度和停车边界。
4. 将 `RecoveryGate` 接入 ROS 2 lifecycle 或独立恢复服务，并保留审计记录。
5. 在真实适配器完成后，增加图开销、误报率、停车时间和任务完成率的基线对比。

**验证命令：**

```bash
python3 -m pytest -q
python3 experiments/run_innovation_experiments.py
source /opt/ros/jazzy/setup.bash
cd ros2_ws && colcon build --symlink-install
```

完成纯 Python 层后，再单独规划 ROS 2 消息扩展和 Web 驾驶舱映射，避免一次改动同时改变算法、消息和 UI。
