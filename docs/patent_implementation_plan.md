# 可溯源预测防护与恢复协议实施计划

日期：2026-09-23。规格来源：用户确认的因果图、证据账本、预测包络、双阶段恢复与技术交底架构。

## 目标与范围

新增可在笔记本运行的确定性研究内核和对照实验，准备中国发明专利技术交底草案。现有 ROS 2 消息、Jev 请求、驾驶舱控制边界保持兼容。核心不新增第三方依赖，不访问 Jev 服务，不直接驱动机器人。工程效果与可专利性分开评价。

## 任务 1：带出处的图快照

- Create `ros2_ws/src/guardian_core/guardian_core/causal_graph.py`
- Test `tests/test_patent_core.py`
- 接口：`CausalNode`、`CausalEdge`、`GraphSnapshot`、`trace_risk(snapshot, seeds, now, max_age_sec)`、`compare_graphs(before, after)`。
- 快照指纹不包含采样时间，包含拓扑、边权、出处、信任域；最大乘积路径给出风险出处、边与跨域记录；检测过期图、未知种子和非法数值。
- 红：导入失败。绿：链、环、同权路径确定性、跨域路径、图变更及过期测试。

## 任务 2：不可变证据和哈希链

- Create `ros2_ws/src/guardian_core/guardian_core/evidence_ledger.py`
- 接口：`Evidence`、`EvidenceLedger.append/active/anchor/export/verify`。
- 证据含 ID、来源、类型、节点、观察时间、有效期、置信度、严重度、策略版本、父证据、替代目标、验证标记及硬停车标记。
- 重复 ID、缺失父证据、跨来源替代被拒绝；过期/未验证/被替代父证据的派生证据不能生效。
- 外部保存的 `(count, head)` 锚点检测篡改和截断；不称为数字签名，不承诺抵抗拥有锚点写权限的攻击者。

## 任务 3：预测安全包络与解释

- Create `ros2_ws/src/guardian_core/guardian_core/predictive_envelope.py`
- Create `ros2_ws/src/guardian_core/guardian_core/assurance.py`
- 接口：`MotionSample`、`PredictiveConfig`、`PredictiveEnvelope.evaluate`；`AssuranceController.assess/counterfactuals`。
- `d_stop = v*tau + v²/(2a) + margin + uncertainty + risk_margin`；速度上限同时受上述制动不等式和外推风险约束。
- 账本有效证据进入图与固定权重评分；硬停车独立于均值，Jev/semantic 不能移除硬停车；解释逐项屏蔽证据及其派生项并重算，不修改实时状态。
- 验证延迟单调性、距离单调性、风险增长、非有限输入失效停车、健康低风险任务可继续。

## 任务 4：绑定上下文的双阶段恢复

- Create `ros2_ws/src/guardian_core/guardian_core/recovery_protocol.py`
- 接口：`RecoveryObservation`、`RecoveryConfig`、`RecoveryProtocol.observe/commit/authorize_command`、`RecoveryProof`。
- SAFE_STOP → RECOVERY_PROBING → RECOVERY_CANDIDATE → RESUMABLE；满足持续窗口和驻留时间才生成有期限的本地凭据，后续独立样本提交。
- 凭据绑定图/策略/账本摘要/命令代次；图变化、攻击复现、过大采样间隔、倒退时钟、凭据重放与到期拒绝恢复。
- 命令清空和探测成功由可信适配器提供；内核只判断门控，不声称实现真实命令隔离器。

## 任务 5：对照实验与交付

- Create `experiments/run_patent_innovation_experiments.py`
- Create `docs/patent_disclosure.md`、`docs/patent_prior_art.md`、`docs/patent_experiments.md`
- Modify `README.md`、`HANDOFF.md`、`task_plan.md`、`findings.md`、`progress.md`
- 实验：路径和图变更；证据篡改及反事实；固定阈值/现有包络/预测包络的同输入对比与参数扫描；布尔恢复与双阶段恢复的短暂稳定/新攻击/旧凭据对比。
- 报告 JSON 保存 `experiments/results/`；发布小型固定报告副本用于复核。不得把人工轨迹的命中率称为真实误报率。
- 验证：`python3 -m pytest -q tests`；两套实验脚本；`colcon build --symlink-install`；Windows compileall；`git diff --check`。
- 保留 `.env` 跟踪；仅本地 `main` 提交。公开新增技术方案前提示申请前公开的影响，并给用户可审阅的最终差异。

## 状态

- [complete] 参考实现核查、契约与失败测试。
- [complete] 四个模块及联动控制器。
- [complete] 对照实验、完整技术交底和边界说明。
- [in_progress] 验证、交接、main 提交与公开决策。
