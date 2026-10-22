# 持续健康窗口与恢复推进反馈实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 改善第七轮暴露的恢复停滞搜索短板，以新种子与同时间预算验证目标及组合的效果。

**Architecture:** 新反馈只读取完整控制轨迹，以持续健康且上下文稳定的窗口和恢复推进阶段形成两个有界目标。复用 Hypothesis campaign 与第七轮 holdout runner，加入可选模式、相同指标采集、保存见证/重放与四组配对。

**Tech Stack:** 已安装 Hypothesis 6.168.5、Python 标准库、pytest；不增加 ROS 运行依赖。

**Spec:** 用户已授权继续上一轮“针对持续健康但无法恢复路径改进目标，再用新种子验证”的下一步。本计划是已知受控缺陷上的目标改进，不是未见缺陷泛化。

## Global Constraints

- SafetyOracle、生产恢复决策、三类 holdout 缺陷和原18动作/10时长/32动作策略不改。
- 新目标来自 full trace，不读取输入动作、mutant、Oracle、反例或命中结果。
- 健康窗口要求证据healthy、无未解除事件/强制停车、图/策略/账本非空、速度有限非负；停车帧额外要求ACK及零速。正常运动不要求停车ACK，避免正确恢复截断长健康路径。
- 连续性要求帧间隔<=.25秒、图/策略/账本相等、当前输入epoch等于前帧输出epoch；正常恢复的下一epoch因此不会截断窗口。坏证据、上下文变化、epoch跳跃或采样空窗重启窗口。
- 时间目标为最长窗口秒数，量化6位小数、上限6秒；阶段目标0..4为SAFE_STOP/PROBING/签发候选/RESUMABLE/NORMAL，后两者要求任务允许与消费ID。
- 正式运行前独立审查复现.25秒浮点舍入截断，新增真实轨迹红绿测试；仅新代理加入1e-9秒采样容差并冻结配置，Oracle仍严格.25秒。
- 比较模式unguided/boundary/liveness/boundary_liveness；所有组都采集新指标，只有新目标组优化它们。默认旧campaign及第七轮三组行为保留。
- seeds40..59，每组5秒，执行上限10000，共80组400秒名义预算；沿用软上限/预算外发现排除/源码快照/目录拒绝覆盖。
- 不用第七轮种子再选优；不据本批次自动修改默认；不提交、推送、部署或连接机器人。

## Task 1: 独立轨迹特征

**Files:** 新 experiments/recovery_liveness_feedback.py、tests/test_recovery_liveness_feedback.py。

**Interface:** RecoveryLivenessFeedback.from_trace(frames)；targets()/features()/configuration()。

- [x] 红：手工帧验证持续窗口、坏证据/ACK/上下文/epoch/gap切断、正确恢复epoch保持连续、重复帧无增益、阶段推进与6秒上限。
- [x] 绿：确定性提取公开帧关系，冲突同刻/倒退/非有限时间拒绝；不调用Oracle或场景执行。
- [x] 回归：`pytest tests/test_recovery_liveness_feedback.py -q`。

## Task 2: 模式、采集公平性、见证与重放

**Files:** experiments/run_recovery_feedback_fuzzing.py、run_recovery_holdout.py、新 tests/test_recovery_liveness_campaign.py。

**Interfaces:** run_campaign(..., collect_liveness=False)；run_holdout_evaluation(..., modes=("unguided","guided","boundary"))。

- [x] 红：捕获真实target调用，验证liveness只优化两标签、组合优化原四标签加新两标签； baseline无新增标签但采集同样指标。
- [x] 绿：新模式按full trace分数优化，保存新颖性及最大值见证；corpus记录配置并按同配置重放。
- [x] 红绿：四组实际旋转、协议标记known-defect验证、未知/重复模式拒绝、配对截尾和新指标重放匹配。
- [x] 独立审查修复0.25秒浮点边界并运行：`python experiments/run_recovery_holdout.py --seeds 40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59 --modes unguided,boundary,liveness,boundary_liveness --wall-time-sec 5 --execution-cap 10000 --output-dir experiments/results/recovery_liveness_validation`。80组wall_time结束，41,935次生成，完整机制0违规，193反例和80语料重放一致；liveness检测never_resume 16/20，unguided 5/20；组合模式7/20。

## Task 3: 完整回归与结论

**Files:** docs/recovery_liveness_feedback.md、README.md、PROJECT_GUIDE.md、HANDOFF.md。

- [x] 全部反例/corpus重放并独立复核80报告/12份源码快照/配对统计；额外回归测试保留epoch、重复/冲突帧和非健康状态覆盖。
- [x] 全量pytest（674 passed）、experiments与guardian_core compileall、git diff --check及修改文件空白检查；无ROS运行代码变更，不重复无关构建。
- [x] 在 `docs/recovery_liveness_feedback.md`、README、PROJECT_GUIDE、HANDOFF记录实际预算、停滞检出、其它两族、Wilson区间及配对截尾指标；声明已知缺陷新种子范围和组合退化，保留默认模式。
