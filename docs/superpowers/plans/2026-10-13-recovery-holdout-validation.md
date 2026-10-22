# 恢复检测独立缺陷与等壁钟验证实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在冻结现有 Oracle、输入分布和反馈目标后，验证三个新增受控缺陷，并运行可复核的等壁钟搜索对照。

**Architecture:** 扩展已有 Hypothesis campaign 的可选时间限制，旧执行次数模式保持原行为。新增离线缺陷模块通过明确的 gate_factory 接口复用原场景执行器；独立 runner 保存资格挑战、首次发现、配对统计和重放结果。

**Tech Stack:** Python 标准库 AST/单调时钟、已安装 Hypothesis 6.168.5、pytest；不增加 ROS 运行依赖。

**Spec:** 用户已授权继续上一轮建议中的“冻结当前 Oracle，开展未见缺陷族＋等壁钟预算独立验证”。本计划明确该验证是新受控缺陷检查，不是未知真实漏洞或盲测。

## Global Constraints

- 不修改 SafetyOracle、BoundaryFeedback、生产恢复/认证决策和原 18 动作/10 时长/32 动作策略。
- 原四类变异及旧 runner 默认保持可复现；新实验结果使用新目录，不覆盖第五/六轮及前端历史快照。
- 时间限制采用完整用例边界协作停止，公开记录尾部超时；超过预算才得到的检出不计为预算内发现。
- 资格挑战、反例/语料重放和最终文件保存不计搜索预算；生成过程中的目标、检测和首次反例保存计入预算。
- 新缺陷：忽略停车 ACK、错误下一 epoch、拒绝有效许可导致恢复停滞。输入类型仍已知，缺陷与 Oracle 由本项目提供，不声称独立外部基准。
- 20 个新种子 20..39；unguided/guided/boundary 各 5 秒；执行上限 10000；模式按种子位置轮换。
- 保留未提交改动，在现有 codex/evidence-bound-recovery 上完成；不提交、推送、部署或连接机器人。

## Task 1: 时间限制与明确的离线核心注入接口

**Files:** experiments/run_recovery_feedback_fuzzing.py、experiments/recovery_scenarios.py、tests/test_recovery_wall_budget.py。

**Interfaces:** run_campaign(..., wall_time_sec=None)；execute_scenario(actions, variant="full", gate_factory=None)。

- [x] 红：测试时间到期停止真实 Hypothesis、停止不额外执行/重放、用例尾部可超时且显式记录、非法预算在创建文件前拒绝。
- [x] 绿：使用 unittest.SkipTest 的专用子类触发 Hypothesis 原生立即退出，在 callback 开始检查 perf_counter；捕获仅自己的子类。添加 search_elapsed_sec、stop_reason、wall_time_sec、deadline_overrun_sec。
- [x] 回归：`pytest tests/test_recovery_wall_budget.py tests/test_recovery_fuzzing.py tests/test_feedback_target_ablation.py -q`。

## Task 2: 新缺陷资格、独立对照与重放

**Files:** 新 experiments/recovery_holdout_mutations.py、experiments/run_recovery_holdout.py、tests/test_recovery_holdout.py。

**Interfaces:** execute_holdout(actions, family)；qualify_holdout(output_dir)；run_holdout_evaluation(seeds, wall_time_sec, execution_cap, output_dir, progress)；aggregate_holdout(runs)。

- [x] 红：用真实核心比较资格控制无违规、新三族产生指定违规、变异站点不匹配拒绝、时间截尾统计及配对种子对应正确。
- [x] 绿：AST 严格检查单一站点计数；三个缺陷只存在离线命名空间。复用已有生成、覆盖和保存；所有新缺陷都执行评价，不按 Oracle/目标筛选。
- [x] 红绿：测试重复目录拒绝、源码变化拒绝、首次发现时间不得越预算、保存反例与 corpus 一致重放。
- [x] 运行：`python experiments/run_recovery_holdout.py --seeds 20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39 --wall-time-sec 5 --execution-cap 10000 --output-dir experiments/results/recovery_holdout_validation`。

## Task 3: 独立审查、回归与如实结论

**Files:** docs/recovery_holdout_validation.md、HANDOFF.md、README.md、PROJECT_GUIDE.md。

- [x] 独立审查预算、公平性、冻结来源、统计、资格和重放；没有剩余重要问题。
- [x] 全量 pytest、compileall、git diff --check；不修改 ROS 包时不重复无关构建。630 passed。
- [x] 文档记录实际预算、检出与未检出、源版本和误差边界；本批次未证明引导搜索优势。
