# 冻结目标的新缺陷验证与真实 ROS 2 审计留存

> **For agentic workers:** Use superpowers:executing-plans task-by-task. Steps use checkbox syntax. 本轮独立缺陷选型由只读审查完成，主 agent 实施并验收。

**Goal:** 在不调整第八轮反馈目标、输入策略或Oracle的条件下，验证两个独立选定的新受控缺陷，并用自有三进程DDS闭环验证持久审计导入。

**Architecture:** 为现有holdout runner增加受限的transfer缺陷集，复用计时、聚合、源码冻结与重放。为已有launch_testing脚本增加可选审计产物目录，停机后保存不可变JSONL快照；新的只读CLI复用dashboard_recovery.inspect_recovery_trace。

**Tech Stack:** 现有ROS 2 Humble launch_testing、Hypothesis 6.168.5、Python标准库与pytest；不新增运行依赖。

**Spec:** 用户授权继续“独立缺陷族与外部轨迹验证”，并选择“先用现有ROS 2闭环验证入口”。本轮数据明确为自有软件AMR的真实DDS轨迹。

## Global Constraints

- 当前codex/evidence-bound-recovery工作区含前序未提交实现，原地延续，保留已有改动；不提交、推送或部署。
- 第八轮liveness、boundary、18动作策略和SafetyOracle已先于缺陷选型冻结在 experiments/results/recovery_transfer_preregistration/；新实验必须逐项核对该登记。
- 独立选型审查未阅读反馈目标或实验结果。两族为no_motion_envelope、nonzero_safe_stop_limit，各唯一AST站点，匹配非1即拒绝；只生成离线类，不替换生产类。
- 新种子60..79，模式unguided/liveness各5秒、执行上限10000，共40组200秒名义预算；无预热/缩减、按种子轮换组序、所有组采集同一反馈；不依据结果调参或改默认。
- 不改变Oracle或生产恢复代码；自有真实DDS与外部机器人/物理证据分开。日志哈希用于固定输入身份，不证明来源认证。
- 所有新产物目录拒绝覆盖，JSONL不排序、不跨时钟重写，读入上限复用2MiB/2000帧限制。

## Task 1: 有界审计导入与ROS产物留存

**Files:** 新 experiments/inspect_recovery_audit.py、recovery_ros_artifacts.py、tests/test_recovery_audit_import.py；修改 experiments/independent_observation_launch_test.py。

**Interfaces:** inspect_audit(path, *, source_kind="user_supplied", expected_sha256=None) -> dict；begin_capture(root, directory, *, domain) -> Path；retain_capture(directory, audit_path) -> dict。

- [x] 红测：混合JSONL筛选kind=recovery_trace后调用同一Oracle；长健康停车检出recovery_stalled；输入中的认证/物理安全声明不得提升报告可信度；恶意NaN、重复键、坏JSONL、错误SHA和超大输入拒绝。
- [x] 绿：只做标准库解析和哈希，复用inspect_recovery_trace；输出schema guardian-recovery-audit-inspection/v1；CLI --input/--output/--source-kind/--expected-sha256，输出文件拒绝覆盖。
- [x] 红绿：保留审计原始字节、源码与快照SHA；目录已存在时拒绝，源码/快照/实际安装源漂移及轮转拒绝；归档只在launch进程停止后执行；默认无归档时行为保留。
- [x] 在隔离localhost ROS域执行 GUARDIAN_RECOVERY_ARTIFACT_DIR=experiments/results/recovery_ros_trace_validation launch_test experiments/independent_observation_launch_test.py：退出0、19场景通过、保留271帧/265876字节、0违规/0gap；独立CLI指定SHA重读一致。

## Task 2: 新缺陷集与登记核验

**Files:** 新 experiments/recovery_transfer_mutations.py、tests/test_recovery_transfer.py；修改 experiments/run_recovery_holdout.py。

**Interfaces:** get_defect_suite(name="holdout")；run_holdout_evaluation(..., defect_suite="holdout", preregistration=None)；原保存反例默认可重放，新反例携带defect_suite。

- [x] 红测资格：no_motion_envelope 的 near_obstacle(.3) 触发unsafe_candidate与unsafe_motion；nonzero_safe_stop_limit 的graph_missing(.01)触发invalid_speed_limit；完整控制均0违规，唯一站点校验不放宽。
- [x] 绿：从独立选型记录实现两族，复用生产类源码与已有gate_factory，不变更输入策略。
- [x] 红绿：默认三族/旧schema保留；新集参与资格、探测、聚合、反例重放与源码快照；登记源文件、模式、种子、预算或登记文件漂移均使transfer失败。审查P2通过driver漂移红绿修复，前批11个保留源均对照锁定报告，不改原登记。
- [x] 正式运行：python experiments/run_recovery_holdout.py --defect-suite transfer --preregistration experiments/results/recovery_transfer_preregistration/protocol.json --seeds 60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79 --modes unguided,liveness --wall-time-sec 5 --execution-cap 10000 --output-dir experiments/results/recovery_transfer_validation。40组均wall_time停止、29134次生成、82反例/40语料重放一致、完整0违规；两族两组均20/20。

## Task 3: 验收与记录

- [x] 独立复算所有40组报告及配对，重放82反例/40语料共7966保存输入；13冻结源、登记/选择/前批报告与快照、11保留源及DDS审计核对一致。无执行上限触发、预算外发现0。
- [x] 相关测试、完整pytest（696 passed/58.04s）、compileall及修改文件格式检查；不重复不相关浏览器/包构建。
- [x] 更新docs/recovery_transfer_validation.md、README、PROJECT_GUIDE、HANDOFF，记录两族20/20饱和、吞吐/转移下降、亚毫秒配对时间差和DDS来源范围；没有外部/物理数据，不改默认。
