# 第七轮：新受控缺陷与等壁钟验证

## 研究问题

现有反馈目标对许可 TTL 的改善对种子敏感，执行次数预算也未扣除引导搜索的额外时间。本轮固定第六轮的 Oracle、输入策略和反馈目标，增加三个未用于前六轮目标比较的受控缺陷，并按相同搜索时间比较。新增缺陷仍由本项目设计，动作类型和模型仍已知；不称未知真实漏洞、外部独立基准或盲验证。

## 实现与复用

- 继续使用安装的 Hypothesis 6.168.5，复用已有 action_strategy、target、SemanticCoverage、BoundaryFeedback、SafetyOracle 和 corpus 重放。没有增加 ROS 运行依赖或新的通用生成框架。
- `run_campaign` 增加可选 `wall_time_sec`。仅在无固定预热、无缩减时允许使用；原执行次数模式和默认调用保持原行为。
- 时间到期采用 Python unittest.SkipTest 的专用子类，通过 Hypothesis 原生立即退出路径停止；不使用它的内部 StopTest、不修改框架，也不把结束当成失败用例再次执行。已用真实 Hypothesis 回归验证一次执行后停止。
- `recovery_holdout_mutations.py` 只对仓库恢复类的单一 AST 站点生成离线对象；站点数量不同即失败。`execute_scenario` 通过显式 gate_factory 接口复用原传感器、场景与轨迹采集，不替换生产类或原四类变异。
- `run_recovery_holdout.py` 提供资格挑战、搜索、时间截尾统计、源码冻结和全部反例/语料重放；输出目录必须不存在，避免覆盖历史结果。

## 新缺陷资格

| 新受控缺陷 | 关闭/改变的检查 | 冻结 Oracle 预期检出 |
| --- | --- | --- |
| ignore_stop_ack | 恢复门控忽略停车 ACK，保留零速检查 | unsafe_candidate、unsafe_resume |
| wrong_next_epoch | 许可绑定输入 epoch+2，而非下一 epoch | candidate_binding_mismatch、context_mismatch |
| never_resume | 消费有效许可后仍返回停车，反复重新探测 | recovery_stalled |

这三类检查未作为原四族受控变异参与反馈目标设计。资格挑战只验证变异可执行、Oracle 能检出且完整控制无违规，不作为生成种子、搜索预热或检出率样本。冻结 Oracle 仍使用 liveness_sec=3、max_frame_gap_sec=.25；没有为获得本轮检出增加断言。

## 正式协议

固定 seeds20..39，unguided/guided/boundary 三组，每组 5 秒，执行上限 10000，共 60 组、300 秒名义搜索预算。三种模式按种子位置轮换，三类缺陷的探测顺序按 seed+输入索引轮换。生成输入沿用原 18 动作、10 时长和最多 32 动作，所有未检出缺陷族都接受当前输入，不进行与缺陷相关的预筛选。

计时包括策略构建、输入生成、完整核心、覆盖/边界提取、目标优化、受控缺陷执行、Oracle 和首次反例文件保存。已检出族停止额外执行，其成本变化属于本协议；每组保留各族实际探测次数。资格挑战、最终 corpus/报告写入、反例重放和 corpus 重放不计搜索预算。

这是**软时间预算**：已开始的完整输入及其探测完成后才停止，记录 search_elapsed_sec 和 deadline_overrun_sec。首次发现时间在保存反例之后记录；超过 5 秒的发现单列 out_of_budget_defects，不计入预算内检出。状态/转移覆盖包含最后完成的输入，因此覆盖有尾部超时影响，不能按严格 5 秒覆盖率解释。达到执行上限或提前耗尽搜索空间的组会使 equal_wall_comparison_valid=false，CLI 返回非零，不能被当作有效等壁钟对照。

冻结协议在资格验证之前写入 frozen_protocol.json，记录 Python/Hypothesis 版本、目标标签、Oracle 参数、源码 SHA-256 与来源快照。每组开始前和完整批次结束后检查来源未变。源码快照不含密钥；离线随机许可 ID 不作为反例重放身份。

## 统计口径

报告每族检出种子数/20、Wilson 95% 检出率区间、仅已检出组的首次时间，以及全部组的预算截尾首次时间。未检出按 5 秒记入截尾统计，不把它记为零秒，不将条件首次时间解释为总体检出速度。配对比较按相同种子对应，时间差定义为左模式减右模式，负值代表更早；同时报告检出差。

Wilson 区间只描述本模型、输入分布、预算与种子下的运行检出率，不是独立漏洞数、不用于证明实机安全或未见缺陷泛化。种子配对共享随机因素，模式比较不能将两组中位数直接相减替代配对分析。不同墙钟预算与前六轮执行次数预算不合并统计。

## 2026-10-13 实际结果

正式批次60组完整结束，CLI退出0，31,749条生成执行，完整机制0断言违规，三族资格挑战均检出且完整控制无违规。129个首次发现加3个资格反例共132个反例及60组corpus重放一致；没有预算外发现、源码漂移或重放差异。所有组均因墙钟到期结束，执行上限10000未触发。

| 模式 | 总生成执行 | 每组执行中位数 | ACK缺陷检出 | epoch缺陷检出 | 恢复停滞检出 | 转移覆盖中位数 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 无引导 | 15,852 | 759.5 | 20/20 | 20/20 | 6/20 | 480.5 |
| 旧语义反馈 | 5,919 | 288 | 20/20 | 20/20 | 1/20 | 239 |
| 许可边界反馈 | 9,978 | 472.5 | 20/20 | 20/20 | 2/20 | 268.5 |

三组实际搜索时间合计分别100.498、101.057和100.760秒。每组尾部超时中位约23.4、51.3、36.3毫秒，最大分别35.3、87.1、51.0毫秒；这些尾部计入公开覆盖，未当作严格300秒执行。

恢复停滞的Wilson 95%区间分别为14.5%–51.9%、0.9%–23.6%、2.8%–30.1%。仅检出组首次时间中位为2.200、0.661、2.846秒，三组全部样本的截尾首次时间中位均5秒。旧反馈的0.661秒只来自一个检出种子，不能据此称其总体更快。配对截尾时间差中位均0，大量两边未检出使这个指标失去区分；必须同时看检出差。旧反馈/边界反馈相对无引导分别少检出5/4个种子；边界相对旧反馈多1个。

本批次没有证明反馈引导在新缺陷上的稳定优势。ACK与epoch两族达到检出饱和，不能用它们区分方法；恢复停滞仍难以搜索，且引导开销减少了同时间内的执行数。结果支持下一轮研究持续可恢复窗口的探索目标，并使用新的协议/种子验证，而不是在本轮结果上改目标后仍称独立验证。默认目标和生产恢复机制保持不变，不把这些人为缺陷称为生产漏洞。

独立审查逐份核对60份源报告、11份源码及对应快照，并独立重算全部统计和配对结果；132份反例与60组corpus（9342条保存输入）独立重放一致。最终全量630项测试通过（新增23项），compileall和diff检查通过。首次全量启动仅加载ROS基础环境，因未加载工作区消息包而在收集阶段失败；加载install/humble/setup.bash后全量通过，未为该环境问题修改生产代码。本轮只修改离线实验及文档，未修改ROS包运行代码或部署服务。

## 复现与产物

```bash
source /opt/ros/humble/setup.bash
output/recovery-fuzz-venv/bin/python experiments/run_recovery_holdout.py \
  --wall-time-sec 5 --execution-cap 10000 \
  --output-dir experiments/results/recovery_holdout_validation
# 默认种子为20..39；重跑必须选择新的输出目录。
output/recovery-fuzz-venv/bin/python experiments/run_recovery_holdout.py \
  --replay experiments/results/recovery_holdout_validation/qualification_ignore_stop_ack.json
output/recovery-fuzz-venv/bin/python -m pytest tests/test_recovery_holdout.py tests/test_recovery_wall_budget.py -q
```

产物包含 frozen_protocol.json、source_snapshot/、qualification.json、每组原始报告/corpus、预算内/超时反例和 summary.json。CLI 对完整机制违规、反例或 corpus 重放差异、非等壁钟有效比较返回非零；资格失败或源码漂移立即终止。

本轮未扩展真实 DDS 随机故障、物理仿真或硬件验证；既有 DDS 间歇启动超时仍未解决。前端保留第六轮历史快照，本轮独立协议结果不覆盖该快照。后续依据实际检出与未检出定位搜索盲区，再设计独立的真实 ROS/外部轨迹验证。
