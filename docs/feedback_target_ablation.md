# 第六轮：反馈目标消融与新种子验证

本轮延续第五轮的未决问题：许可边界目标比旧覆盖目标改善TTL检出，但没有优于无引导。将原有四个标签按反馈族拆开，使用未用于迭代的种子检验结果。输入策略、特征提取、受控变异与ROS恢复决策保持冻结；首批实验发现活性断言对采样空窗的误判，诊断后只修正该断言的连续性前提，并完整重跑，见下文。

## 方法与冻结协议

| 模式 | 实际优化标签 | 用途 |
| --- | --- | --- |
| unguided | 无 | 无引导基线 |
| guided | recovery_semantic_coverage | 旧覆盖目标基线 |
| boundary | 四个许可边界标签 | 第五轮完整边界反馈 |
| ttl | permit_ttl_diversity、permit_expiry_proximity | 移除上下文与修复反馈 |
| context_repair | permit_context_diversity、repair_transition_diversity | 移除TTL反馈 |

TTL-only组保留两个原始TTL标签，属于目标族消融，并不是把两者合成一个新分数。所有方法都采集四个原始目标的最大值和完整边界特征；`active_target_labels` 表示真正传给Hypothesis的标签，不能把观测了某个指标理解为优化了它。标签的实际调用由测试捕获确认，不仅核对报告文字。

seeds10..19，每种方法每个种子1000次实际生成执行，50组共50,000次；不预热固定输入。五种模式按种子在列表中的位置轮换，每种模式各有两次排在第一。动作策略沿用18动作、10时长、最长32动作；Hypothesis固定6.168.5，数据库关闭。`seed_role=unseen_validation` 明确记录本批次角色。

这些随机种子没有参与前五轮比较，但模型、输入分布和四类人为缺陷均已用于设计。它是新种子验证，不是未见缺陷验证；不合并前一批seeds0..9来选择看似最好的结果。设计和比较在运行前固定，见 `docs/superpowers/specs/2026-10-12-feedback-target-ablation-design.md`。

预先规定的比较包含各反馈组vs无引导、两个消融组各vs完整boundary、ttl vs context_repair，保留boundary vs guided。首次发现索引未检出按1000截尾，配对差定义为左方法减右方法，越小越好；同时报告检出率，避免把第1000次检出与未检出混淆。只包含已检出样本的条件索引/时间不能当作总体速度结论。

搜索目标不读取安全Oracle或变异结果；后者只用于评价。资格挑战与21输入×5配置机制消融是搜索预算外的验收控制。变异只在离线对象中运行；最终报告保留来源源码SHA、Python/Hypothesis版本、标签选择及所有重放结果。

## 修正批次结果

五组50,000次生成执行完成，退出码0，完整机制与资格控制均0违规。四类受控缺陷资格通过；184个反例（176个首个发现＋4个资格原始＋4个缩减）及50组corpus重放一致，语义覆盖、边界特征、四目标最大值与违规码均匹配。来源快照包含8份代码与SHA清单。

| 模式 | TTL检出 | TTL截尾首索引中位 | 状态中位 | 转移中位 | 边界特征中位 | 壁钟中位秒 |
| --- | --- | --- | --- | --- | --- | --- |
| unguided | 5/10 | 931 | 156.5 | 547.5 | 14 | 5.27 |
| guided | 4/10 | 1000 | 163.5 | 566.5 | 14 | 12.36 |
| boundary | 7/10 | 414 | 144.5 | 482.5 | 17.5 | 6.58 |
| ttl | 6/10 | 865.5 | 153.5 | 505 | 15.5 | 7.32 |
| context_repair | 4/10 | 1000 | 145.5 | 479 | 15 | 6.41 |

另外三族（上下文、一次性重放、独立观测）在每组均10/10检出。TTL仅检出组的首次索引中位依次为341、411.5、245、400、329，相应首次时间中位为1.565、4.991、1.047、2.081、1.690秒；条件统计排除了未检出的种子，不能替代上表截尾指标。完整min/median/max和各族条件统计保存在summary。

| 配对比较（左减右） | TTL截尾索引差中位 | TTL多检出种子数 | 转移差中位 | 转移胜/负 |
| --- | --- | --- | --- | --- |
| guided vs unguided | +69 | -1 | +19 | 6/4 |
| boundary vs unguided | -71.5 | +2 | -67.5 | 0/10 |
| boundary vs guided | -372.5 | +3 | -94.5 | 0/10 |
| ttl vs unguided | -112.5 | +1 | -34 | 3/7 |
| context_repair vs unguided | 0 | -1 | -74 | 1/9 |
| ttl vs boundary | +147 | -1 | +13.5 | 6/4 |
| context_repair vs boundary | +136.5 | -3 | +11.5 | 7/3 |
| ttl vs context_repair | 0 | +2 | +27.5 | 6/4 |

TTL索引差负值有利，转移差正值表示覆盖更多；“多检出种子数”是十个配对检测差之和，不是独立漏洞数。这批完整边界反馈的TTL检出7/10优于无引导5/10，截尾配对指标也改善，但十个种子的转移覆盖全部下降；只能称本批次TTL敏感性改善。第五轮同一比较为8/10 vs9/10、配对差+48.5，方向不同，结果对种子敏感，尚未建立稳定全面优势。

两个消融组都没有在TTL检出率上超过完整boundary：移除TTL族降为4/10，只留TTL族为6/10。结果支持继续检验组合反馈，不能据此给每个标签分配独立因果贡献；Hypothesis多目标优化可能存在交互。TTL族相对无引导的配对索引改善幅度比完整boundary更大，但检出率低于boundary（6/10 vs7/10），说明不能只按单个中位数选优。默认搜索模式保持原值，不在本批次后选择新默认。

独立审查逐份核对50报告、模式标签、实际预算、轮换、来源指纹、探测计数与配对统计。raw/corrected全部50组语义覆盖、边界特征、四目标最大值和各族首个检出索引/违规码相同，仅活性误报与时间记录有差异。它们是相同种子的重跑，不能当作两份独立样本；Oracle修正发生在看到raw结果之后，因此本轮不声称全程盲验证。

## 复现与产物

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
output/recovery-fuzz-venv/bin/python experiments/run_recovery_evaluation.py \
  --modes unguided,guided,boundary,ttl,context_repair \
  --seeds 10,11,12,13,14,15,16,17,18,19 --budget 1000 --seed-role unseen_validation \
  --output-dir experiments/results/feedback_target_ablation_corrected
output/recovery-fuzz-venv/bin/python experiments/plot_recovery_evaluation.py \
  experiments/results/feedback_target_ablation_corrected/summary.json
output/recovery-fuzz-venv/bin/python -m pytest tests -q
```

修正后的产物在忽略Git的 `experiments/results/feedback_target_ablation_corrected/`，每组报告/corpus/首个缺陷反例、资格原始与缩减反例、summary及独立PNG/SVG图。runner自动重放全部反例和各组corpus，核对Oracle、语义覆盖、边界特征和四目标最大值；差异或完整机制违规使退出码非零。资格/缩减/重放执行不计入生成预算；壁钟每组含搜索、目标优化、变异探测及保存，不包含批次收尾重放，也不是独占机器性能基准。

## 活性断言误报与修正

原始50,000次批次完整结束，退出码1，保留在 `experiments/results/feedback_target_ablation/`，不覆盖、不混入修正批次统计。boundary的seed12和16触发 `recovery_stalled`；184个反例和50组corpus都执行了重放。两个corpus再次触发相同的活性违规，被runner的 `corpus_replay_mismatches` 归为验收失败；此处不是输入不能复现或覆盖不同。

保存输入的诊断前缀包含六次 `.6s` 的控制更新暂停（gap）。候选许可有效期为 `.5s`，完整机制正确拒绝过期许可；但旧Oracle把各个采样点之间的空窗计入“连续健康”，累计触发停滞断言。恢复正常 `.05s` 更新后，机制约 `.35s` 虚拟时间内恢复，支持这是采样连续性误报。原始报告来源匹配的8份源码快照、SHA清单及诊断轨迹均保留于原目录。

`SafetyOracle` 新增显式 `max_frame_gap_sec=.25`：超过该间隔只重启连续活性计时，等于该值仍连续；`liveness_sec=3` 保持原值。该前提覆盖本模型 `.05s` 和ROS审计 `.1s` 的正常更新，并低于本场景 `.5s` TTL。采样空窗不能证明其中连续健康，因此不据此推断活性；它不是额外的控制安全保证。授权、过期、上下文、一次性及重放检查仍跨空窗执行，`SAFE_STOP` 本身不会清空活性计时，连续更新中的真实停滞仍被检出。

红绿回归分别覆盖原始六gap复现、连续健康停滞、空窗后新的完整窗口、过期许可跨空窗和 `.25/.26s` 边界。修正后五组完整重跑，目标/动作分布/变异未按收益调整，报告额外记录Oracle实际参数和源码SHA；独立复审已核对该修改及原始源码快照。

## 边界

最终验证：全量 `597 passed`（新增6项目标消融、4项活性连续性测试），experiments与guardian_core的compileall、Humble两包构建及 `git diff --check` 通过。PNG/SVG已生成并目视检查，五组图例、刻度与标题可读。未把第四轮三进程实验当作本轮新测量。

没有发现违规不等于不存在缺陷。缺陷族检出数是“种子×预定义缺陷族”的统计，不能当作独立漏洞数；软件随机序列结果也不能证明物理制动或真实传感器安全。默认模式保留，服务未部署，DDS间歇启动超时问题不属于本轮离线目标消融的解决范围。

后续优先在独立协议中扩大执行预算，并增加等壁钟预算对照，检验收益是否抵消搜索开销。随后用未参与目标设计的缺陷族或外部恢复轨迹检验泛化。它们服务于证据与上下文绑定恢复机制的验证，不能把反馈工具的覆盖指标直接当作恢复机制的安全证明。
