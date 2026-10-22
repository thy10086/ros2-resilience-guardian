# 第四轮：重复实验、受控缺陷检出和机制消融

## 结论

已完成离线评估闭环：四类受控缺陷均被对应挑战检出，完整机制在配对挑战、21 条验收输入及 30,000 次批量执行中未触发安全断言；121 个保存反例重放无差异。这是测试敏感性与本项目软件恢复机制的证据，不是发现了四个生产漏洞，也不是实机安全证明。

当前 Hypothesis `target` 的“单序列状态数＋转移数”目标没有显示稳定收益：十个配对种子中，引导组仅四个获得更多转移覆盖，配对差值中位数为 -2；许可过期缺陷的检出率反而下降，耗时增加。保持无引导和固定边界用例作为基线，后续再评估针对许可边界的目标函数。

## 实现与开源复用

- `experiments/recovery_mutations.py` 用 Python 标准库 AST 对仓库自有恢复类施加四种预定义变异，编译到独立命名空间，不修改生产模块。目标分支匹配数量不符时直接失败；报告保留原始核心源码 SHA-256 和关闭的检查清单。
- `recovery_scenarios.py` 的 `variant` 仅属于离线执行器，默认完整机制；新增 `replay_proof` 动作调用真实协议授权入口。传感器原始证据与精确上下文继续提供给安全断言，不能用变异控制器的主张当作健康真值。
- `run_recovery_evaluation.py` 复用 [Hypothesis 官方生成、target、find 接口](https://hypothesis.readthedocs.io/en/latest/reference/api.html)，负责配对资格验证、批量执行、按预定义缺陷族去重、首个发现保存、预算截尾标注和消融报告。没有重写通用生成或缩减引擎。
- `ros_startup_diagnostics.py` 记录预期/实际 ROS 域、首个消息与控制端点出现时间、图发现和白名单进程环境；签名密钥不进入报告。
- 三个 ROS 节点复用 [rclpy Humble Context.try_shutdown](https://github.com/ros2/rclpy/blob/humble/rclpy/rclpy/context.py) 修正信号清理竞态，已关闭 context 时正常处理消息转换中断，存活 context 下的 RuntimeError 仍抛出。

## 实验协议

固定 seeds=0..9；每种模式每个种子 1000 次实际执行，共 30 组、30,000 次。引导与无引导使用相同动作策略、时序配置、32 动作长度上限和执行预算；生成组不预先运行固定种子。按种子奇偶交替两种生成组顺序，减少固定顺序偏差。

固定组循环已有 17 条边界输入到 1000 次，seed 标签不改变该组输入。它是已知边界参考，四类缺陷的命中来自预置挑战，不能解释为自动搜索发现未知漏洞，也不是十组独立随机样本。

完整机制执行每条输入，只有到达相关动作/许可时序的输入才额外执行对应变异；记录筛选、实际变异执行次数。每组发现某缺陷族后停止该族的额外探测，仅保留首次发现，避免反复计算同一故障。未发现的族按 1000 次预算截尾，不记为发现时间 0。首次发现时间包含观测、探测与保存成本，缩减搜索不进入生成预算。

四类缺陷分别为：取消许可时间区间检查；取消探测/消费/持续运行的上下文绑定；把已消费许可分支改为允许；使用适配器自报告替代独立融合证据。后者是机制消融，不是修改底层传感器协议。模型不包含真实 DDS 网络模糊测试。

## 多种子结果

2026-10-12，WSL Ubuntu 22.04，Hypothesis 6.168.5。下表为每组 1000 次执行的中位数，方括号为十组范围。

| 模式 | 状态数 | 转移数 | 壁钟秒 | 缺陷族检出总数 / 40 |
| --- | ---: | ---: | ---: | ---: |
| 固定边界参考 | 26 [26,26] | 36 [36,36] | 2.43 [2.34,2.47] | 40 |
| 无引导 | 157 [140,171] | 550.5 [478,633] | 5.50 [5.05,6.45] | 39 |
| 语义反馈引导 | 162 [142,180] | 559 [492,623] | 14.13 [12.31,17.02] | 34 |

独立比较两个组的中位数不能代替种子配对。按 seed0..9，引导减无引导的转移差为 `[-39,-2,-87,-116,-42,-2,37,83,63,89]`；4 胜、6 负、0 平，中位数 -2，未作显著性结论。时延来自本机一次批次，含探测与保存；并非独占机器的性能基准。

| 受控缺陷族 | 固定参考检出 | 无引导检出 | 引导检出 | 无引导首个索引中位数* | 引导首个索引中位数* |
| --- | ---: | ---: | ---: | ---: | ---: |
| 许可过期 | 10/10 | 9/10 | 4/10 | 293 | 392 |
| 上下文绑定 | 10/10 | 10/10 | 10/10 | 33.5 | 35 |
| 一次性许可重放 | 10/10 | 10/10 | 10/10 | 98 | 122.5 |
| 独立观测 | 10/10 | 10/10 | 10/10 | 5 | 5 |

*首次发现的统计只包含已检出的组，未检出样本有预算截尾；不能把两个条件中位数直接解释为总体发现速度差。详细首次发现秒数、索引和截尾信息在 summary.json。

## 配对挑战与消融

四条资格挑战中，四个变异均产生违规，完整控制均无违规。Hypothesis `find` 的 128 次预算缩减策略显式包含原始反例，只用于缩减，不进入生成基准。此次四条结果仍为 3 动作，未声称缩短或得到全局最短反例。

消融采用 4 条资格挑战加 17 条固定输入，五种配置，共 105 次运行。存在重复故障路径，因此下表的输入/帧数不能当作独立漏洞数。

| 配置 | 违规输入 / 21 | 不健康证据下授权帧 | 所有违规授权帧 | 违规恢复事件 |
| --- | ---: | ---: | ---: | ---: |
| 完整机制 | 0 | 0 | 0 | 0 |
| 取消许可有效期 | 2 | 0 | 2 | 2 |
| 取消上下文绑定 | 4 | 0 | 52 | 4 |
| 接受许可重放 | 2 | 0 | 2 | 2 |
| 移除独立观测 | 7 | 67 | 67 | 0 |

`unsafe_motion_frames` 仅统计 `unsafe_motion` 断言所指的不健康证据等授权错误；健康证据下的过期许可与上下文错配归入 `unsafe_authorized_frames`。恢复延迟只从显式非初始 `healthy` 修复动作边界计时；没有修复命令的 TTL/上下文挑战记为 null，不用故障前启动时刻冒充修复。完整机制显式修复样例约 0.05–0.35 秒，数值来自虚拟时间，不能与实机时延比较。此次无 eligible-stall 断言。

## DDS 排查与退出修复

增加诊断后，并行运行 ROS 测试时再次复现启动零话题超时。探针、三个子进程的 domain 均为194，控制订阅和远程主题已被发现，但节点图仅见探针，消息未到达。现有证据排除了域值不一致，尚未确认底层根因，不能把它归结为已修复的退出竞态。

另在 SIGINT/进程重启时复现已确认的退出问题：信号线程关闭 context 后，清理仍调用第二次 shutdown；AMR 还可在 take_message 转换期间遇到已关闭对象。已采用原生幂等清理，并将 context 已关闭时的转换 RuntimeError 视为正常退出，live-context 异常仍报错；有红绿回归测试覆盖。

`experiments/fastdds_udp_only.xml` 是参考 [Fast DDS 2.6 传输配置](https://fast-rtps.docs.eprosima.com/en/2.6.x/fastdds/transport/transport_api.html) 的诊断对照，未改生产默认。UDP 对照曾通过启动与19场景，但不能据单次结果断言共享内存是根因。最终运行和退出验收结果保留为 default/UDP 两份报告。

## 最终验收

全量回归 `569 passed`，Python compileall 与 ROS 2 Humble 两包重构建通过。独立审查提出的恢复延迟起点与违规帧分类问题已补充红绿测试并修正，没有剩余重要阻塞项。

默认 DDS 与 UDP 对照串行验收各 19 项全部通过，包括独立观测器进程重启和全部子进程退出码为 0。默认报告记录 264 帧、21 状态、26 转移；UDP 报告为 292 帧、20 状态、24 转移，两者均无安全断言违规。原始启动与语义报告分别保存在 `startup_default_validation.json` 和 `startup_udp_validation.json`；这些成功运行不代表间歇性 DDS 启动超时的根因已解决。

## 复现与产物

先按 [第三轮安装说明](recovery_feedback_fuzzing.md) 准备隔离 Hypothesis 环境。

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
output/recovery-fuzz-venv/bin/python experiments/run_recovery_evaluation.py --seeds 0,1,2,3,4,5,6,7,8,9 --budget 1000
output/recovery-fuzz-venv/bin/python experiments/run_recovery_evaluation.py --replay experiments/results/recovery_evaluation/qualification_no_proof_ttl.json
output/recovery-fuzz-venv/bin/python experiments/plot_recovery_evaluation.py experiments/results/recovery_evaluation/summary.json
launch_test experiments/independent_observation_launch_test.py
# 诊断对照，建议与其它 ROS 测试串行；仅此进程及其子进程使用该配置：
FASTRTPS_DEFAULT_PROFILES_FILE="$PWD/experiments/fastdds_udp_only.xml" launch_test experiments/independent_observation_launch_test.py
output/recovery-fuzz-venv/bin/python -m pytest tests -q
```

产物在忽略 Git 的 `experiments/results/recovery_evaluation/`：每组报告与 corpus、summary.json、qualification.json、ablation.json、121 个原始/缩减/首个发现反例、replay_verification.json，以及独立 PNG/SVG 图。绘图使用已有 Matplotlib，可选，不进入 ROS 或搜索工具依赖。

## 后续优先级

第五轮已按相同输入策略实施许可边界反馈：候选签发后到消费前的上下文变化、TTL接近程度和故障修复转移；旧目标作为对照保留。结果见 [许可边界反馈](permit_boundary_feedback.md)，本批次TTL检出比旧目标改善，但尚未优于无引导。后续先做目标独立消融及新种子验证，并继续采集默认DDS超时证据。通用IDS解除协议、Nav2行为树日志、物理仿真和硬件验证仍为后续独立阶段。
