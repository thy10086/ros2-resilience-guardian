# 恢复语义反馈测试：最小闭环

## 本轮落地范围

借鉴 BTreeFuzz 官方摘要中的“任务状态转移反馈”，为现有安全恢复机制增加离线测试闭环：

`动作序列 → 生产恢复/观测代码 → 语义状态与转移 → Hypothesis 搜索目标 → 有价值输入保存 → 安全断言 → 违规缩减与重放`

现有项目没有行为树，因此不增加人为的行为树执行层，也不宣称复现论文未公开核实的图相似性算法。当前采用精确的归一化状态/转移新颖性。论文依据与推导见 [BTreeFuzz 分析](btreefuzz_recovery_testing.md)。

## 开源复用和项目新增代码

复用 [Hypothesis](https://hypothesis.readthedocs.io/en/latest/stateful.html) 的动作列表生成、`target` 搜索和 `find` 缩减；依赖固定在 `experiments/requirements-fuzzing.txt`，仅用于离线实验。复用 ROS 2 `launch_testing` 管理真实 DDS 三进程场景。未找到可核实的 BTreeFuzz 作者代码入口，当前不依赖作者实现。

本项目新增三个部分：

- `guardian_core/recovery_feedback.py`：原始审计帧、状态归一化、状态/转移覆盖、安全断言。任务阶段、恢复阶段、证据类别、ACK、未解除事件、图/策略/账本/epoch 的变化关系共同构成状态；覆盖统计忽略绝对时间和具体标识，不替代精确授权校验。
- `experiments/recovery_scenarios.py`：虚拟时间执行实际 `EvidenceBoundRecovery`、`SensorObservationBuffer` 和 `fuse_observations`。场景模型不重新实现恢复算法；每条序列使用全新核心实例，消除跨用例污染。
- `experiments/run_recovery_feedback_fuzzing.py`：搜索、报告、保存 corpus 和精确动作重放。新状态不是漏洞，只有 oracle 违规才计为失败并尝试缩减。

`target` 使用单条序列的状态数加转移数，目标在重放时保持确定性；全局新颖性用于保留输入。这是最小可运行的反馈搜索，并非基于全局覆盖增益的自定义队列调度器。

## 动作与安全断言

动作包含正常证据、攻击、传感器暂停/过期/重放/非法扫描/速度矛盾/近障碍、未清命令、探测失败、ACK 缺失、图缺失/改变、策略改变、epoch 改变，以及保持更新的 `wait` 和暂停更新的 `gap`。每条序列最多 32 个动作，每个动作 0.01–1 秒。通常每 0.05 秒调用恢复核心；`gap` 专门跳过更新后再调用，覆盖许可 TTL 边界。

安全断言独立检查：

- 不健康证据、未解除事件、缺失上下文或强制停车时禁止任务运动。
- 候选许可签发和恢复消费需要匹配停车 ACK 与零速度观测。
- 恢复必须使用先前签发、未撤销、未过期且未消费的许可；精确匹配图、策略、账本和输出 epoch，并验证输出 epoch 等于输入 epoch 加一。
- `NORMAL` 必须继续使用已授权上下文，停车会撤销旧候选许可。
- 连续健康、停车 ACK 有效、上下文稳定且无强制停车的窗口内应恢复，避免永久停车；默认观测上限 3 秒。

Liveness 是测试约束，需随实际恢复配置调整；当前虚拟场景 dwell=0.2、stable=0.1、TTL=0.5 秒，真实测试使用默认恢复配置。控制更新长时间中断、watchdog 锁存和未解除故障不视为无条件必须恢复。

## 运行

在 WSL Ubuntu 22.04 项目根目录安装隔离离线环境：

```bash
python3 -m venv --system-site-packages output/recovery-fuzz-venv
output/recovery-fuzz-venv/bin/python -m pip install -r experiments/requirements-fuzzing.txt
output/recovery-fuzz-venv/bin/python experiments/run_recovery_feedback_fuzzing.py --seed 42 --budget 64 --mode guided
output/recovery-fuzz-venv/bin/python experiments/run_recovery_feedback_fuzzing.py --seed 42 --budget 64 --mode unguided --output experiments/results/recovery_feedback_unguided.json
output/recovery-fuzz-venv/bin/python experiments/run_recovery_feedback_fuzzing.py --replay experiments/results/recovery_feedback_guided_corpus.json --output experiments/results/recovery_feedback_replay.json
```

输出报告、interesting corpus 和重放报告位于忽略 Git 的 `experiments/results/`。命令发现安全违规时退出码为 1。报告记录种子、实际执行次数、覆盖、耗时和违规；Hypothesis `find` 只在出现违规时运行，受 256 次搜索预算限制，未重新发现则明确标记，不保证全局最短反例。

真实 ROS 验证：

```bash
bash deploy/run_guardian.sh build --distro humble
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
launch_test experiments/independent_observation_launch_test.py
output/recovery-fuzz-venv/bin/python -m pytest tests -q
```

Guardian 仅在配置 `audit_path` 时输出 `recovery_trace`；日志复用有界轮转审计，记录实际发布后的命令 epoch，不含签名密钥。三进程测试保留原 18 项验收，再将完整恢复轨迹送入相同覆盖器与安全断言。报告中新增 `semantic_feedback`。

## 当前测量与结论

2026-10-12，Hypothesis 6.168.5，seed=42，每组 16 条固定种子和 64 次生成执行：

| 模式 | 状态数 | 转移数 | 保留输入 | 安全违规 |
| --- | ---: | ---: | ---: | ---: |
| feedback guided | 56 | 84 | 36 | 0 |
| unguided | 65 | 104 | 39 | 0 |
| guided corpus 重放 | 56 | 84 | 36 | 0 |

同种子的小预算实验中，引导组覆盖低于无引导组；此轮证明工具闭环和可重放性，尚未证明引导收益。没有发现违规也不能推出系统不存在缺陷。后续需要多种子、足够预算、首次发现时间与唯一违规统计，并比较目标函数，而不是只报覆盖数。

独立审查发现并修正：撤销许可仍被 oracle 接受、缺少消费输入 epoch 校验，以及逐周期更新导致 TTL 过期路径不可达。相关回归和注入式缩减测试纳入测试集。

最新全量测试 `548 passed`（新增 19 项），Humble 两包构建和 compileall 通过。真实三进程 19 个验收场景通过；一次串行验收记录 269 帧、21 个状态、26 条转移、0 个安全违规。并行运行全量 pytest 时曾出现一次 DDS 启动阶段零话题超时，串行复验通过；未确认该瞬态超时根因，复现命令建议串行执行，不将它计为恢复安全漏洞。

## 边界和后续

第四轮已经完成多种子对照、受控缺陷资格验证和消融，结果见 [重复实验报告](recovery_evaluation.md)。新增 replay_proof 动作后当前固定种子为17条；本页16条种子/64生成结果是第三轮的历史测量，不应与新策略直接混合统计。

离线搜索覆盖恢复/观测核心；ACK 是场景模型，未生成真实 DDS 网络延迟、认证消息重放或任意传输序列。真实 DDS 故障目前由固定三进程验收验证。观测数据来自软件 AMR 模型，不能证明实机制动或物理净距安全；行为树插桩、Nav2 集成和硬件验证留待后续。主线贡献仍是证据与上下文绑定恢复，语义反馈测试是验证工具。
