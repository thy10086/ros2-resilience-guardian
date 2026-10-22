# 恢复语义反馈引导测试

用户已授权实施 docs/btreefuzz_recovery_testing.md 的借鉴方向。范围是离线测试，继续保留当前分支全部未提交工作，不提交/部署或连接机器人。

## 选择与复用

新增测试子系统。选择 Hypothesis 的 lists/sample_from/floats 策略、target 覆盖目标和 find 缩减接口生成与简化动作序列；复用 EvidenceBoundRecovery、SensorObservationBuffer、fuse_observations 和现有 launch_testing 三进程验收。项目只自行实现恢复语义状态、oracle 和场景适配。另一方案是自建 mutator/scheduler/shrinker，重复已有工具；完整行为树插桩需要 Nav2 等目标，本项目当前没有行为树。

查阅依据：BTreeFuzz 的 ICSE 官方摘要与作者论文列表；Hypothesis 官方 stateful、targeted testing、find/replay 文档；ROS 2 官方 launch_testing_ros 示例。尚未核实 BTreeFuzz 全文/作者仓库，不宣称复现其图相似性算法。Hypothesis 为离线工具依赖，安装在 output 下独立虚拟环境，不进入 ROS 生产运行依赖。

## 流程

Hypothesis 序列生成/目标搜索 → 实际恢复核心与独立观测核心执行 → 任务/恢复/ACK/证据/事件/上下文状态图 → 新状态/边保存语料 → 精确安全 oracle → JSON 报告与动作重放。

状态归一化忽略绝对时间、随机 proof_id、具体 graph/policy/hash、绝对 epoch，保留是否改变/失配以及任务阶段、恢复阶段和证据失效类别。归一化仅用于覆盖反馈和去重，oracle 使用原始精确绑定字段，运行时协议仍精确校验。

核心序列每次从新对象开始，使用可控单调时间和有界动作/步数。攻击、reset、健康/过期/重放/矛盾/无效/近障碍、缺少 ACK、图/策略/epoch 改变是有效动作。每步真正执行独立传感器校验、双源融合、预测包络和恢复协议；不伪造状态机输出。此高速目标不模拟 DDS/签名运输，报告明确区分 core target 与三进程 ROS 验收。

## 安全断言

- 缺失/不健康证据、未解决事件或无效上下文时不得授权。
- RESUMABLE 必须来自先前已签发许可，绑定相同 graph/policy/ledger、正确下一 epoch，且尚未过期；候选阶段必须停车并有匹配 ACK。
- 同一许可不得消费两次，签发后变更上下文不得消费旧许可。
- 健康证据持续、当前已停车 ACK 且无锁存 fault 时，要求在配置窗口内恢复；短暂还未成熟不能计作 liveness 违规。
- 真实 ROS 动作/运动验收继续独立执行，并将实际控制帧导入相同状态覆盖与 oracle，不将新颖状态直接视作漏洞。

语料保存动作序列、相对时间、配置、状态/边增量和原始 trace；无密钥。CLI 支持 seed、budget、guided/unguided、输出路径、重放保存的语料。发现违规时尝试用 Hypothesis.find 缩减并保留可重放输入；无违规只报告本次范围内未发现，不声称安全证明。

## 集成与验收

Guardian 仅在已配置 audit_path 时追加结构化 recovery_trace；字段为输入证据类别、精确上下文、许可信息和实际决定，不修改恢复策略或添加新 ROS 话题。现有三进程实验读取完整审计帧，生成状态图覆盖与独立 oracle 结果。

先写失败测试验证归一化的时钟/随机标识稳定性、区分同停车不同原因、去除重复 heartbeat、oracle 的正负例、序列重放与语料 JSON 往返。随后实现核心执行器和 Hypothesis CLI。运行固定种子 guided/unguided 小预算检查与语料重放、全量 pytest、Humble 重建/三进程验收及独立审查。

贡献为本项目的安全恢复语义反馈与违规检测。小预算覆盖数据仅是工具验收，不是论文效果比较；后续仍需等预算多种子重复实验与真实行为树目标。
