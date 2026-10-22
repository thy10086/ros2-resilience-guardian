# 项目代码逻辑与创新方向审查

日期：2026-10-19。范围：当前工作区恢复协议、ROS适配、离线Oracle、ARTEX风格编排与实验方法。三名独立审查agent分别审查恢复链、编排链和检测/实验；主agent重新执行全部五项关键异常探针。本轮未修改生产代码或原测试，未启动ROS节点、机器人或真实模型。

后续状态：本文保留修复前的复现记录与当时行号。用户已授权修复，R1–R5现已实施并补充回归；R1另将timestamp纳入签名、扣除到达前源年龄，并处理ROS冻结的旧传输；R2补暂停后的可恢复性。真实接口与页面入口也已实现。最终验收结果以最新 `HANDOFF.md` 与多角色使用文档为准，不能继续把以下历史探针结果当作当前未修问题。

结论：确定性恢复与研判旁路分离、一次性许可精确绑定、注册测试白名单等分层合理；当前仍有一项P1和四项P2。现有回归通过不能覆盖这些新增异常用例。以下为已经复现的问题，不将尚未实现的真实LLM/UI当作缺陷。

## 1. 已复现的逻辑问题

### R1 / P1：执行端缺少授权失效与失联停车

位置：`ros2_ws/src/guardian_core/guardian_core/amr_simulator.py:246`，重点是257–273行运动放行条件。

`AmrSimulationModel.update()`检查缓存命令与安全状态的身份配对、允许任务等条件，不保存或校验授权接收年龄。一次合法NONE命令和匹配NORMAL状态后，不再接收任何Guardian消息，仅继续更新执行模型，5秒后仍有 `actual_speed=0.2, distance_m=1.0, mission_allowed=True`。

Guardian进程内的ACK/watchdog逻辑不能在Guardian自身崩溃时产生停车输出。该问题限于当前软件AMR执行路径，未对真实硬件作出结论。建议执行端独立使用单调时钟校验命令/状态短租约；超时停车并撤销缓存授权，重新收到旧消息不能续租。新增“Guardian输入停止，执行端继续更新”的验收。

### R2 / P2：单源健康报告被接收时刻续期

位置：`guardian_node.py:363,370,432`（同上guardian_core目录）。

接收回调仅当次检查源timestamp的年龄，保存的RecoveryTelemetry时间却改为当前单调接收时刻；单源路径直接返回该缓存。合法短驻留配置 `max_age=.5,dwell=.2,stable=.1` 下，源年龄.49秒时接收唯一健康报告，在源年龄.74秒签发候选，.79秒时进入RESUMABLE并放行；此时接收年龄只有.30秒。

建议同时保存源时间/接收时间及各自截止，使用时都复核；源采集证据不能因延迟抵达而延长寿命。源ROS时间回拨也必须撤销。独立观测路径使用时会复核原始时间，不受该具体问题影响。

### R3 / P2：缺失速度证据被默认为零

位置：`recovery_feedback.py:26`、`dashboard_recovery.py:23`。

RecoveryFrame的 `observed_speed` 默认0，导入层没有要求此字段存在。真实 `healthy(.6)` 场景产生12帧；候选/RESUMABLE帧的速度显式设为.2时检出unsafe_candidate/unsafe_resume；删除所有帧的observed_speed键后却变为NO_VIOLATIONS。

建议在外部导入边界强制要求关键实测字段；兼容旧日志时标记证据不足，而不能将缺失转为满足零速条件的事实。保留构造器默认值的内部兼容需求与外部导入完整性要求应分开处理。

### R4 / P2：NORMAL续行漏检实际输出epoch

位置：`recovery_feedback.py:232`；生产审计字段语义见 `guardian_node.py:586,592`。

NORMAL检查当前输入command_epoch与先前授权相符，却未比较发布后的next_command_epoch。保持正常轨迹的其他字段不变，仅将最后NORMAL帧的实际输出epoch改为999，输入仍为2，Oracle和dashboard均返回NO_VIOLATIONS。

建议续行同时约束实际输出epoch与授权值，并验证相邻帧输入/输出连续性。会话开始/结束不完整或跨会话拼接应与真正的违规分开报告。此项是检测遗漏，未证明生产发布函数本身会生成999。

### R5 / P2：静态高危发现被模型零违规覆盖

位置：`experiments/agent_review/orchestration.py:219,358`、`experiments/run_agent_review.py:39`。

files分支把静态发现放入evidence与input_summary，却没有像frames分支一样登记输入目标及finding。包含动态执行和无约束控制发布的Python样例得到静态 `critical=1,high=4,verdict=BLOCKED`，总报告却为COMPLETE/NO_VIOLATIONS、findings为空，targets仅含自有虚拟模型，CLI退出0。

建议保留独立静态审查目标与STATIC_REVIEW发现；总体状态应保留静态风险、未检查项和运行检测各自状态，CLI不能表示整项审查无风险。静态嫌疑也不能直接提升为已触发的运行漏洞。这是源码分支的汇总遗漏，之前修过的轨迹分支仍正确保留违规。

## 2. 已有设计中值得保留的部分

- 恢复主链与Jev/agent旁路分离，模型意见不直接改速度、停车或许可。
- 图、策略、账本和下一epoch进入一次性许可；消费前重验，运行上下文变化撤销旧授权，事件TTL不充当解除证据。
- 固定执行目录、无任意源码工具、进程输出限额、seccomp和主管截止，把角色提示词与程序权限分开。
- 轨迹重算、静态线索、固定模型运行证据存在不同来源标签；仍需把R3/R5等结果传播缺口补齐。
- 既有实验代码包含等壁钟预算、预算外发现单列、配对种子、源码冻结、受控缺陷和重放；文档限制了已知模型内结果的适用范围。本轮未重新跑历史完整campaign，不据旧摘要新增效果结论。

## 3. 创新性定位与建议

相关工作的公开主源说明：

- [SOTER](https://arxiv.org/abs/1808.07921) 已研究高级控制器/安全控制器的运行时切换及其保证，因此“增加安全状态机/旁路控制器”不足以单独支撑新颖性。
- [ROSMonitoring 2.0](https://arxiv.org/abs/2411.14367) 已研究ROS主题/服务以及发布与接收顺序；论文所述ROS2支持是部分支持。一般的消息监控、顺序检查也不是本项目独有贡献。
- [BTreeFuzz官方摘要](https://conf.researchr.org/details/icse-2026/icse-2026-research-track/219/BTreeFuzz-Enhanced-Feedback-Mechanism-for-ROS-Program-Fuzzer-Based-on-Behavior-Tree) 将行为树任务日志转为状态图并以图相似性反馈选输入。本项目复用了任务/恢复状态反馈思路，没有复现其相似性算法，不能将图反馈本身重新声明为首创。

我的判断是：当前最有研究潜力的是“分布式恢复授权的证据与上下文完整性”，配以能挑战该机制的检测方法。以下是待验证的研究假设，不是已经证明的创新优势。

| 优先方向 | 本项目需要新增的具体机制 | 可检验的指标 |
| --- | --- | --- |
| A. 将授权延伸到执行确认与撤销 | 从Guardian内部一次性消费扩展为执行端可检查的短租约；绑定证据截止、上下文/epoch与ACK，失联或前提变化可撤销；明确消息延迟/时钟假设 | 最大失联续行时间、错配放行率、正常恢复延迟、误停车与恢复可用性 |
| B. 证据缺口驱动的反事实测试 | 明确哪些字段/来源/时序支持结论；逐次只改变源时间、ACK、图/策略/账本或epoch，检查“证据减少不应增加权限”等关系；加入独立包络边界检查 | 删除/篡改证据时的漏报率，未见缺陷检出率、独立复现率与单位预算有效反例 |
| C. 按可证问题规划的多agent选测 | goals提出可检验主张；planner按证据缺口/测试成本选目录项；worker产生原始见证；reviewer以独立程序结果反馈重规划；确定性验证仍为最终判据 | 与固定全选、规则选测、单agent对比的成本、检出/误报、引用有效率、未完成比例 |

三值结果、TTL、短租约和多agent分工分别已有成熟思想；应把创新主张落实到ROS2恢复的具体分布式协议、可验证不变量与有效实验，不能把这些组件名称当作新算法。

可继续复用开源设施：[TLA+/TLC](https://github.com/tlaplus/tlaplus)用于界定恢复协议状态/故障模型并检查不变量，[ROSMonitoring](https://github.com/autonomy-and-verification-uol/ROSMonitoring)作为独立通信观测框架候选，现有Hypothesis用于反事实动作生成与缩减。上述工具尚未安装或接入；需要适配Guardian事件/字段及明确假设，不能直接套用为已有安全证明。

当前scenario的故障/距离/速度仍高度离散（近障碍.01/正常5.0，速度0/.2等），Oracle的unsafe_distance标签还可能来自同一生产包络函数。因此建议扩展为制动距离两侧的连续挑战，并以独立公式或变形关系复核，减少控制器与检测器共享同一缺陷的风险。

验证上需要两个独立目标或外部轨迹来源、冻结后未参与设计的缺陷，以及等墙钟/等模型成本两种对照。ARTEX风格当前是fixture流程，每次默认选满六项；这能验收编排边界，尚未证明模型研判、智能选测或多agent收益。前端展示、agent数量和模块拼装属于工程交付，不宜作为论文核心贡献。

## 4. 本轮证据与可重跑入口

主agent本轮定向回归：

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 output/agent-review-venv/bin/python -m pytest -q \
  tests/test_recovery_feedback.py tests/test_dashboard_recovery.py \
  tests/test_bound_recovery.py tests/test_independent_observation.py \
  tests/test_agent_review_contracts.py
# 99 passed / 23.02s
```

核心异常探针：`python -I -S output/code-logic-review-20261019/core_probe.py`，纯标准库加载实际核心与抽取方法，使用明确合成签名值，未读真实配置。主agent重跑得到R1/R2相同结果。

检测/汇总异常探针：`output/code-logic-review-20261019/detection_probe.py`；已保存 `detection_probe_results.json`、`static_input.json` 和 `static_report.json`。静态样例中的代码只作待分析字符串，不执行。由于输入与输出采用排他创建，重跑应使用新的产物目录，避免覆盖本轮记录。

审查验证的是上述异常条件可在当前源码重现。它不等同于修复验收；R1–R5均尚未修复，建议先修这些逻辑项，再推进真实模型与跨项目实验。
