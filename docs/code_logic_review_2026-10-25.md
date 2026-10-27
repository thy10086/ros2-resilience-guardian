# 2026-10-25 项目深度审计与创新路线

审计基线：`main` / `5cc6f8c65e83809f76d3da0333cdf931cbf8889b`。审计开始时工作区干净。本轮没有修改生产代码或既有测试；新增本报告、交接记录及本机忽略目录中的复现探针。以下问题均尚未修复。

项目已经具有可运行的恢复安全机制、独立观测、确定性轨迹检测和受约束的多角色测试流程。当前最需要投入的是证据的时间与物理含义、跨进程生命周期、检测器自身的漏报边界，以及可复现部署。增加 agent 数量或提示词长度，不能解决这些问题。

本轮完整回归 **874 passed / 332.41s，0失败、0错误、0跳过**；结果见 [JUnit](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025/pytest.xml) 与 [日志](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025/pytest.log)。三个独立审查分别检查恢复链、检测与实验、agent 编排；主审重新执行探针并核对源码。现有回归通过与下列反例同时成立，说明覆盖仍有缺口。

## 1. 优先处理的恢复问题

### A01 / P1：有效期内的距离观测，没有按已经经过的时间折损

位置：[bound_recovery.py:136](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/bound_recovery.py:136)、[predictive_envelope.py:84](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/predictive_envelope.py:84)。

`RecoveryTelemetry.healthy()`正确检查采集年龄，但随后将原始净距直接交给运动包络。包络只使用固定的控制延迟与传感器延迟，没有接收该次观测实际年龄。已恢复运行时，一条尚未过期的旧观测可以被重复使用。

主审复现：观测年龄0.49秒、采集速度0.35m/s、采集净距0.34m，仍返回 `mission_allowed=True, speed_limit=0.35`。假设机器人对静止障碍匀速前进，此时剩余净距为 `0.34 - 0.35×0.49 = 0.1685m`；按项目配置，仅当前控制延迟、制动距离与安全余量也需要 `0.35×0.2 + 0.35²/(2×0.8) + 0.15 = 0.2965625m`。

影响：时间上有效的证据可能已经不能支持当前空间安全结论。此项证明核心许可与其制动假设不一致，未证明实机发生碰撞；软件模型的即时速度截断也不能验证真实制动过程。它不同于上轮已修的“到达时重新授予完整TTL”。

建议：把采集年龄、采样/配对误差和观测后最大可能位移纳入包络；明确固定传感器延迟是否已经包含在年龄中，避免重复计算。进一步覆盖加速、障碍运动和测量误差。验收应包含“同一采集事实下，证据变旧不能增加运动权限”的关系测试，以及实际制动模型的独立检查。

### A02 / P2，恢复能力缺口：Guardian 或执行适配器单独重启后，缺少受控重新接入

位置：[guardian_node.py:173](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/guardian_node.py:173)、[guardian_node.py:337](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/guardian_node.py:337)、[amr_simulator.py:204](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/amr_simulator.py:204)。

observer 已有启动会话处理；Guardian/AMR 的 epoch、ACK与遥测水位尚无对应的认证启动会话协议。

- Guardian重启：存活AMR处于epoch7/transmission100，新Guardian发送epoch1/transmission1…9均被旧水位拒绝；租期结束后停车且不能建立新的ACK闭环。
- AMR重启：存活Guardian已接收ACK序号1000，新AMR合法签名ACK1…7均被拒绝，最后反馈时间不更新，随后watchdog超时；遥测也受原水位约束。

停车本身符合安全原则；缺口是健康新进程无法通过受控流程重新加入。不能通过“看到小序号就清零”修复，否则会破坏防重放。

建议：在命令、状态、ACK、遥测及恢复上下文中绑定发行者/执行器启动会话；建立“撤销旧许可—确认停车—认证新会话—重建水位—重新观察—新许可”流程。复用现有observer会话跟踪设计，明确持久化和旧会话保留上限。用各节点单独/组合重启验证安全与可用性两类性质。

### A03 / P2：新的演示攻击重复使用旧事件序号

位置：[amr_simulator.py:119](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/amr_simulator.py:119)、[amr_simulator.py:344](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/amr_simulator.py:344)、[verifier.py:68](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/verifier.py:68)。

`speed_abuse`固定序号7001，`gripper_fault`固定7003，event_id也由固定序号组成。同一模型按“超速—reset—超速—reset—夹爪故障—reset—超速”运行，新事件的验证结果依次为 `ACCEPTED / REPLAY / ACCEPTED / REPLAY`。

影响：新攻击没有正常进入攻击登记、事件账本和风险统计，重复演示及恢复实验可能失真。bound模式仍能通过 `attack_active` 遥测停车，不能把它描述成已经绕过安全门禁。

建议：普通新事件使用来源生命周期内递增序号及唯一事件ID，场景reset不回退；只有明确的replay测试动作才复用原事件。补同一浏览器会话多轮攻击/恢复验收。

## 2. 检测结果仍存在的盲区

### A04 / P2：相对控制话题被漏识别

位置：[dashboard_code_security.py:234](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dashboard_code_security.py:234)、[dashboard_code_security.py:267](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dashboard_code_security.py:267)、[ros_graph_security.py:98](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/ros_graph_security.py:98)。

无namespace节点使用 `create_publisher(Twist, "cmd_vel", 10)` 并直接发布，单文件检查返回空topics、空publish_paths和空findings；安全图将其视作普通话题并返回PASS。相对名是正常ROS用法，在根命名空间可展开为 `/cmd_vel`，见 [ROS 2名称设计](https://design.ros2.org/articles/topic_and_service_names.html)。

建议：建立共享的资源名称解析层，结合namespace、launch remapping、节点私有名和配置上下文保留解析结果。能够确定时归一化；无法确定时输出解析缺口，不能直接丢掉控制路径。命名解析可参考/复用ROS现有语义，避免单纯再增加字符串正则。

### A05 / P2：部分门控字段被改写后，旧门控仍被视作有效

位置：[dashboard_code_security.py:193](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dashboard_code_security.py:193)、[dashboard_code_security.py:302](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dashboard_code_security.py:302)。

检查器认可 `emergency_stop/e_stop/safe_stop/motion_allowed` 等名称，但赋值后的证据失效集合只包含部分名称。最小反例在 `if self.emergency_stop: return` 之后执行 `self.emergency_stop = True`，再限幅并发布 `/cmd_vel`。检查器仍返回 `guarded=True`、无findings，安全图PASS。

建议：门控识别与失效共用同一名称/极性定义，覆盖普通、注解、增量赋值；后续再补别名、函数副作用和消息其他速度轴。现阶段应保持“识别到的语法模式”与“完整路径安全证明”的区别。

### G01 / 检测能力缺口：现有Oracle主要验证恢复授权，不能独立证明运动包络正确

位置：[recovery_feedback.py:201](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/recovery_feedback.py:201)、[dashboard_recovery.py](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dashboard_recovery.py)。

构造字段完整、许可/epoch/上下文合法的三帧候选—恢复—NORMAL轨迹，仅把NORMAL的 `speed_limit` 改成 `1e100`，结果仍是 `NO_VIOLATIONS`。Oracle检查有限、非负和停车输出为零，却没有已绑定策略的正上限或独立制动包络检查。现有帧也缺少重算所需的净距、年龄、制动参数等原始字段。

这是确定的属性覆盖缺口，不是生产控制器实际输出 `1e100` 的证据。当前报告对非实机认证已有说明，应进一步按属性给出“满足/违反/证据不足”，例如授权可判定、物理包络不可判定，避免绿色总览掩盖检测范围。

建议：以版本化schema补充最小原始证据、策略参数或可信参数引用，增加独立包络检查，并显示每项属性的输入依据。导入日志的SHA只固定字节身份；现有导入器已正确标记 `authenticated=False`，后续需要来源认证、会话边界、截断和序号缺口支持，不能仅靠多加哈希宣布证据可信。

## 3. 多智能体研判：执行闭环存在，研判闭环仍不完整

### A06 / P2：合法大批输入没有可满足的reviewer输出

位置：[orchestration.py:372](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/orchestration.py:372)、[orchestration.py:504](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/orchestration.py:504)、[orchestration.py:514](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/orchestration.py:514)、[provider.py:183](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/provider.py:183)。

输入允许最多128个文件，reviewer必须一次返回全部findings对应记录，但角色回复限制16,384字节，真实接口另设2,048 completion tokens。128个仅含 `int main() { return 0; }` 的CPP文件会产生128项未支持语言发现。即使解释字段全部为空、JSON去除空白，必要字段仍需 **29,581字节**，超过硬上限。

纯内存探针保留真实编排/契约，仅把执行子进程边界替换为可信固定目录的 `run_case`：8/32文件完成，64/128文件在六次场景计算后均 `INCOMPLETE / role response too large`，reviews为空。64项与默认解释长度有关；128项则任何模型回复都无法满足现有契约。此探针不验证隔离子进程或真实供应商。

建议：程序维护身份字段，模型返回紧凑解释/引用；按字节与token预算分批复核，保留已完成批次，提前检查总预算可行性。确定性发现现在会保留，这是正确行为；不应为了完成任务而静默删掉发现。

### A07 / P2：多文件输入使规划阶段看不到具体风险证据

位置：[contracts.py:162](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/contracts.py:162)、[orchestration.py:352](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/orchestration.py:352)、[orchestration.py:382](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/orchestration.py:382)。

证据列表先放全部 `source_file`，再放 `static_finding`；每次角色调用只传前8条。达到8个文件时，goals/planner得到的具体证据全部是文件摘要，规则、严重度和位置不在其可见范围内。goals还有总体风险数量，但有效引用也受前8条限制；planner没有按ID补读证据的实际工具。

影响：报告仍保留确定性静态风险，不能说全部风险丢失；但“根据证据选择测试”的输入已经不足，文件顺序可能影响研判质量。

建议：按风险和证据类型分层选择，保证关键规则证据进入上下文；增加只读证据ID补读，记录每个角色实际读取的证据。验收包括把相同风险移到第9/第128个文件后，仍能被规划引用，且不超信息/调用预算。

### 当前成功程度的准确表述

| 方面 | 当前判断 | 依据与边界 |
| --- | --- | --- |
| 角色调度与实际测试 | 已实现 | goals、planner、worker、reviewer可串联，注册场景由程序执行 |
| 工具权限与隔离 | 有实质实现 | 白名单、seccomp、进程截止、预算和会话归属；权限不是只靠提示词 |
| 报告绑定与复放 | 有实质实现 | 目标/计划/来源/产物绑定，程序复算Oracle并逐finding匹配 |
| worker智能探索 | 尚未实现 | 模型目前确认固定intent，实际执行由程序完成；这属于明确设计限制 |
| reviewer反馈再规划 | 尚未实现 | 当前边为reviewer→END，没有回到planner的有界修订回路 |
| 无发现结论复核 | 不充分 | findings为空则reviews为空，没有结构化检查未覆盖属性/触发前提 |
| 模型独立反证 | 有限 | 程序保护标签；反证解释目前主要检查类型/长度，缺少命题级证据约束 |
| 真实模型质量与收益 | 尚未证明 | 协议fixture与固定场景通过不等于多角色优于规则或单agent |

当前图见 [orchestration.py:530](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/experiments/agent_review/orchestration.py:530)。模型调用还位于角色全局锁内，不能把“最多3个worker”解释为3路模型请求并行。工程上合理的下一步是有界证据补读、批量复核与基于反证的再规划，不是先解除工具限制。

## 4. 部署与持续验证

### A08 / P2：按ROS安装布局运行时，agent环境定位仍返回503

位置：[dashboard_agents.py:64](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dashboard_agents.py:64)。

在实际Humble安装环境导入，模块位于 `install/humble/guardian_core/lib/python3.10/site-packages/guardian_core/`，`parents[4]`得到 `install/humble/guardian_core`，不是仓库根；函数实际返回 `runtime_unavailable / 503`。源码PYTHONPATH下成功不覆盖该部署路径。

这是10月22日交接已记录而尚未修复的问题。本轮重新复现。建议将研究runner做成独立可安装包/服务，或使用明确的受信管理员配置定位；提供环境doctor和安装后API冒烟测试。不能由客户端传入任意解释器路径。

### A09 / P2，验证保障缺口：默认CI没有安装研究测试依赖

位置：[ros2.yml:32](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/.github/workflows/ros2.yml:32)、[ros2.yml:54](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/.github/workflows/ros2.yml:54)、[test_agent_review.py:13](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/tests/test_agent_review.py:13)。

当前workflow安装ROS依赖、pytest和yaml，未安装两份研究requirements。多项agent/Hypothesis测试使用 `importorskip`。本机普通Python针对agent_review和recovery_fuzzing两个测试文件得到 **7 passed / 8 skipped**；研究venv完整回归则为874通过、零跳过。

这不是对某次GitHub Actions运行状态的断言；它证明当前CI定义不保证关键研究测试实际执行。建议分开ROS运行时与研究测试作业，在后者固定依赖、验证seccomp可用、对指定测试的跳过显式失败；另加安装布局及启动闭环测试。ROS运行环境不必因此混入LangGraph依赖。

### A10 / P2：旧Jev代理的timeout仍不是整个请求的总截止

位置：[dashboard_jev.py:291](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dashboard_jev.py:291)。

`open(timeout=timeout)`后直接 `read`。单个本地fixture每50ms发送一个字节，配置timeout0.15秒，实际约0.65秒才完成且没有超时。新agent provider已有主管总截止，旧Jev通路尚未采用同等机制。

影响：慢速持续返回可长期占住HTTP工作线程，页面等待与标称超时不一致。本轮只用一个临时回环服务和无凭据虚构数据复现，未做负载攻击。建议复用有绝对截止、取消和有界输出的统一模型传输层；不要把每次socket等待超时当作整个请求期限。

### A11 / P3，局部API边界：本地数据集扫描跟随文件符号链接

位置：[dataset_security.py:96](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dataset_security.py:96)、[dataset_security.py:106](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dataset_security.py:106)。

`resolve()`后才调用 `is_symlink()`，根链接检查失效；枚举也会将指向根外的文件链接当作普通文件读取。临时目录中指向另一份虚构Python文件的链接被扫描，并以根内文件名生成风险发现。

边界必须说明：HTTP ZIP上传在 [dataset_upload.py:308](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/dataset_upload.py:308) 已拒绝符号链接，因此本轮没有证明远程上传任意文件读取。问题适用于直接扫描不可信本地语料及未来目录接入，可能混淆扫描范围和来源。

建议：在解析前拒绝链接并验证每个实际目标仍属于批准根；若要抵抗并发替换，使用不跟随链接的文件打开方式，不能只做一次字符串路径检查。

## 5. 需要补齐的产品功能

| 功能 | 应补内容 | 可观察的完成标准 |
| --- | --- | --- |
| 可复现启动 | 正式纳入经验证的启动方案，环境doctor、实际就绪状态、明确错误日志 | 新环境按文档安装后，模型列表/离线测试/取消/下载均可用，安装副本不依赖源码路径覆盖 |
| 跨进程恢复 | 发行者、执行器、observer的认证会话与重启接入 | 单节点重启后旧许可无效，健康环境能重新建立闭环 |
| 项目级静态分析 | 相对名、namespace、remap、launch、C++解析及不确定性 | 支持矩阵公开；不支持路径明确标记，不能混入“已检查通过” |
| 外部轨迹接入 | rosbag2到版本化证据schema的适配，来源/时间域/会话清单 | 同一原始bag可重复导入；缺失字段、断流、截断和时间不同步有明确结果 |
| 研判可追踪性 | 实际读取证据、分批复核、反证请求、局部完成保存 | 每条结论可追到证据和执行，合法大输入不因固定回复限制必然失败 |
| 检测页结果表达 | 按属性展示证据充分性、输入对象和检测范围；来源摘要与报告一致 | 用户能区分上传程序、原始日志重算、自有模型测试和未检查属性 |
| 实验交付 | 脱敏最小原始数据包、源码/Oracle/环境版本、种子与重放入口 | 第三方可从公开产物复算关键表格；源码ZIP不被误当完整实验数据集 |
| 真实ROS安全边界 | SROS2权限、独立来源、异常发布者、证书/会话生命周期测试 | 多机器人命名空间及未授权发布的隔离有实测，而不只存在部署说明 |

现有原始导入器主要接受JSON/JSONL；此前用户选择的是自有DDS软件闭环数据。本轮没有把它重新称作外部机器人数据。10月22日的组合进程演示和DDS间歇启动问题仍需单独验收；本轮pytest成功不能证明历史多进程启动问题已根治。尚未重新构建Jazzy、开展硬件测试或调用真实供应商。

## 6. 创新方向：建议主线加两个支撑点

以下是研究假设与建议的验收标准，不是已经证明的新颖性或性能优势。若目标是论文，应先修上述问题，再冻结机制与评价协议。

### 方向一，优先主线：时间、空间与启动会话共同约束的恢复授权

现有基础是证据账本、上下文指纹、一次性许可、双流租期和独立观测。新增贡献应聚焦：证据年龄如何改变可行动作，节点重启如何撤销旧授权，以及执行端如何确认新授权仍建立在当前可信前提上。

最小机制可包括：带会话的观测身份、采集年龄/误差、保守当前净距或可达集上界、策略版本、授权epoch和执行确认。明确时钟误差、最大通信延迟和制动能力假设；使用TLA+/TLC检查重放、错会话、撤销与重新接入状态机，物理包络另做独立数学/仿真验证。有限模型检查不等于实机证明。

对照为固定TTL方案、当前绑定方案、加入年龄折损的方案、加入重启会话的完整方案。指标至少包含不安全放行、最小制动余量、失联续行上界、误停车率、恢复成功率和P95恢复延迟。可把100组单独/组合重启与延迟/乱序组合设为首轮工程验收，正式实验仍需独立故障集和不同任务。

### 方向二，检测创新：按属性判断证据是否足够，并用反事实挑战结论

把“未触发违规”细化为每项安全属性的“满足/违反/证据不足”。不同结论需要不同原始证据：授权合法不等于速度包络正确，字节哈希一致不等于来源可信，单个健康点也不等于持续健康。

在独立Oracle中检查变形关系：减少/老化证据不得增加权限；单独改变图、策略、epoch或启动会话应撤销旧授权；只改变日志顺序/截断不应凭空产生可信健康窗口；越过连续制动边界应改变判定。将反例与原始轨迹、属性、见证和最小修改一起输出。

测量每项属性的漏报、误报、不可判定率、检测延迟、证据引用正确率及缺失/乱序下的结论稳定性。对照现有Oracle、简单规则和独立时序监测实现；缺陷或标签不能由参与设计该Oracle的人单方面生成后自行评分。

### 方向三，agent创新：证据缺口驱动的有界再规划与测试预算分配

在保留程序权限边界的前提下，从“六项固定场景选子集”推进到审定动作DSL：允许受限TTL、证据年龄、epoch/图变化顺序、断流长度等参数。每项计划明确可证伪命题、所需证据、测试成本和停止条件。reviewer给结构化异议与白名单复放请求，程序校验后进入有限轮次的planner修订。

程序继续决定违规与授权；模型负责证据补读、假设选择和下一次测试。即使没有finding，也应复核触发前提、覆盖缺口及未支持属性。不要让模型自行生成任意shell或操作机器人来获得所谓自主性。

至少比较：固定全选、规则选测、现有反馈模糊测试、单agent、四角色流程；再比较无reviewer、纯文字reviewer和结构化反证reviewer。分别控制模型token/费用、总场景执行数和墙钟时间，所有补读/复放计入预算。使用冻结后未见缺陷、外部目标与干净负例，报告独立缺陷数、首次发现时间、过度断言率、重复测试率、未完成率及每个有效反例成本。

这一方向需先解决A06/A07，否则“智能选测”的输入和输出预算自身就不成立。自适应反馈调度可作为后续扩展：在语义覆盖、许可边界、持续健康目标间按单位计算成本调度，而不是把所有目标同时优化。调度器不能读取测试缺陷标签或Oracle真值来指导搜索。

### 已有实验能支持到哪里

第八轮同一批次停滞缺陷检出为liveness **16/20**、固定组合 **7/20**、无引导 **5/20**，见 [历史结果](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/docs/recovery_liveness_feedback.md:27)。这是已知缺陷的新种子结果。第九轮两类新受控缺陷在两组中均 **20/20**，未出现新增检出优势，见 [迁移验证](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/docs/recovery_transfer_validation.md:28)。这些是历史记录，本轮未重跑完整campaign。

这些结果支持继续研究目标选择与搜索成本，尚不能支撑“反馈普遍优于随机”“多agent有效提高检出率”或“适用于任意机器人”。建议至少两个独立目标/数据来源；正式重复次数应结合预期效应与预算确定，并报告配对结果、区间和截尾处理，不以单次最佳值作主要证据。

## 7. 开源复用与相关工作边界

本轮核对的主源是针对性比较，并非系统性文献检索；不能据此断言首次提出。

| 参考 | 可复用之处 | 本项目需要形成的差异 |
| --- | --- | --- |
| [BTreeFuzz官方摘要](https://conf.researchr.org/details/icse-2026/icse-2026-research-track/219/BTreeFuzz-Enhanced-Feedback-Mechanism-for-ROS-Program-Fuzzer-Based-on-Behavior-Tree) | 行为树日志、任务状态图与反馈选输入的研究思路 | 恢复授权/证据时空边界专用反馈与独立属性判定；本轮仅核对摘要，未证明复现其图相似算法 |
| [SOTER](https://arxiv.org/abs/1808.07921) | 运行时保证与控制器切换的既有研究 | 分布式恢复证据、撤销及重启接入语义；普通安全状态机不作为独立新颖点 |
| [ROSMonitoring](https://github.com/autonomy-and-verification-uol/ROSMonitoring) | 通信观测、顺序化日志、外部Oracle接入 | 将它作为独立观测/对照候选，补本项目恢复属性与输入适配；不要重写通用监测框架 |
| [Nav2 Collision Monitor](https://docs.nav2.org/rolling/tutorials/general_tutorials/using_collision_monitor/using_collision_monitor/) | 速度链末端的传感器安全过滤与外部目标/基线 | 用恢复后运动与上下文撤销挑战做比较；该组件本身也不代表硬实时安全认证 |
| [TLA+/TLC](https://github.com/tlaplus/tlaplus) | 状态机模型检查 | 建模本项目会话/许可/时序假设，检查实现与规格的对应关系 |
| [SROS2](https://github.com/ros2/sros2/blob/rolling/README.md) | DDS-Security部署工具 | 独立身份、最小权限与认证来源，不能由共享HMAC和图GID直接替代 |

现有LangGraph、Hypothesis、ROS launch_testing继续复用。ARTEX角色与调度参考已落入当前工程；角色数量、红队措辞、页面可视化或把几个开源库拼接起来，本身不足以支撑论文核心创新。

## 8. 建议实施顺序与验收

1. **先修核心与检测反例。** A01优先；A03、A04、A05补最小回归。对G01先明确属性范围与证据不足结果，再扩schema和独立包络。完成标准是本轮反例被正确拒绝/标记，正常对照仍可恢复。
2. **修研判与安装闭环。** A06分批复核、A07证据补读、A08安装定位、A09研究CI、A10统一传输。验收128文件边界、多文件风险位置变化、实际安装环境、取消/超时/下载及关键测试零跳过。
3. **扩展跨进程恢复。** A02会话协议与模型检查；补正式多进程启动及SROS2隔离。验收旧会话重放永不续行、合法新会话能够恢复、重启不要求无关进程一起重置。
4. **再做研究增益实验。** 固定机制与Oracle，接独立来源的ROS2任务/轨迹，开展等预算规则/单agent/多agent及反馈目标对照。数据允许负结果，发现边界也应进入报告。

## 9. 本轮可重跑证据

探针为审计用临时脚本，不属于产品功能或正式回归测试。目录：[output/audit-20261025](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025)。

| 入口 | 验证内容 | 限制 |
| --- | --- | --- |
| [recovery/probe.py](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025/recovery/probe.py) | A01–A03 | 纯核心及AST抽取生产类，不是重启真实进程或物理制动实测 |
| [detection/probe.py](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025/detection/probe.py) | A04、A05、G01 | 源码只作为字符串分析；完整最小输入保存在同目录 |
| [agents/probe.py](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025/agents/probe.py) | A06、A07 | 仅本进程替换runner执行边界，运行固定模型，不测试真实provider/沙箱 |
| [main_probe.py](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025/main_probe.py) | A08、A10、A11 | 安装路径实际导入；一个临时回环HTTP服务；虚构本地文件 |
| [system-python-optional-tests.log](C:/Users/thy/Documents/Codex/ros2-resilience-guardian/output/audit-20261025/system-python-optional-tests.log) | A09 | 系统Python的两文件对照，不是远程CI运行日志 |

从WSL仓库根执行纯探针：

```bash
PYTHONPATH=ros2_ws/src/guardian_core output/agent-review-venv/bin/python -B output/audit-20261025/recovery/probe.py
output/agent-review-venv/bin/python -B output/audit-20261025/detection/probe.py
output/agent-review-venv/bin/python -B output/audit-20261025/agents/probe.py
python3 output/audit-20261025/main_probe.py
```

安装布局探针在干净shell中source `/opt/ros/humble/setup.bash` 与仓库 `install/humble/setup.bash`，不额外覆盖源码PYTHONPATH，然后执行 `python3 output/audit-20261025/main_probe.py --installed`。完整测试使用研究venv、上述Humble overlay及 `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`，仅收集 `tests/`。

本轮没有使用真实API Key、调用外部模型、连接物理机器人、执行上传代码或重新发布GitHub。pytest中的ROS/HTTP验收使用测试自身的隔离域与临时端口；没有启动8080演示服务。本轮产物哈希和校验摘要另见同目录 `audit-receipt.json`。
