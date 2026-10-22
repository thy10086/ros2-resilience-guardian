# 参考 ARTEX 的 ROS 2 多 agent 证据研判与测试设计

日期：2026-10-19。状态：**用户已确认第一阶段实施；后续真实模型与前端按阶段推进**。

目标：在既有静态安全分析、恢复测试和证据回放之上，增加“目标/证据研判 → 测试规划 → 有界执行 → 独立复核”的旁路。用户要求参考本地 ARTEX 的 agent 设计、限制与提示词；本设计将其落实为 ROS 2 专用契约。运行时的停车、许可和执行器控制继续由现有确定性核心负责。

## 1. 主参考与已核对事实

主参考是用户本地 `D:/ARTEX`，origin 为 `https://github.com/mhtsec/ARTEX.git`，HEAD 为 `a9d11cb852eadad00669e4f6a05ee59cbbd14860`。该仓库本轮仅只读检查，未启动其服务或执行安装脚本，未读取 `.env`、`jwt.key`、运行数据和凭据。当前两处已有 skills 修改与本设计无关。逐文件 SHA256 见 [参考清单](../../artex_ros2_reference_audit.json)。

最初查到的 `BaaRai/ARTEX` 是辅助参考，其 `7ef07417549a6cfc126731ad704644f92f968760` 版本含额外提示词段落。**不能把派生版本新增的提示词防护、反证要求等记到本地版本。** 截至本次查询，Autumn-27 与 mhtsec 的原 GitHub 页面均返回 404；本地源码是此次判断的依据。

| 本地源码 | 确认的行为 | ROS 2 迁移决策 |
| --- | --- | --- |
| `agent/goals.go` | 将目标拆为可验证交付物，提取明确给定的范围 | 限于当前提交文件、轨迹与注册测试目标；不扩张 ROS 域或网络范围 |
| `agent/planner.go:297` | 图变化触发规划，基于已有意图/事实去重，生成后续意图 | 根据当前证据与覆盖缺口选测试，禁止无限追加任务 |
| `agent/worker.go:230` | 一次领取一个意图，区分资产与探索事实；确认发现要求实际触发证据 | 一次处理一项已审定测试，静态嫌疑与实际恢复违规分别登记 |
| `db/exploration.go:1173` | `open → running` 带任务与当前状态条件的原子 UPDATE | 采用任务内原子领取与一次完成，拒绝重复执行和迟到写回 |
| `server/engine.go`、`server/engine_timeout.go` | planner/worker 循环、暂停/取消、deadline 与收尾 | 保留有界调度思想，测试子进程另设可终止的硬截止 |
| `agent/retester.go:4`、`db/finding_retests.go` | 单条发现的独立复测；复现/修复/无法确认区分，保留历史记录 | 复核器重新读取原始产物并回放；超时或前置条件缺失只能无法确认 |

以下边界不能照搬，也不能把提示词承诺当成已实现权限：

- `agent/constraints.go` 把范围约束写入提示词，属于模型行为约定。
- `agent/planner.go:375,412` 与 `agent/worker.go:379,436` 装配 SDK 通用工具并使用 `ModeBypass`。`agent/toolcatalog.go:30` 明确通用 Bash/文件工具不进入领域工具绑定过滤。planner 不是程序强制的纯只读角色。
- `guard/guard.go:83` 在 interceptor 缺失、工具未启用拦截、没有规则且 judge 不接管时可放行。规则与 judge 可配置；不能作为机器人安全授权的最终门。
- `norma/harness/query.go:609` 的收尾禁用列表过滤发给模型的工具 schema；`norma/harness/tools.go:28` 从 registry 取工具。只隐藏 schema 不等于服务端拒绝该工具。
- `goal_met` 有直接完成任务的实现，但 `agent/toolcatalog.go:52` 将其默认不绑定任何 agent，管理员可显式启用。因此不称为默认绕过；本项目直接不提供模型可调用的“宣布全部通过”能力。

本地仓库 LICENSE 为 AGPL-3.0。本轮借鉴角色、数据流和约束思路，不复制 ARTEX/Norma 实现或整段提示词；[ROS 2 提示词草案](../../artex_ros2_agent_prompts.md)独立撰写，并保留来源说明。

## 2. 方案选择与开源复用

推荐 **Python LangGraph 编排 + 本项目的类型化工具适配**：复用 StateGraph、条件路由和 Send 的 worker 模式，角色不获得通用工具。LangGraph 是调度框架，不是安全隔离层；权限、身份、预算与最终判据由本项目实现。

已查阅官方 [workflow/agent 与 orchestrator-worker 文档](https://docs.langchain.com/oss/python/langgraph/workflows-agents)、[许可证](https://github.com/langchain-ai/langgraph/blob/main/LICENSE)及 [PyPI](https://pypi.org/project/langgraph/)。固定版本为 `1.2.16`、Python >=3.10、MIT。用户批准后已安装于独立 `output/agent-review-venv` 并运行第一阶段测试；不加入 `guardian_node` 实时依赖，关闭外部 tracing。首版WSL不支持unshare，选用MIT的pyseccomp0.1.2调用libseccomp拒绝网络及worker创建子进程，隔离范围以实现说明为准。

备选：

1. 直接运行 ARTEX/Norma Go 服务，再接 ROS 工具。可复用更多原调度，但引入 Go/PostgreSQL/跨进程服务与过宽默认工具，需要大量权限改造；不作为第一阶段。
2. 完全自行编写通用多 agent 框架。依赖少，但会重复调度、状态与工具调用设施；不选。只自行实现 ROS 证据契约、注册测试目录和确定性授权检查。

继续复用：`ros_graph_security.inspect_project`、`dashboard_recovery.inspect_recovery_trace`、`RecoveryFrame`、`SafetyOracle`、`SemanticCoverage`、`recovery_scenarios.Action/execute_scenario`，以及现有认证、JSON 输入限制与实验框架。现有 Jev 的 TypeSafe questions/answers 是分类协议，不能通过更换 prompt 冒充通用规划 provider。

## 3. 角色与权限

| 角色 | 输入与职责 | 可申请的工具 | 输出 |
| --- | --- | --- | --- |
| `goals` 目标与证据研判 agent | 读取服务器生成的证据摘要，区分事实、静态嫌疑和缺口，提出范围内目标 | `read_evidence`、`list_test_catalog` | 目标/证据引用/无法检查项 |
| `planner` 规划 agent | 按目标、已有结果、预算和覆盖选择后续测试；唯一测试意图提议者 | 只读证据/目录/历史摘要 | 有界 `TestIntent` 列表或停止理由 |
| `worker` 执行 agent，最多 3 个并发 | 每个会话仅处理一个已批准 intent，申请执行其固定测试 | `run_registered_test`，参数只能是已分配 intent ID | 工具产物 ID 与增量说明 |
| `reviewer` 独立复核 agent | 读取工具产物、程序复算结果与对照，提出反证和待补证项 | `read_artifact`、`request_replay` | 引用产物的解释与复核建议 |

证据建包、计划审定、进程管理、Oracle 计算、最终状态聚合和报告保存是**确定性程序节点**，不伪称 LLM agent。主界面承担 ARTEX mainagent 的人在环路职责；首版报告由模板聚合，不额外消耗 reporter 模型调用。

整体设计区分两种 provider，分阶段实现：首笔 `fixture` 用固定角色应答验收编排与拒绝路径；其后 `llm` 使用管理员配置且满足结构化输出契约的真实模型。fixture 不外发数据，报告必须写明“脚本角色应答，非真实模型研判”。真实模型接口、Key 获取与调用成本另行配置，不读取或迁移 ARTEX 的 Key；缺配置返回不可用。不得在真实 provider 失败后静默切换 fixture 并宣称完成多 agent 研判。

## 4. 两类图与证据身份

资产图保留现有文件、函数、ROS 节点、主题、发布/订阅和控制路径。探索图新增 goal → intent → execution artifact → verification 的记录，以服务器生成的 asset/evidence ID 连接资产图，不引入图数据库。

- 文件输入由服务器重新运行静态分析；浏览器或 agent 提交的 findings/可信标记不能直接成为事实。
- 轨迹输入由服务器按现有字段、大小和时钟检查重新检测；SHA 固定字节身份，不证明来源真实或物理安全。
- `EXTRACTED` 表示静态抽取，不代表代码可信；`INFERRED` 不得由模型提升为运行时确认。
- `review_context_digest` 绑定本次审查快照；它与实际 RecoveryFrame 的 graph/policy/ledger/epoch 不同，不能相互代替。
- 证据包绑定输入摘要、分析器/Oracle/测试目录/提示词版本、profile 和执行目标源码摘要。计划、执行和复核均引用相同包；任何输入或版本变化开始新 run。
- canonical JSON 使用 UTF-8、键排序、固定 separators、禁止 NaN/Infinity/重复键；文件按已校验的文件名排序，源码逐字节保留，不剥离注释或重排帧。
- 文件/轨迹文本是被分析数据，即使含有伪造 system 指令，也不能改变工具集合、角色或测试范围。

证据摘要保留有界的结构化记录和代码位置，默认不把源码全文、原始日志、路径、凭据送给真实 provider。证据正文被截断时必须标明缺口；不能把截断后的缺失当成完整排除依据。

## 5. 计划、工具调用与产物契约

`TestIntent` 的模型可填字段严格限于：`goal_id`、`test_id`、`evidence_refs`、`reason`。`reason` 最多 512 字；每条最多 8 个当前包引用。intent/run/context/plan ID 和执行预算由服务器添加，模型不能选择。未知字段、空引用、伪造或跨 run 引用、重复测试、非有限数值均拒绝。结构化输出失败最多允许一次修正，仍计入共享调用预算。

计划审定器核对 role、run、范围、目录适用性、配额和版本，生成计划摘要。**模型文本不能增加能力**。worker 的 `run_registered_test(intent_id)` 只能运行当前 role 会话已领取的 intent，不能换 test ID 或追加参数；工具 dispatcher 在调用当刻重新检查，而非仅检查发给模型的 schema。

每个执行产物绑定 context/plan/intent/test ID、目标类型、测试目录版本、实际目标源码摘要、开始/结束时间、退出状态、原始轨迹摘要及有界观测。模型不能提交 `passed`、违规数、来源认证、运行时指纹等结果字段作为程序事实。

最终报告保留：输入来源声明及认证状态、角色/provider 模式、工具真实运行情况、测试覆盖范围、程序计算结论、模型解释、未检查项、成本/时间、取消原因和所有产物绑定。保存的是结构化事件与可核对产物，不要求或披露模型的内部思维链。

## 6. 第一批注册测试与适用范围

首版只运行生产恢复核心的虚拟时间模型，固定 `variant="full"`，不接受客户端 gate_factory 或 mutation。最长 32 个 Action；每个 duration 0.01–1 秒。具体序列复用现有 seed 场景，冻结后写入测试目录。

| test ID | 固定场景 | 验证问题 |
| --- | --- | --- |
| `healthy_resume` | healthy(.5) | 完整前置成熟后能否恢复，作为正常对照 |
| `ttl_gap` | healthy(.25), gap(.51), wait(.5) | 许可过期后是否拒绝旧候选并重新探测 |
| `graph_change` | healthy(.25), graph_change(.05), wait(.6) | 图变化后是否拒绝旧绑定 |
| `policy_change` | healthy(.25), policy_change(.05), wait(.6) | 策略变化后是否拒绝旧绑定 |
| `epoch_change` | healthy(.25), epoch_change(.05), wait(.6) | epoch 变化后是否拒绝旧绑定 |
| `proof_replay` | healthy(.35), replay_proof(.05), healthy(.6) | 一次性许可是否拒绝再次使用 |

这些场景的测试对象始终是 `guardian_recovery_virtual_model`。上传项目可用于静态风险研判和解释为何某类恢复机制值得关注，**不表示该项目已被执行、拥有相同恢复机制或通过运行时测试**。不能将这里的零违规覆盖上传项目的静态发现，也不能证明完整活性（部分场景未达到 Oracle 3 秒健康窗口）。

注册目录必须分开定义触发前置与行为期望，不依赖通用 Oracle 在短轨迹上发现停滞。`healthy_resume` 的前置是确实提供足时长的健康观测与停车ACK，期望观察到候选、许可消费和允许运动；`ttl_gap` 前置为候选存在后确实越过其截止时间，期望拒绝旧许可并以新许可恢复；三种上下文变化前置为变化发生在候选存在期间，期望拒绝旧绑定并在新上下文成熟后恢复；`proof_replay` 前置为实际向授权入口提交先前已消费的同一 proof，期望为拒绝。不能只根据 Action 名称声称触发成功。

执行适配器需保留实际调用与结果的有界 witness events（含对应帧、proof 引用和实际授权结果），必要时为共享场景执行器增加只供内部使用的观测接口，保持旧的 trace 返回接口兼容。目录断言只能读取真实 trace/events，不改变控制算法和原 Oracle。`validity=VALID/NOT_EXERCISED/ERROR` 只表示触发前置是否成立；`assertion_result=PASS/FAIL/NOT_EVALUATED` 单独表达安全期望。错误接受旧proof应是VALID且FAIL，允许违规复现；不得因没有拒绝结果将其标未覆盖。正常对照未恢复必须FAIL并阻止整轮通过，但仍可为有效执行。原Oracle违规与目录行为断言分开记录，不修改原Oracle；两者的失败各自保留规则来源。

对上传原始恢复轨迹，复核是同一段提交数据的离线重算，目标为 `submitted_recovery_trace`，不将它伪装为在目标机器人上重新触发。首版不提供 Bash、任意 HTTP、MCP、文件路径读取、Python 源码执行、`run_sandbox(source)`、`simulation_control` 或 ROS publish 工具。没有对应注册测试时记录 `UNSUPPORTED_TEST`，由后续人工实现并审查新的适配器，不能现场生成代码执行。

## 7. 运行上限与隔离要求

默认 2 轮规划、全 run 最多 6 个唯一测试、最多 3 个并发 worker。正常对照 `healthy_resume` 由程序加入且计入 6 项上限，避免模型只选择异常测试。fixture 与 llm 使用相同工具权限与预算。

- 全 run 最多 16 次 provider 请求，含修正/worker/reviewer；任何 fallback/retry 必须预先占用同一预算，不接受 provider 内隐藏自动重试。
- 每个响应最多 2048 输出 token（provider 支持时）和 16 KiB 实际响应字节；单次输入摘要最多 24 KiB，总外发输入最多 128 KiB。token 上限不是金额上限，公开实际 usage 和价格未配置状态。
- 单次 provider 最长 8 秒，全 run 从证据建包起最多 30 秒，子进程测试单项最多 2 秒；实际 timeout 取剩余预算的较小值。所有时间使用单调时钟，不靠 ROS `/clock`。
- 每个 worker 会话最多 1 次运行请求；每个 intent 至多 1 次额外复放，计入最多 12 次场景执行总量。fixture 不占真实网络请求预算，但受同样角色步数上限，报告分别计数。
- 同时运行任务最多 2 个，每会话最多 1 个；满载明确拒绝，不排无限队列。产物单次输出不超过 2 MiB/2000 帧；持久化只保存到服务器分配目录，单 run 总量最多 32 MiB，按会话做访问隔离。

固定 argv 启动打包后的测试 worker，无 shell、不接受代码/路径参数；以输入 JSON 传递目录 ID，环境按白名单重建，不带 dashboard/provider 凭据。父进程并行读取有界输出，超时/取消/超量即终止并回收整个子进程组，不能使用仅让等待方超时的 future 充当取消。

子进程只执行审查过的场景，并设置内存/CPU/文件上限；首版 Linux/WSL 研究环境应验证无网络的执行隔离可用。隔离或资源限制不可建立时返回 `UNAVAILABLE`，不能静默运行任意宿主机代码。进程隔离也不等于承诺可安全执行敌对代码，此入口始终没有上传代码执行能力。

全任务主管还需独立于 LangGraph/模型线程计时。provider 适配必须支持可终止调用，或在受主管管理的独立进程中运行；硬截止后停止本地请求并回收进程，不能仅依靠 SDK timeout 或等待线程退出。已发送到外部服务的请求可能仍在远端计费，报告保留该不确定性，不能声称取消保证零费用。fixture 同样受最多 16 次角色调用上限约束，图节点另有有限步数上限，避免无需网络的空循环绕过预算。

取消后不再派发工具；迟到 provider/worker 结果不能改变终态。输入/版本不符返回 `STALE_CONTEXT`，不重用旧 run。重启中断的任务记录 `INCOMPLETE`，不自动重新执行。缓存如后续启用，必须绑定完整上下文、角色、目录、提示词与模型版本，且只缓存解释，不复用为新的运行测试证据。

## 8. 确定性复核与结论

worker 返回的轨迹由独立节点重新解析并运行原 `SafetyOracle`。需要复现的发现，再以相同固定测试与源码摘要在新 worker 进程执行一次。reviewer 可质疑，但不能改写原轨迹、Oracle、违规码或覆盖统计；多个模型意见一致也不形成执行授权。

复核单位是服务器生成的 `finding_id`，不能仅按 intent 聚合。静态 finding ID 绑定证据包、规则和代码位置；运行违规 ID 绑定原 artifact 摘要、违规码和原始 frame index，每项保留精确帧引用。首版固定虚拟场景的复放匹配要求相同 test/目录/目标源码/动作序列、两次执行均 VALID，并重新得到同一违规码和对应 frame index 的 Oracle 违规；验证的是每次原始帧自己的精确许可/上下文关系，不要求随机 proof ID 字节相同。缺少可比条件即 INCONCLUSIVE，不用自然语言相似度或仅按违规码合并。

若同一次执行出现 A/B 两项违规，复放只重现 A，分别记录 A=REPRODUCED、B=NOT_REPRODUCED（前提是可比有效复放），不得将整个 intent 标为全部复现。未来非确定性 DDS/物理轨迹需要独立的匹配协议，首版不沿用 frame index 规则。上传轨迹重算标 `verification_kind=TRACE_RECHECK`，静态审查标 `STATIC_REVIEW`，只有重新执行固定模型为 `REEXECUTION`；前两者不得标记新一轮触发已复现。正常无发现的测试无需虚构 finding，其结果由程序检测与目录见证表达。

报告状态分开表达：

- 执行状态：`COMPLETE / INCOMPLETE / CANCELLED / UNAVAILABLE / STALE_CONTEXT`。
- 程序检测：`VIOLATIONS / NO_VIOLATIONS / NOT_RUN`，只覆盖明确标识的目标与数据。
- 发现复核：`REPRODUCED / NOT_REPRODUCED / INCONCLUSIVE`。首版不输出“已修复”，因为尚未建立修复前后可比目标与正常对照流程。
- 静态嫌疑始终附静态来源；没有运行证据时为待验证，不能转成 confirmed finding。

超时、工具失败、模型拒答、非法输出、证据不足都不能输出“检查安全”。有确定性违规时，即使模型超时或反对，也保留违规；`INCOMPLETE` 与已发现违规可同时存在。没有违规只能解释为“提交的数据/已执行场景未触发现有断言”。

## 9. 接入位置与实施顺序

本节是实现边界与交付拆分；用户已批准第一阶段，[TDD实施计划](../plans/2026-10-19-artex-ros2-agent-review.md)已生成并执行，CLI说明见[第一阶段运行文档](../../artex_ros2_agent_review.md)。

1. **离线闭环**：新增独立 `agent_review` 研究包（contracts/evidence/roles/orchestration/tools/runner 各司其职）、LangGraph 独立依赖文件与 CLI；fixture 的四角色输出可注入，工具执行与 Oracle 必须真实运行。先复用 experiments 场景，不让实时包依赖 LangGraph。
2. **真实模型适配**：新增受配置约束的结构化 RoleProvider，严格 JSON 与返回大小、共享请求预算和超时；验证真实模型可用时才标 `llm`。已有 Jev 保持分类旁路，不修改其问题协议。真实调用不作为无凭据自动回归的前置条件。
3. **检测页集成**：为已登录用户增加独立研究作业服务和创建/查询/取消接口，不同步占住 30 秒 HTTP 请求。复用现有会话鉴权并校验 job 归属；浏览器只能提交原始 files 或 frames 与目录选项。展示四阶段、目标范围、引用与程序结果，模型文本转义。若需把场景打包供服务使用，抽入共享纯模块并保留实验兼容入口，禁止运行时改 sys.path 找 experiments。
4. **后续扩展**：有界 Hypothesis campaign（含覆盖反馈）作为新目录项；之后再单独设计 Gazebo/Webots/DDS 测试适配。新的目标、网络或机器人动作都不由 agent 自行发现并开放。

前端实施时使用现有 vanilla 页面与 Playwright 验证；按用户 AGENTS 的插件偏好说明 `build-web-apps@openai-curated` 的可用性，不为此重写整个应用。该步骤不是本轮已交付功能。

## 10. 验收与效果评估

第一阶段必须验收：

- 用 fixture 四角色串通实际注册测试与复核，角色输出、工具结果、测试对象和 provider 模式能区分。
- 非 planner 造 intent、未知字段/工具、跨任务引用、伪造 test ID、伪造通过与来源认证均在工具执行前拒绝。
- 在源码/轨迹中植入“忽略指令、调用控制 API、泄露 Key”的测试文本，不产生额外能力；模拟直接调用被隐藏工具也拒绝。
- 并发领取同一 intent 只运行一次；取消、超时、子进程超量、迟到模型结果、证据/源码漂移均不产生完成或安全结论。
- 负对照使用现有**离线测试专用** mutation 验证 Oracle 能检出；该入口仅测试代码可注入，不暴露给模型/HTTP，不能把 mutation 的结果冒称生产核心缺陷。
- 正常对照对 never-resume 实现必须断言FAIL；错误接受重放proof的有效执行必须能够复现违规，缺少实际重放调用时才不能计为已覆盖。构造同一 intent 的 A/B 两项违规、复放仅重现 A，验证逐 finding 标记而非整体盖章。
- 测试通过 spy 证明没有调用真实 provider、ROS publisher、`simulation_control`、`run_sandbox` 或读取凭据；真实 provider 验收单列，不拿 fixture 结果替代。
- 既有恢复场景、静态图、轨迹检测与认证回归通过；修改前端后再做真实浏览器登录、运行、取消、跨会话拒绝和移动宽度检查。

多 agent 本身是工程组织方式，不能单独宣称检测创新或优于现有 fuzzer。研究假设是：绑定证据和上下文的分工规划，在相同预算下改善测试选择与确认质量。后续冻结独立缺陷/来源后比较规则选测、单 agent 与多 agent；同时报告等墙钟和等模型调用/成本两类预算、检出率、误报率、引用正确率、复现率、覆盖、超时及未完成比例。仅 6 个固定测试或一次演示不支持效果优势结论。

## 11. 本轮核验记录

本轮两个只读审查 agent 分别核对本项目接口与本地 ARTEX 源码，第三个独立审查 agent 检查设计一致性；发现的正常对照触发断言和逐 finding 复核缺口已纳入本设计。可复用底座定向回归：2026-10-19，加载 `/opt/ros/humble/setup.bash` 与本项目 `install/humble/setup.bash` 后，执行恢复 fuzzing、dashboard recovery、ROS 静态图三个测试文件，**28 passed / 15.81s**。初次命令遗漏项目消息 overlay，第二次误用了旧 `ros2_ws/install`，均在收集期失败；改用现有正确 overlay 后通过，未为此修改代码。

以上28项是设计阶段已有底座的回归。随后用户确认第一阶段实现；新增独立研究包、固定测试目录、实际调用见证、隔离worker、LangGraph编排和CLI，运行文档记录实际能力。新功能整组74项测试通过；包含目录真实执行、隔离/凭据/超时/取消、非法计划、伪造复核和提交轨迹违规不被模型结果覆盖。独立代码审查指出的默认环境可选依赖gate及轨迹违规遗漏已修复并复核。真实模型和前端入口尚未实现，未发布ROS消息或修改恢复授权算法。
