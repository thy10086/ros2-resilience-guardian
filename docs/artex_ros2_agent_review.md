# ARTEX 风格的 ROS 2 多角色研判与测试闭环

2026-10-27更新：提示词v3，证据按风险和类型选择，记录实际可见ID；reviewer每批最多16项，使用短索引回复，程序校验并回填完整finding/intent/artifact绑定。规范回复上限2048字节，批次仍计入16次角色调用，预算不足保留已完成复核和待复核ID。128项边界真实离线执行已完成，未支持语言的审查项继续保留。安装定位支持管理员GUARDIAN_RESEARCH_ROOT或受信源码标记查找；详情见[分梯度改动](priority_hardening_2026-10-27.md)。

`goals → planner → 最多3个worker → reviewer` 由 LangGraph 编排，现支持明确分开的 **fixture 脚本模式**和 **OpenAI 兼容接口模式**。模型可以生成目标与选择测试，worker 仅确认其分配意图，真实执行与 SafetyOracle 重算由程序完成。检测页入口位于“安全测试分析 → 四角色协作测试分析”。本地 HTTP 验收证明协议与调度，不代表已经完成真实模型的质量评估。

参考是用户本地 `D:/ARTEX` 的 `a9d11cb852eadad00669e4f6a05ee59cbbd14860`，不是根据网页演示模仿 UI。角色分工、探索血缘、单意图执行和独立复核思路来自源码阅读；ROS 契约、权限检查与提示词独立编写。参考清单见 [来源记录](artex_ros2_reference_audit.json)，[设计](superpowers/specs/2026-10-19-artex-ros2-agent-review-design.md)与[角色提示词](artex_ros2_agent_prompts.md)可单独审阅。

## 能检查什么

| 输入/执行对象 | 本阶段实际工作 | 证据范围 |
| --- | --- | --- |
| 固定自有模型样例 | 正常恢复、TTL空窗、图/策略/epoch变化、proof重放六个注册场景 | 当前Guardian虚拟恢复模型 |
| `files` 文件列表 | 复用现有ROS静态分析，提取风险线索，再执行上述模型场景 | 上传源码只静态分析，不执行；模型结果不认证上传程序 |
| `frames` 恢复轨迹 | 复用原Oracle重算，再执行上述模型场景 | 原提交轨迹单独标 `TRACE_RECHECK`，不冒充重新触发或来源认证 |

每项测试分开表达 `validity`（前置条件/触发是否成立）和 `assertion_result`（预期行为是否满足）。例如，实际提交已消费proof后被错误接受，属于有效测试的FAIL；不能被标成“未测试”。正常对照必须观察许可及运动，短轨迹上的Oracle零违规不会替代该断言。

上传轨迹违规与模型测试结果分别报告：`submitted_trace`、`model_detection` 和 `targets` 明确对象，`detection` 保留任何已检出的违规。逐 `finding_id` 复核；原数据重算没有目标重新执行证据，复现标签保持 `INCONCLUSIVE`，原Oracle违规继续保留。

上传源码有独立 `submitted_source_static` 目标、`static_detection` 和 `STATIC_REVIEW` 发现。存在静态风险、未支持文件或抽取缺口时，总结论为 `STATIC_REVIEW_REQUIRED`，模型测试通过不会覆盖；静态嫌疑不冒充运行时已确认违规。导入轨迹要求完整帧字段，缺少 `observed_speed` 或许可字段直接拒绝，不能默认为零速安全。

## 安装与运行

在 Linux/WSL Ubuntu 22.04 的项目根目录运行。依赖放进独立研究环境，不安装到 ROS 实时节点环境：

```bash
python3 -m venv --system-site-packages output/agent-review-venv
output/agent-review-venv/bin/python -m pip install -r experiments/requirements-agent-review.txt

# 输出文件必须不存在。示例报告默认只保存在本机。
output/agent-review-venv/bin/python experiments/run_agent_review.py \
  --sample --output output/agent-review-example.json
```

导入 JSON 的顶层只能是三者之一：`{"sample":"guardian_recovery_virtual_model"}`、`{"files":[{"filename":"controller.py","source":"..."}]}` 或 `{"frames":[...]}`。文件列表复用128文件、单文件64KiB、合计512KiB上限；轨迹复用2000帧、2MiB上限。拒绝重复JSON键、NaN、额外执行字段和伪造引用。

```bash
output/agent-review-venv/bin/python experiments/run_agent_review.py \
  --input output/review-input.json --output output/review-result.json
```

退出码：0表示已完成且本次范围内无违规及待审静态风险；1表示发现违规、静态风险、未完成或不可用，报告仍保存；2表示非法输入、已有输出或读写失败。fixture 不需要 Key 或 ROS 节点；CLI 不读取 ARTEX 配置或已有 Jev 凭据。

## 配置真实模型

进入“恢复验证 → 多智能体研判”（`#research/agents`），填写 API URL、API Key，点击“读取模型列表”后确认模型，也可手动填写模型名；选择自有模型或上传仅含 `files` / `frames` 的 JSON，再点“连接并运行分析”。也可从单文件检查、安全图或轨迹检测点击“带入多智能体研判”，复用当前输入，页面会显示来源；带入不会发起模型调用，也不会覆盖运行中的任务。切换输入会清除旧结果与下载入口。支持查询、取消和下载报告。Key 只用于当前页面操作，不持久化；退出登录清空表单并取消该会话任务。若接口不提供 `/models`，直接手动填模型名。

URL 可为 `https://服务地址/v1` 或完整 `/chat/completions` 地址；本机模型允许显式 loopback HTTP。地址不能带账号、查询参数或片段，不跟随重定向，也不使用环境代理。管理员需明确选择可信的模型服务；模型不能修改这个地址。协议须支持 Chat Completions 的 `response_format: json_object`、`max_completion_tokens` 及标准 `choices` 响应；不支持时明确失败，不自动换接口或模型。

CLI 对应调用（Key 放入本次 shell 的环境变量，不放命令行参数）：

```bash
read -rs -p 'API Key: ' GUARDIAN_AGENT_API_KEY; export GUARDIAN_AGENT_API_KEY
output/agent-review-venv/bin/python experiments/run_agent_review.py \
  --provider llm --base-url https://your-provider.example/v1 --model YOUR_MODEL \
  --sample --output output/live-review.json
unset GUARDIAN_AGENT_API_KEY
```

这会向所选服务发送角色提示词、结构化证据与执行摘要；不发送上传源码全文、原始轨迹或文件路径。证据截断有显式标记。Key 仅在父层及其固定 HTTP 传输进程中使用，通过 stdin 传入，不进入参数、测试子进程环境、报告或模型提示词。没有真实模型配置时不产生外部模型调用；失败不退回 fixture 冒充研判成功。

页面下载使用同会话的 `GET /api/agents/report?id=...`，由服务器序列化，浏览器按原响应文本保存。不能对已解析报告再 `JSON.stringify`：这会将 `1.0` 改为 `1`，破坏现有规范 JSON 摘要的可复算性。未登录、跨会话和未完成任务分别返回 401、404、409。退出登录与创建任务入表在同一服务锁内协调，已经通过路由初次认证的旧请求也不能在登出后启动。

## 恢复侧兼容性

本轮 command/status 的既有 `timestamp` 强制纳入 HMAC。Guardian publisher、AMR adapter 和独立 observer 已同步更新；部署时应一起更新和重启这些节点，旧签名不会兼容放行。执行端 command/status 双租期默认0.5秒，并扣除到达前源年龄；steady timer 在 ROS 时钟停顿时仍检查。冻结链恢复必须取得严格晚于已观察 ROS 高水位的新采集，旧队列不能重锚。单源证据也保留采集截止并在使用时复核，不因到达而重授完整 TTL。

这些检查依赖执行进程及调度仍在运行；不是硬件 watchdog 或持久化的跨重启防重放保证。微小漂移、暂停后正常恢复及小步恢复旧队列都有回归，未对真实机器人硬件作验收。

## 约束由程序执行

模型/fixture仅能提出固定目录ID与当前证据引用；worker仅能执行已分配意图，没有Bash、任意HTTP、源码执行、路径导入或ROS控制工具。任务内原子领取与一次完成防止重复执行。

全run最多6个唯一测试、12次含复放执行、16次角色调用。fixture 通常选满六项、9次角色调用；接口模式按模型计划选测，平台始终补正常对照。fixture 总截止30秒；接口模式最多180秒，单次HTTP总截止15秒、单项测试2秒，最多3个并发worker。有界读取并终止/回收进程，取消后迟到结果不能改为完成；本地取消不能撤回服务商已处理的请求或保证不计费。源文件前后摘要变化返回 `STALE_CONTEXT`。

复用开源 [LangGraph](https://docs.langchain.com/oss/python/langgraph/workflows-agents) 与 [pyseccomp](https://pypi.org/project/pyseccomp/)。当前WSL不允许unshare，固定测试进程通过libseccomp拒绝网络、创建子进程、exec与离开进程组，并实际探测socket被拒绝；另有干净环境、临时cwd与CPU/内存/文件限制。缺少隔离依赖时失败关闭。它只运行本仓库审定代码，不是可执行敌对上传代码的完整容器。

报告保存上下文/计划/源码摘要、原始模型轨迹、真实见证、Oracle结果和逐发现引用。reviewer 接收有界的计划、产物、有效性、触发见证及复放摘要，复核标签仍由程序约束。SHA只固定本地字节身份，不证明所有依赖、运行时导入链或输入来源可信；冻结范围以 `source_manifest` 为准。报告保留服务商返回的token计数与已报告调用数，不推算价格。单任务报告上限4MiB，历史最多8条、合计32MiB；超限明确失败，不生成通过结果。

## 测试与后续

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
# 补充既有fuzzing依赖，避免完整回归跳过Hypothesis测试。
output/agent-review-venv/bin/python -m pip install -r experiments/requirements-fuzzing.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 output/agent-review-venv/bin/python -m pytest -q tests
```

当前系统pytest与新研究依赖携带的anyio插件版本不兼容，研究环境运行回归时禁用插件自动加载。缺少研究依赖时，原环境会跳过相应真实agent执行用例，纯契约和原项目测试继续运行；不以这些跳过代替完整研究环境验收。

后续应接用户指定的真实服务进行有效性评估，并以规则选测、单agent和多agent作等预算比较。本地协议fixture、六场景演示及框架接通均不证明多agent提升检出率；worker当前没有自由探索或自主编写测试能力。

第一阶段历史验收（本次修改之前）：新功能74项回归，完整研究环境全量 **770 passed / 151.31s**。历史结果不能代替当前版本重新验收。

本地产物在 `experiments/results/agent_review_validation/`：`sample_review.json`六场景完成/零违规；`self_ros_review.json`重读已有自有DDS271帧并完成六场景/零违规；`stalled_review.json`对合成停滞轨迹保留违规且CLI退出1。它们均为fixture角色、0外部模型调用。输入来源、原始审计SHA与依赖版本单独留存，未重新启动DDS或机器人。

2026-10-20最终验收：Humble构建、compileall、JS语法和空白检查通过，完整研究环境 **874 passed /311.08s，零跳过**。本机协议fixture通过实际浏览器完成运行、静态风险保留、取消、错误、下载与退出；四份 `output/playwright/*1020-v2.json` 的四次真实注册执行、Oracle/见证和摘要已独立复算一致。最终日志及JUnit见 `output/verification/20261020-report-final-pytest.*`，收据为 `output/verification/live-verification-20261020.json`。这些HTTP调用只到loopback协议fixture，未完成外部真实模型的效果评估。非v2下载是数值序列化修复前的复现文件，不能用于通过验收的声明。
