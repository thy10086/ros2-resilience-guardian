# ROS 2 Resilience Guardian：证据与上下文绑定安全恢复

2026-10-22 源码快照：见[版本说明、获取与构建步骤](docs/releases/2026-10-22-snapshot.md)。固定版本可通过 `snapshot-2026-10-22` 标签获取；语料库大型二进制文件使用 Git LFS。

2026-10-27 本地分梯度改动：观测年龄包络、静态控制路径、分批研判及安装环境修复见[实施与运行记录](docs/priority_hardening_2026-10-27.md)。构建后可运行 `bash deploy/run_guardian.sh demo --distro humble` 启动本机软件演示；检测页新增逐属性证据充分性说明。

面向 ROS 2 机器人的证据与上下文绑定安全恢复机制。项目研究机器人停车后，如何依据新鲜可信观测、执行反馈、相关控制图、策略版本和证据账本，授权第一条恢复命令，并阻止过期、重放或上下文错配的许可生效。RobResilience 兼容风险逻辑保留为基础，AMR 是首个软件闭环验证场景。

## 当前研究主线与最小闭环

`可信事件/健康观测 → 停车与匹配 ACK → 证据账本/控制图/策略绑定 → 稳定探测 → 短期一次性许可 → 第一条恢复命令 → /cmd_vel 运动反馈`

默认 `configs/guardian.yaml` 已为 AMR 启用 `evidence_bound_recovery`。告警 TTL 不再自动解除攻击，reset 只清理场景；恢复必须重新取得晚于告警的新鲜健康证据。普通节点默认关闭此研究模式，以保留原有调用兼容性；接入其他设备时需要单独实现可信观测适配器。

复现真实 ROS 2 软件消息闭环（需要先按下方构建并配置反馈密钥；实验脚本在隔离 localhost 域使用临时密钥）：

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
python3 experiments/run_bound_recovery_experiments.py
```

输出为 `experiments/results/bound_recovery_validation.json`，包含五个验收场景、观测时延、恢复状态转换和账本导出。开源工具复用、机制边界和运行说明见 [安全恢复闭环](docs/evidence_bound_recovery.md)。本轮验证的是 AMR 工程仿真与真实 DDS 消息，不代表实机制动、完整 IDS 或生产安全认证。

第二轮增加独立观测节点，从标准里程计和激光扫描交叉核验执行器报告。复用 ROS 2 官方 `launch_testing` 在三个独立进程中验证证据缺失、过期、重放、矛盾、近障碍与端点/进程重启；独立模式显式启用，缺少观测时保持停车。

```bash
launch_test experiments/independent_observation_launch_test.py
```

报告为 `experiments/results/independent_observation_validation.json`，运行与信任边界见 [多进程独立观测](docs/independent_observation.md)。独立计算尚不代表独立物理传感器。

第三轮借鉴 BTreeFuzz 的任务状态反馈，复用 Hypothesis 实现离线恢复语义测试、许可时序变异、安全断言、corpus 保存与重放；同一断言检查真实 ROS 审计轨迹。安装与命令见 [恢复反馈测试](docs/recovery_feedback_fuzzing.md)，论文依据见 [BTreeFuzz 分析](docs/btreefuzz_recovery_testing.md)。当前小预算实验尚未证明反馈引导优于无引导。

第四轮完成四类受控缺陷资格验证、十种子每组1000次对照和恢复机制消融。30,000次完整机制执行未触发安全断言，121个保存反例重放一致；现有反馈目标只在4/10种子上获得更多转移覆盖，尚未证明搜索收益。报告、诊断边界和复现见 [重复实验与消融](docs/recovery_evaluation.md)。

第五轮新增许可有效期、精确消费绑定和修复转移目标，保持相同输入策略作30,000次三组对照。过期缺陷检出为无引导9/10、旧反馈4/10、许可边界反馈8/10；新目标比旧目标改善，但未优于无引导且总覆盖下降。119个反例和30组corpus重放一致，默认模式保留。详见 [许可边界反馈](docs/permit_boundary_feedback.md)。

第六轮冻结目标族消融并使用新种子10..19，完成50,000次五组对照。TTL缺陷检出为无引导5/10、旧反馈4/10、完整边界7/10、TTL族6/10、上下文/修复族4/10；这批TTL指标改善，但总覆盖下降且与第五轮比较方向不同，未确立稳定优势。实验发现并修正离线活性断言把采样空窗计为连续健康的误报，原批次和源码快照保留；恢复决策不变。修正后184个反例及50组corpus重放一致，全量597项测试通过。见 [目标消融与新种子验证](docs/feedback_target_ablation.md)。

第七轮完成冻结 Oracle 的新受控缺陷验证：20个新种子、三组各5秒，共31,749次生成，完整机制0断言违规；132反例/60组corpus重放一致。停车ACK与下一epoch缺陷各组均20/20检出，恢复停滞为无引导6/20、旧反馈1/20、边界反馈2/20，尚未证明引导效率优势。入口支持等壁钟预算、超时发现排除、源码快照与拒绝覆盖；最终630项测试通过。协议、实际结果和复现见 [新缺陷与时间预算验证](docs/recovery_holdout_validation.md)。它仍是自有模型的受控缺陷评估，不是外部盲测或真实漏洞发现。

第八轮新增只从完整健康轨迹提取的持续健康窗口与恢复推进目标。seeds40..59四模式等壁钟对照共80组；`never_resume`检出为unguided 5/20、boundary 3/20、liveness 16/20、boundary_liveness 7/20。纯liveness在本批已知缺陷的新种子验证中提升了恢复停滞检出，许可边界组合则明显退化；不改变默认，也不声称未见缺陷泛化。完整机制0违规，193反例和80语料重放一致，最终回归见第八轮[协议、结果与限制](docs/recovery_liveness_feedback.md)。

第九轮先冻结第八轮目标/driver/控制模型，再由未读取反馈实现的独立审查选定包络拒绝和非零停车上限两族。新种子60..79、40组等时间对照中，unguided/liveness对两族均20/20检出，82反例/40语料重放一致；liveness没有新的检出率优势，转移覆盖与吞吐更低。同轮保留真实三进程DDS审计：19场景通过、271帧零违规，可用有界JSONL CLI及预期SHA重读，来源明确为自有软件AMR。全量696项测试通过；结果、来源核验边界和复现见 [冻结目标的新缺陷与DDS审计](docs/recovery_transfer_validation.md)。

参考本地ARTEX源码实现四角色编排：goals研判、planner规划、worker注册测试、reviewer独立复核。支持显式脚本模式和OpenAI兼容模型接口；“安全测试分析”页面填写URL、API Key与模型后可运行、取消和下载。模型在六项注册场景内选测，程序执行并重算Oracle，源码静态风险、提交轨迹违规与自有模型结果分别保留。复用LangGraph/pyseccomp，运行与适用边界见 [多角色闭环说明](docs/artex_ros2_agent_review.md)；本地协议验收不证明真实模型检出收益。

完整的系统交接、操作记录和后续提交规范见 [HANDOFF.md](HANDOFF.md)。

前端“安全测试分析”已同步恢复轨迹检测和第六轮五组对照，首页“防护实验室”提供“恢复轨迹检测”入口。支持JSON/JSONL审计轨迹与六个内置样例，直接复用安全断言，展示违规帧和绑定证据；历史实验结果与当前检测分别展示。使用与快照更新见 [前端检测页](docs/recovery_detection_page.md)。

## 现在能运行什么

- 纯 Python 核心引擎：不依赖 ROS 图形界面，可测试攻击验证、风险计算、3b 多波攻击重规划和安全状态机。
- 跨层安全核心：对 ROS 2 数据路径做图风险传播、来源/时序策略检查、多源证据融合、风险自适应速度包络和恢复门控。
- ROS 2 Humble（Ubuntu 22.04）和 Jazzy（Ubuntu 24.04）包：`guardian_interfaces`
  消息包和 `guardian_core` 节点包。
- 本地 Web 安全驾驶舱：只读映射风险、攻击组件、缓解方案和安全状态。
- 笔记本 ROS 2 闭环工程仿真：`amr_simulator` 发布 `/cmd_vel`、里程计、抓取器和攻击事件，并消费 Guardian 的安全反馈。
- 驾驶舱内置 Jev 连接测试：通过本地后端代理验证 TypeSafe API，并显示有界的语义判断结果。
- `guardian_node` 订阅 `guardian/attack_events` 和执行器确认 `guardian/mitigation_ack`，
  输出 `guardian/risk_state`、`guardian/mitigation_command` 和 `guardian/safety_status`。
- `experiments/run_innovation_experiments.py` 现在包含 6 组确定性实验，新增跨层融合和 Jev 语义顾问的离线验收。
- 离线实验：`python3 experiments/run_guardian_scenario.py --scenario 3b`。
- 可接入现有 Webots PR2：把攻击事件送入 Guardian，再由 `safety_supervisor` 控制速度、隔离或停车。

## 设计原则

1. 攻击事件必须经过来源、时间戳、序列号和重放检查。
2. `active_attacks`、IDS 已确认集合和当前缓解集合分开维护。
3. 新攻击出现时取消旧方案并重新规划。
4. 任务完成、恢复失败、超时和安全停车使用不同的结果状态。
5. 核心安全判断与任务控制器解耦。

## WSL2 + ROS 2 Humble/Jazzy

推荐使用部署辅助脚本，它会按发行版隔离 `build/<distro>`、`install/<distro>`
和 `log/<distro>`，并自动加载 `configs/guardian.yaml`：

```bash
cd /mnt/c/Users/thy/Documents/Codex/ros2-resilience-guardian
bash deploy/run_guardian.sh build --distro humble   # Ubuntu 22.04
# bash deploy/run_guardian.sh build --distro jazzy  # Ubuntu 24.04
```

运行核心离线实验：

```bash
bash deploy/run_guardian.sh test --distro humble
python3 experiments/run_guardian_scenario.py --scenario 3b
```

运行测试：

```bash
bash deploy/run_guardian.sh test --distro humble
```

启动 ROS 2 守护节点：

```bash
bash deploy/run_guardian.sh core --distro humble
```

启动安全驾驶舱（需要先启动 `guardian_node`）：

```bash
bash deploy/run_guardian.sh dashboard --distro humble
# 浏览器打开 http://127.0.0.1:8080
```

也可以一次启动守护节点和前端桥接：

```bash
bash deploy/run_guardian.sh all --distro humble
```

本机默认配置将 dashboard 运行在 `127.0.0.1:8080`；如需避开端口占用，
先加载 `/opt/ros/humble/setup.bash` 和 `install/humble/setup.bash`，再运行
`ros2 run guardian_core guardian_dashboard --ros-args -p port:=8088`。
部署辅助脚本不透传额外 ROS 参数。Guardian 默认从 `configs/guardian.yaml`
读取参数，启动时可以通过 ROS 参数覆盖非敏感配置；运行时仅 `task_phase`
可修改，其余 Guardian 配置需要重启后生效。事件签名密钥仅从
`GUARDIAN_EVENT_SECRET` 环境变量读取，不再声明为 ROS 参数。
执行命令、状态和 ACK 默认要求 `GUARDIAN_FEEDBACK_SECRET`，该密钥也只从环境变量
读取；未配置时 Guardian 保守进入 `SAFE_STOP`。可参考
`deploy/guardian.env.example`，不要把真实密钥写入仓库。
`security_profile_json` 是 ROS 2 通用安全 profile 入口，定义 `profile_id`、
执行适配器 `adapter_id`、可信事件源以及资源的 `tau`、`epsilon` 和是否可隔离；
默认值是 AMR profile，接入机械臂、传感器、飞控或工业控制器时只需替换 profile
和执行适配器，不需要复制 Guardian 决策代码。
多攻击策略合并、延迟执行和配置错误停车规则见 [运行安全约束](docs/deployment.md#runtime-safety-contract)。
首次打开页面需要登录。生产环境必须设置 `GUARDIAN_DASHBOARD_USER` 和
`GUARDIAN_DASHBOARD_PASSWORD`；`admin/admin` 仅能通过显式
`GUARDIAN_DASHBOARD_ALLOW_DEFAULT_CREDENTIALS=1` 开启，不应用于生产。登录失败
会限速，Dashboard 默认只允许绑定 `127.0.0.1`。驾驶舱通过 `GET /api/state` 提供当前状态，订阅 `/guardian/risk_state`、
`/guardian/mitigation_command`、`/guardian/mitigation_ack` 和 `/guardian/safety_status`。默认只监听
`127.0.0.1`，不会把控制接口暴露到局域网；后续接入 Webots 时应继续由
`safety_status` 输出边界驱动实际控制器。

### ROS 2 闭环工程仿真

`guardian.launch.py` 会同时启动 `guardian_node`、`guardian_dashboard` 和
`amr_simulator`。仿真节点是一个确定性的 AMR 数字孪生，模拟差速轮沿
`A-12 → P-07` 搬运托盘、抓取力和三类受控故障；它不连接真实电机，也不声称是
Webots 物理引擎。也可以单独运行：

```bash
ros2 run guardian_core guardian_node
ros2 run guardian_core amr_simulator
ros2 run guardian_core guardian_dashboard --ros-args -p port:=8088
```

登录后进入“工程仿真”页面，按以下顺序观察闭环：

1. 点击“启动托盘任务”，确认任务阶段从 `IDLE` 进入 `DOCK_TO_PALLET`，请求速度约
   `0.20 m/s`，`/cmd_vel` 的实际速度跟随安全上限。
2. 点击“注入超速指令”。仿真节点会请求 `0.62 m/s` 并发布带认证的
   `amr_simulator` 来源 `UNSAFE_COMMAND`；默认恢复闭环在登记后保持
   `SAFE_STOP`，仿真的实际速度降为 `0`，而请求速度仍显示 `0.62 m/s`。
3. 点击“注入序列重放”，两条事件共用 `sequence=7001`，时间线会显示第一条接受、
   第二条 `REPLAY` 拒绝；点击“注入抓取器故障”会把抓取力置为 `0 N`，用于观察
   `/amr_07/gripper_state` 与右臂风险的关联。
4. 点击“重置场景”清除仿真任务和攻击模式，确认任务回到 `IDLE`、位置清零；Guardian
   取得新的匹配停车 ACK 与晚于告警的认证健康观测后，重新经过 `RECOVERING` 和
   一次性恢复许可。再启动任务即可观察恢复后的运动。告警过期本身不会放行。页面
   轮询的 `/api/state` 同时显示任务阶段、位置、请求/实际速度、速度上限、托盘状态、
   攻击模式和缓解动作。

仿真使用的 ROS 2 话题为：

| 方向 | 话题 | 作用 |
| --- | --- | --- |
| 控制台 → 仿真 | `/amr_07/sim_control` (`std_msgs/String`) | `start`、`stop`、`reset`、三类攻击控制 |
| 仿真 → Guardian | `guardian/attack_events` (`AttackEvent`) | 速度异常、重放和抓取器语义事件 |
| Guardian → 仿真 | `guardian/safety_status` / `guardian/mitigation_command` | 速度上限、任务许可和隔离动作 |
| 仿真 → Guardian | `guardian/recovery_telemetry` (`RecoveryTelemetry`) | 认证健康观测、观测序列、当前命令身份和恢复探测 |
| 仿真 → Guardian | `guardian/mitigation_ack` (`MitigationAck`) | 适配器身份、epoch、传输号、反馈序列和执行状态确认 |
| 仿真 → 控制器 | `/cmd_vel` (`geometry_msgs/Twist`) | 安全限幅后的实际速度 |
| 仿真 → 驾驶舱 | `guardian/sim_state` (`std_msgs/String`) | 有界数字孪生遥测 |

Jev 不在这条实时控制链路中。它只对经过 Guardian 确定性校验的摘要做语义分类和
人工复核建议；即使 Jev Key 缺失或 provider 超时，`CONTAINING`、限速和停车仍由
本地 Guardian 状态机完成。

### ROS 2 通用安全 profile

Guardian 的实时输入是设备无关的 `AttackEvent`：`component` 可以表示关节控制器、
传感器、导航器、通信桥、末端执行器、飞控模块或其他 ROS 2 资源。示例 profile：

```json
{
  "profile_id": "manipulator-runtime",
  "adapter_id": "ros2-control-adapter",
  "trusted_sources": ["controller_monitor"],
  "resources": {
    "joint_1_controller": {"tau": 2, "epsilon": 0, "mitigatable": true},
    "wrench_sensor": {"tau": 0, "epsilon": 1, "mitigatable": false}
  }
}
```

`command_epoch` 表示缓解动作语义变化，`transmission_id` 表示每次发送，
`feedback_sequence` 表示执行适配器确认的新鲜度。Guardian 只接受身份、epoch、
传输号、计划、动作、组件和序列均匹配的确认；watchdog 使用单调时钟，不依赖
`/clock`。SROS2/DDS 权限、硬件急停和独立 watchdog 仍是生产部署必需项，仿真
适配器 ACK 只代表软件状态。

### 代码沙箱仿真与运行证据

登录后进入“代码沙箱仿真”。这里与“工业代码安全检查”不同：安全检查只读
AST/规则，沙箱会在固定场景中真正运行一个受限的 Python 控制器，或解析一个
SDF/URDF 模型并使用内置控制器，生成轨迹和风险事件。

Python 文件必须定义：

```python
def control(state):
    return {"linear_x": 0.2, "angular_z": 0.0}
```

`state` 只包含时间、位姿、障碍物净距、速度上限和安全许可。上传的 Python 不得
导入 ROS 2、网络、文件、进程或动态执行接口。XML 只支持根节点为 `sdf` 或
`robot` 的 SDF/URDF，禁止 `DOCTYPE`、外部 URI、`plugin` 和 `include`。

可直接上传仓库中的三个实验文件：

- `experiments/sandbox_safe_controller.py`
- `experiments/sandbox_unsafe_controller.py`
- `experiments/sandbox_warehouse_obstacle.sdf`

点击“运行沙箱仿真”后，页面会显示源码 SHA-256、隔离提供方、是否真正执行源码、
固定步长引擎、请求速度与实际施加速度、超速周期、碰撞周期、最小障碍净距、
运动轨迹和事件证据。若已保存 Jev Key，后端只把这些服务器生成的指标/事件摘要
发给 Jev，不发送源码、完整轨迹或本地路径。Jev 是旁路解释，不会改变本地
“必须阻断/需要整改/当前场景通过”的确定性结论。

本机当前优先选择 Docker；没有可用 Docker 镜像时使用 WSL
`unshare-userns` 的用户、挂载、PID 和网络命名空间，并关闭网络。两者都不可用时
直接失败关闭，不会在 Dashboard 进程中执行上传源码。当前引擎
`guardian-kinematic-v1` 是固定步长二维工程筛查，不等同于 Gazebo 物理认证；
SDF 另外会在本机存在 `gz` 时执行 `gz sdf --check`，但不加载 XML 插件。
WSL `unshare` 不是完整 VM 或 rootfs 隔离，当前版本适合本地工程验证，不用于
恶意多租户代码执行；部署到外部用户环境时应配置只读容器镜像或 VM 级隔离。

打开页面后，在“Jev 连接测试”面板中输入 TypeSafe API Key 和一段简短的
测试状态，点击“测试连接”即可执行一次旁路请求。浏览器只把请求发给本地
`POST /api/jev/test`，由 dashboard 后端默认调用固定的
`https://api.typesafe.ai/v1/systemone`（仅允许显式 localhost 测试 endpoint），因此不会触发 TypeSafe 的浏览器 CORS
限制。点击“保存 / 更新 Key”或成功测试带 Key 的请求后，Key 会原子写入当前 WSL
用户的 `~/.local/state/ros2-resilience-guardian/jev-<account>.json`，目录为 0700、
文件为 0600；不会写入 `.env`、GitHub、浏览器存储、ROS 消息、审计记录或日志。
状态接口只返回 `{"saved": true|false}`，不会回传完整 Key。点击“忘记已保存 Key”
才会删除本机记录；输入新的 Key 保存会原子替换旧记录。刷新、退出登录和 dashboard
服务重启不会删除它，输入框也不会回填明文；“清空输入”只清空当前页面输入。
该面板只返回攻击类型、任务影响、分数、置信度和人工复核建议，不会改变
Guardian 安全状态、速度限制或机器人命令。

面板也支持“加载样例文件”：选择本地 `.txt`、`.log`、`.csv` 或 `.json` 文件后，
浏览器只在内存中读取并把内容填入测试状态；JSON 字符串、`state` 字段和
`summary` 字段会直接作为状态，其余 JSON 会格式化显示。文件上限为 64 KiB，
发送状态上限为 4096 个字符，只有点击“测试连接”才会发给本地 dashboard，
不会保存文件或上传到仓库。留空 API Key 时会复用本机保存的 Key。

该接口接受 `{ "api_key": "...", "state": "..." }` JSON；已保存设备 Key 时，
也可只提交 `{ "state": "..." }`。请求体上限为
64 KiB，状态文本上限为 4096 个字符。成功返回 HTTP 200；输入错误返回
400/413；上游拒绝或返回非法内容返回 502；超时返回 504。真实 API Key
不应提交到版本库，也不应放入 `.env`。

Windows/WSL 启动器和双发行版构建入口见 [docs/deployment.md](docs/deployment.md)。
它不会自动安装或修改系统级服务；如需常驻仿真，可按文档复制用户级
`deploy/guardian@.service` 模板并自行审核工作区路径和发行版。

```powershell
.\deploy\start_guardian_dashboard.ps1 -Distro humble
```

详细设计见 [docs/design.md](docs/design.md)，实验和指标见 [docs/experiments.md](docs/experiments.md)。

创新功能验证见 [docs/innovation_validation.md](docs/innovation_validation.md)，可直接运行：

```bash
python3 experiments/run_innovation_experiments.py
```

运行专利化安全核心的五组对照实验：

    python3 experiments/run_patent_innovation_experiments.py

可选的 Jev 语义安全顾问见 [docs/jev_advisor.md](docs/jev_advisor.md)。它只对已经通过确定性验证的事件摘要做分类和人工复核建议，默认关闭，不进入 `guardian_node` 的实时控制循环，也不能解除停车或直接控制底盘；非布尔或未验证来源会在缓存和网络之前被拒绝。advisor 和高效判断层对注入时钟执行有限、单调不减保护，避免非法时间、TTL 回退、负延迟和预算窗口倒退；缓存过期判断和预算窗口时间都在锁内重新采样，暂停的旧请求不能复活过期建议或回滚并重置新窗口；高效层只接受 advisor 的新鲜 `OK` 结果启动自己的缓存租约，不会用下层 `CACHED` 结果续租；single-flight 失败会保留失败状态，缓存命中会重新计算冲突标记。离线实验使用 stub provider，不需要 API Key。Jev 高效判断层增加本地风险分流、稳定事件指纹、TTL/LRU 缓存、并发 single-flight、调用预算和冲突指标；运行 `python3 experiments/run_jev_efficiency_experiments.py` 可复现实验。

Jev 事件会话层进一步聚合连续告警、对风险和语义变化重新查询、用滞回窗口稳定人工复核状态，并把有期限的 Jev 软证据绑定到确定性父证据；同一会话的决策和账本写回串行化，不同事件仍可并行，账本的哈希链写入只在短临界区内串行，账本异常分支也受会话容量上限约束。父证据必须当前有效、`verified` 为原生布尔 `True`、策略匹配且完整父链可验证；非布尔祖先标记、过期、被替代或祖先失效都会在 provider 前阻断，provider 返回后还会按完成时刻再次校验，失败 provider 也不会绕过这道检查。迟到成功结果会消耗软证据剩余 TTL，不能建立已经过期的租约。缓存结果切换父证据只保留原软证据截止时间，到期缓存不能复活账本证据，只有新的 provider 成功结果才能建立新租约。会话 ID 和签名复用 Jev 适配器的有界上下文表示，避免超长输入放大会话层资源消耗；非布尔或未验证来源会强制进入本地 `CONTAINING`，不会复用旧 Jev 结果。实验命令为 `python3 experiments/run_jev_session_experiments.py`，设计见 [docs/jev_session_design.md](docs/jev_session_design.md)。

跨层融合扩展的历史实验设计见 [docs/fusion_experiment_plan.md](docs/fusion_experiment_plan.md)。2026-10-12 的最小恢复闭环已接入相关控制话题的 ROS 2 live graph、证据账本、预测距离约束与恢复协议，具体边界以 [安全恢复闭环](docs/evidence_bound_recovery.md) 为准；尚未接管真实底盘或 Webots。

### 前端防护测试台

登录驾驶舱后，页面中的“防护测试台”用于验证 Guardian 的确定性安全链路。它把样例依次送入：

`事件校验 → 攻击登记 → 风险评估 → 缓解规划 → 安全监督`

页面提供五个内置样例：正常基线、未知来源拦截、重复序列拦截、关键组件隔离和无隔离能力停车。也可以点击“导入样例 JSON”上传自定义回放；文件只在浏览器内读取，服务端只接受 `guardian-replay/v1`、最多 64 条事件的有界数据。判断结果会显示每一步的验证码、风险分数、缓解动作、安全状态和速度上限。

现在还提供“仓储 AMR 托盘运输”工业案例。选择该案例后，页面会展示机器人、任务阶段、
`/cmd_vel` 与 `/gripper/command` 主题、模拟威胁和 Jev 摘要；点击“执行防护判断”即可
在网页内运行四条事件的离线 Guardian 回放。点击“带入 Jev 语义分析”会把经过整理的摘要
复制到 Jev 页面，供用户检查后决定是否调用真实 provider。网页不会发布 ROS 2 事件，也不会
把 Jev 结果写回 Guardian 安全状态。执行 Guardian 回放后，还可以点击“运行 Jev 综合评价”，
对每条已验证事件单独调用 Jev，再按 Guardian 客观风险 60% + Jev 语义风险 40% 计算综合风险、
安全分和风险等级。重放、过期、未知来源等未验证事件不会外发给 Jev，而是保留本地硬证据。

自定义样例的最小格式如下：

```json
{
  "schema": "guardian-replay/v1",
  "name": "critical wheel test",
  "profile": "navigation",
  "events": [
    {
      "at": 10,
      "event_id": "event-1",
      "source": "scenario_injector",
      "component": "left_wheels",
      "attack_type": "STOP",
      "sequence": 1,
      "timestamp": 10,
      "confidence": 1
    }
  ]
}
```

`profile=navigation` 允许隔离配置中的组件；`profile=no_isolation` 用于验证无法安全隔离时进入 `SAFE_STOP`。该测试台调用的就是 `guardian_node` 使用的 `EventVerifier`、`AttackRegistry`、`RiskEngine`、`MitigationPlanner` 和 `SafetySupervisor` 类，但运行在新建的离线实例中，不发布 ROS 2 事件或控制命令。Jev 面板仍然是独立的语义复核旁路：它可以补充攻击类型和人工复核建议，不能改变测试台或实时 ROS 2 的安全结论。

### 仓储 AMR 托盘运输案例

为了让风险分析贴近真实工业任务，仓库中提供了一个 AMR 对接和托盘稳定案例：
`amr-07` 从 `A-12` 搬运托盘到 `P-07`，事件来自 `/cmd_vel` 和
`/gripper/command`。案例包含速度指令越界、`sequence=7001` 重放、后续异常速度
指令和抓取器力值为零四类记录。直接运行：

```bash
python3 experiments/run_warehouse_amr_case.py
```

预期验证序列为 `ACCEPTED → REPLAY → ACCEPTED → ACCEPTED`，最终安全状态为
`CONTAINING`，缓解动作是 `ISOLATE_COMPONENT`，速度上限为 `0.15 m/s`。这几个结论
来自 Guardian 的确定性校验和安全状态机；Jev 只接收验证后的限长摘要，用来补充攻击
类型、任务影响和人工复核建议。它不能解除隔离、改变速度上限或发布 `/cmd_vel`。

可操作的导入步骤、字段映射和风险解释见
[docs/warehouse_amr_case.md](docs/warehouse_amr_case.md)。防护实验室选择
`experiments/warehouse_amr_pallet_attack_replay.json`，Jev 语义分析页选择
`experiments/warehouse_amr_jev_context.json`。两个文件都只用于本地实验；案例脚本不
发布 ROS 2 事件，也不调用真实 Jev provider。

对应接口为受登录保护的 `GET /api/experiments/samples`、`POST /api/experiments/replay` 和
`POST /api/experiments/jev-evaluate`。后者使用已保存的 Jev Key，对最多 16 条事件做有界逐事件评价；
网络失败、Key 缺失或模型返回非法内容时保留 Guardian 硬安全下限。

### 多页面工作区与安全测试分析

前端按职责分为六页：

- **实时防护**：查看 ROS 2 风险、活动组件、缓解方案、速度上限和时间线。
- **防护实验室**：导入或上传 `guardian-replay/v1` 样例，查看五阶段逐步结果。
- **工程仿真**：启动仓储 AMR 数字孪生，观察攻击注入和 Guardian 安全反馈如何影响实际速度。
- **工业代码安全检查**：导入 ROS 2 Python 控制节点，检查执行器边界、急停门控、动态执行、凭据暴露和阻塞调用；代码只读分析，不会执行上传内容。规则和操作见 [docs/industrial_code_security.md](docs/industrial_code_security.md)。
- **ROS 安全图**：以离线有界图展示 ROS 2 文件、节点、publisher、subscriber、控制主题和危险路径，标记 `EXTRACTED`、`INFERRED`、`UNSUPPORTED` 证据；不会执行源码或直接控制机器人。详细规则见 [docs/ros_security_graph.md](docs/ros_security_graph.md)。
- 工业代码检查还提供 Gazebo Sim 风格的 AMR 源码：`experiments/gazebo_ros2_amr_controller_unsafe.py`。它使用 `/model/amr_07/cmd_vel` 这类 `ros_gz` 桥接主题，是故意包含风险的检查夹具，不能直接启动。
- **Jev 语义分析**：手动执行有界旁路请求，保存/更新或删除本机 Key；Jev 不进入控制闭环。
- **安全测试分析**：运行 `/api/research/suite` 的离线测试套件，展示高效判断路径、调用减少、会话复用、超时回退、父证据阻断和 ROS 2 安全案例。

研究套件使用生产 `JevEfficientJudge`、`JevIncidentSession`、`EvidenceLedger` 和防护回放类，
但使用确定性 stub provider，因此 `real_api_calls=0`、`actuation=none`。当前可复现实验为：

| 实验 | 观测结果 | 结论 |
| --- | --- | --- |
| 12 条重复事件 | 基线 12 次远程调用，效率层 1 次（91.67% 减少） | 稳定指纹和缓存避免重复语义请求 |
| 低风险 / 关键风险 | `LOCAL_SAFE` / `LOCAL_ENFORCED` | 正常和紧急路径不等待 Jev |
| 未验证来源 | `SKIPPED_UNVERIFIED`，外发 0 次 | Jev 不能绕过 ROS 2 信任边界 |
| Jev 超时 | `UNAVAILABLE`，本地状态继续 | 语义服务故障不影响确定性安全逻辑 |
| 事件会话 | 1 次 `QUERIED` + 9 次 `SESSION_REUSE` | 会话滞回和软证据减少抖动 |
| 父证据过期 | `LEDGER_BLOCKED`，外发 0 次 | 软证据不能脱离确定性父证据 |

运行命令：

```bash
python3 -m pytest -q tests/test_dashboard_research.py
python3 - <<'PY'
from guardian_core.dashboard_research import run_research_suite
print(run_research_suite())
PY
```

这些结果衡量的是本地调度效率和安全边界，不等价于真实 Jev 模型的准确率、网络延迟或实机安全认证；后续论文实验应加入带标签数据集、真实 API 成本/延迟和 Webots/硬件适配器。

专利化研究方案、现有技术边界和对照实验见 [docs/patent_disclosure.md](docs/patent_disclosure.md)、[docs/patent_prior_art.md](docs/patent_prior_art.md) 和 [docs/patent_experiments.md](docs/patent_experiments.md)。当前新增的因果图、证据账本、预测安全包络、反事实解释和双阶段恢复协议已完成纯 Python 离线验证，尚未宣称完成实机认证或专利授权。
## Current implementation status

Implemented in this repository:

- Event verifier with trusted-source, timestamp, sequence/replay and optional HMAC checks.
- Event-sourced attack registry with expiry and per-component aggregation.
- Paper-compatible `delta`, `psi`, `gamma` metrics plus bounded runtime risk.
- Dynamic mitigation planner that re-plans on every event-set change.
- Independent safety supervisor with explicit `NORMAL`, `CONTAINING`, `RESUMABLE` and `SAFE_STOP` decisions.
- ROS 2 Jazzy interfaces and `guardian_node` publishers/subscribers.
- Headless multi-wave scenario driver and tests.

Integration boundary:

`guardian/safety_status` is intentionally an output boundary. A Webots or hardware adapter must apply its speed limit and stop decision to the actual robot controller. This keeps the safety policy testable and prevents the Guardian from directly owning robot-specific APIs.
