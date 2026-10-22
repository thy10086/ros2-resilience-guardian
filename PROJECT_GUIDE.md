# ROS 2 Resilience Guardian 项目导航

这是一个独立的 Codex 项目目录。后续代码修改、测试和运行都以本目录为准。

ARTEX风格四角色闭环见 `docs/artex_ros2_agent_review.md`；`experiments/run_agent_review.py --sample --output <新JSON文件>`保留fixture模式，`--provider llm --base-url ... --model ...`读取指定环境变量的Key接真实接口。检测页“安全测试分析”提供URL/Key/模型、运行/查询/取消/下载。核心在`experiments/agent_review/`，页面作业层在`dashboard_agents.py`；LangGraph/pyseccomp在独立研究venv，不进入Guardian实时依赖。上传源码静态发现、原frames违规及模型执行分开，本地HTTP协议验收不代表真实模型效果验证。

当前主题为“面向 ROS 2 机器人的证据与上下文绑定安全恢复机制”。首轮 AMR 软件闭环见 `docs/evidence_bound_recovery.md`；复现入口为 `experiments/run_bound_recovery_experiments.py`。图发现复用 rclpy，认证复用标准库 HMAC，不自行实现新的发现或密码协议。

第二轮独立观测闭环见 `docs/independent_observation.md`；复现入口为 `launch_test experiments/independent_observation_launch_test.py`。`recovery_observer.py` 消费标准里程计和激光，`independent_observation.py` 负责时效、方向、配对融合及启动会话水位。独立模式需要单独观测签名密钥，不能在失效时回退到单源模式。

第三轮离线恢复反馈测试见 `docs/recovery_feedback_fuzzing.md`；入口为 `experiments/run_recovery_feedback_fuzzing.py`，Hypothesis 依赖在 `experiments/requirements-fuzzing.txt`，只用于隔离离线环境。`recovery_feedback.py` 提供归一化覆盖与精确安全断言；ROS 节点启用 audit_path 后可产出同构审计帧。BTreeFuzz 依据记录在 `docs/btreefuzz_recovery_testing.md`，不宣称算法复现或覆盖收益。

第四轮评估入口为 `experiments/run_recovery_evaluation.py`，定向变异只在 `experiments/recovery_mutations.py` 的独立对象中运行；默认 ROS 类不被替换。`docs/recovery_evaluation.md` 记录10种子/1000预算对照与消融结果。`ros_startup_diagnostics.py` 提供白名单启动诊断；UDP XML 仅作诊断对照，DDS零话题超时根因仍未确认。

第五轮见 `docs/permit_boundary_feedback.md`；`experiments/permit_boundary_feedback.py` 只从完整机制轨迹提取TTL/精确绑定/修复特征，四个Hypothesis目标不读取变异缺陷或Oracle结果。指定 `--modes unguided,guided,boundary` 可运行公平三组对照，正式结果目录为 `experiments/results/permit_boundary_feedback_strict/`。当前TTL检出8/10、旧目标4/10、无引导9/10，不宣称新目标全面优胜；自动重放corpus/所有反例并校验源码指纹记录。

第六轮见 `docs/feedback_target_ablation.md`；同一runner增加 `ttl` 与 `context_repair` 目标族消融，显式 `--seed-role unseen_validation` 标记seeds10..19验证批次。四个特征仍全部采集，`active_target_labels` 单独记录实际优化标签。原始失败批次在 `experiments/results/feedback_target_ablation/`，修正活性采样前提后的完整重跑在 `feedback_target_ablation_corrected/`，两者不混合统计。`SafetyOracle.max_frame_gap_sec=.25` 只约束连续活性推断，空窗期间仍检查过期、授权、上下文及重放。

## 目录职责

前端恢复检测见 `docs/recovery_detection_page.md`。`dashboard_recovery.py` 是已有Oracle的只读适配器，`frontend/recovery.js` 负责样例/导入/检测和对照表；`experiments/export_recovery_dashboard.py` 从通过验收的报告导出两个随包分发的公开JSON资源。登录后的 `POST /api/recovery/inspect` 不调用Jev或ROS执行器，历史快照不依赖运行时的实验环境。

第七轮独立缺陷/等壁钟入口为 `experiments/run_recovery_holdout.py`，协议与结果见 `docs/recovery_holdout_validation.md`。新变异在 `recovery_holdout_mutations.py`，通过场景 gate_factory 复用生产核心，原四族与 ROS 类不被替换。run_campaign 可选 wall_time_sec 要求无预热/缩减；报告区分预算内与超时发现、截尾时间、尾部超时，保存来源快照并拒绝目录覆盖。原前端第六轮快照保留。

第八轮新增 `experiments/recovery_liveness_feedback.py` 的轨迹健康窗口/恢复阶段目标；holdout runner 增加 `liveness` 和 `boundary_liveness`，报告见 `docs/recovery_liveness_feedback.md`，正式数据在 `experiments/results/recovery_liveness_validation/`。已知停滞缺陷的新种子结果为 liveness 16/20、unguided 5/20，但组合模式仅7/20；只作为离线搜索反馈研究，不改变安全判定、生产恢复逻辑或默认模式，也不等同于未见缺陷泛化。

第九轮见 `docs/recovery_transfer_validation.md`：`run_recovery_holdout.py --defect-suite transfer --preregistration ...`复用原框架验证 `recovery_transfer_mutations.py` 的独立新两族，登记锁定前批11份保留源和种子/模式/预算。两组各族均20/20，无新增检出优势。`independent_observation_launch_test.py`可通过 `GUARDIAN_RECOVERY_ARTIFACT_DIR` 留存停机后的原始审计/安装来源快照；`inspect_recovery_audit.py --input ... --output ... --expected-sha256 ...`复用现有只读检测器，接受有界JSON/JSONL。正式数据分别在 `recovery_transfer_validation/`、`recovery_ros_trace_validation/`；后者为自有真实DDS软件模型，不是外部物理机器人数据。

```text
ros2-resilience-guardian/
├─ ros2_ws/
│  └─ src/
│     ├─ guardian_interfaces/       ROS 2 消息定义
│     └─ guardian_core/             Guardian 核心、节点和前端
│        └─ guardian_core/
│           ├─ frontend/             HTML/CSS/JavaScript 页面
│           ├─ dashboard*.py         Dashboard HTTP API 和各业务面板
│           ├─ guardian_node.py      ROS 2 安全守护节点
│           ├─ amr_simulator.py      AMR 闭环工程仿真
│           ├─ sandbox_simulation.py 上传代码隔离仿真
│           ├─ dataset_security.py   数据集静态审计
│           ├─ ros_graph_security.py ROS 2 安全图静态分析
│           ├─ verifier.py            事件来源、时间、序列校验
│           ├─ risk_engine.py         风险计算
│           ├─ planner.py             缓解动作规划
│           └─ supervisor.py          安全状态机
├─ experiments/                       可复现实验和工业仿真样例
├─ tests/                             项目自身的 Python 测试
├─ testdata/robotics-security-mini/   机器人代码与数据集安全测试集
├─ docs/                              设计、实验、Jev 和专利交接文档
├─ configs/                           Guardian 配置
├─ deploy/                            本地/WSL 启动脚本和服务文件
├─ security/                          安全边界说明
├─ .env                               本地默认配置，必须保留在 Git
├─ README.md                          项目总说明和运行入口
└─ HANDOFF.md                         当前交接、约束和已完成事项
```

## 常见修改位置

### 修改前端页面

- 页面结构、文字和控件：`ros2_ws/src/guardian_core/guardian_core/frontend/index.html`
- 页面交互、上传、API 调用和结果渲染：`ros2_ws/src/guardian_core/guardian_core/frontend/app.js`
- 页面样式：`ros2_ws/src/guardian_core/guardian_core/frontend/styles.css`
- 前端结构测试：`tests/test_frontend_workspace.py`

### 修改 Dashboard API

- 总路由和静态页面服务：`ros2_ws/src/guardian_core/guardian_core/dashboard.py`
- 防护回放：`dashboard_experiments.py`
- 工业代码检查：`dashboard_code_security.py`
- ROS 安全图：`ros_graph_security.py`，只读解析 Python AST 和有限配置引用
- 沙箱仿真：`sandbox_simulation.py`
- 数据集上传和安全审计：`dataset_upload.py`、`dataset_security.py`
- Jev 接口和 Key 管理：`dashboard_jev.py`、`dashboard_credentials.py`
- 登录会话：`dashboard_auth.py`

修改 API 时必须同时检查：

1. 前端 `app.js` 的 endpoint 和响应字段。
2. 对应 `tests/test_dashboard_*.py`。
3. `README.md` 和 `HANDOFF.md` 的操作说明。

ROS 安全图接口位于 `/api/ros-graph/samples` 和 `/api/ros-graph/inspect`，
需要登录。它只把源代码当作字符串进行静态审计，不会导入、执行、启动或发布
提交内容；图分析不能替代 SROS2/DDS 权限、硬件急停、watchdog 或实机验证。

### 修改实时安全逻辑

建议按以下顺序定位：

1. `verifier.py`：事件是否可信、是否过期、是否重放。
2. `registry.py`：攻击登记和过期。
3. `risk_engine.py`：风险分数和关键组件。
4. `planner.py`：隔离、限速、停车等缓解计划。
5. `supervisor.py`：`NORMAL`、`CONTAINING`、`RESUMABLE`、`SAFE_STOP` 状态。
6. `guardian_node.py`：ROS 2 话题订阅和发布边界。
7. `bound_recovery.py`：证据账本、预测距离约束、稳定观察与一次性恢复协议的协调。
8. `recovery_graph.py`：从 rclpy 原生发现 API 提取相关 live control endpoints。
9. `RecoveryTelemetry.msg`：认证健康观测；新 epoch 使旧观测失效，告警 TTL 不能代替解除证据。

不要让 Jev 直接修改速度、任务许可、隔离动作或 ROS 2 控制输出。

### 新增工业测试样例

- 防护回放 JSON：`experiments/*.json`
- Python 控制器：`experiments/*.py`
- Gazebo/SDF/URDF：`experiments/*.sdf`、`*.xml`、`*.urdf`
- 仓储 AMR 案例：`experiments/run_warehouse_amr_case.py`
- 测试集清单：`testdata/robotics-security-mini/manifest.json`

新增样例后需要：

1. 明确它是“可运行仿真代码”还是“故意包含风险的安全检查夹具”。
2. 在 README 或对应 `docs/` 文档中说明运行命令。
3. 增加最小测试，避免只依赖人工点击。

## 本地运行

项目同时支持 WSL2 Ubuntu 22.04 + ROS 2 Humble 和 Ubuntu 24.04 +
ROS 2 Jazzy。推荐通过部署辅助脚本运行，避免两个发行版复用构建产物：

```bash
cd /mnt/c/Users/thy/Documents/Codex/ros2-resilience-guardian
bash deploy/run_guardian.sh build --distro humble
```

切换到 Jazzy 时使用：

```bash
bash deploy/run_guardian.sh build --distro jazzy
```

测试和启动：

```bash
bash deploy/run_guardian.sh test --distro humble
bash deploy/run_guardian.sh all --distro humble
```

Dashboard 默认地址：`http://127.0.0.1:8080`。

本地登录：

```text
用户名：admin
密码：admin
```

项目默认前端由源码目录提供，便于修改后立即验证：

```bash
export GUARDIAN_FRONTEND_DIR=/mnt/c/Users/thy/Documents/Codex/ros2-resilience-guardian/ros2_ws/src/guardian_core/guardian_core/frontend
```

## 验证命令

只运行项目自身测试，不要在 Windows 原生 Python 中递归收集 ROS 2 安装目录或
`testdata` 中第三方项目的原始测试：

```bash
cd /mnt/c/Users/thy/Documents/Codex/ros2-resilience-guardian
python3 -m pytest -q tests
```

运行仓储 AMR 防护实验：

```bash
python3 experiments/run_warehouse_amr_case.py
```

## Git 约束

- 工作分支使用 `main`。
- `.env` 必须保留并纳入 Git。
- 大型数据集文件使用 Git LFS。
- 不要提交 `ros2_ws/build/`、`ros2_ws/install/`、`ros2_ws/log/` 等生成目录。
- 不要把真实 Jev API Key 写入 `.env`、源码或提交记录。
