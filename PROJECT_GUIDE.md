# ROS 2 Resilience Guardian 项目导航

这是一个独立的 Codex 项目目录。后续代码修改、测试和运行都以本目录为准。

## 目录职责

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
- 沙箱仿真：`sandbox_simulation.py`
- 数据集上传和安全审计：`dataset_upload.py`、`dataset_security.py`
- Jev 接口和 Key 管理：`dashboard_jev.py`、`dashboard_credentials.py`
- 登录会话：`dashboard_auth.py`

修改 API 时必须同时检查：

1. 前端 `app.js` 的 endpoint 和响应字段。
2. 对应 `tests/test_dashboard_*.py`。
3. `README.md` 和 `HANDOFF.md` 的操作说明。

### 修改实时安全逻辑

建议按以下顺序定位：

1. `verifier.py`：事件是否可信、是否过期、是否重放。
2. `registry.py`：攻击登记和过期。
3. `risk_engine.py`：风险分数和关键组件。
4. `planner.py`：隔离、限速、停车等缓解计划。
5. `supervisor.py`：`NORMAL`、`CONTAINING`、`RESUMABLE`、`SAFE_STOP` 状态。
6. `guardian_node.py`：ROS 2 话题订阅和发布边界。

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

项目使用 WSL2 Ubuntu 22.04 + ROS 2 Humble。启动前进入本目录：

```bash
cd /mnt/c/Users/thy/Documents/Codex/ros2-resilience-guardian
source /opt/ros/humble/setup.bash
source ros2_ws/install/setup.bash
```

如果安装目录不存在，先构建：

```bash
cd ros2_ws
colcon build --symlink-install
source install/setup.bash
```

Dashboard 地址：

```text
http://127.0.0.1:8088
```

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
