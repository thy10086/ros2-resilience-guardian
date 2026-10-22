# 项目工作团队分工

本项目采用“主协调线程 + 专业工作线程”的协作方式。主线程负责拆分任务、
决定跨模块方案、合并结果和最终验收；专业线程只在自己的职责边界内分析或
修改，避免多个线程同时改同一份安全契约。

## 主协调线程

负责：

- 接收用户需求并拆分任务；
- 判断是否影响 Guardian 实时安全契约；
- 统筹跨线程接口、测试和文档；
- 执行最终全量测试、ROS 2 构建和变更审计；
- 维护本文件和 `HANDOFF.md`。

默认规则：涉及多个安全边界、消息接口或运行时状态的变更，必须回到主线程
统一决定，不能由单个专业线程独立改变。

## 专业线程

### 1. 总架构与安全边界

职责：

- Guardian 实时 100 ms 安全循环；
- `SafetyStatus`、`MitigationCommand` 和状态机契约；
- 威胁模型、信任边界、生产安全限制；
- 跨模块变更影响和上线风险。

主要文件：

- `guardian_node.py`
- `models.py`
- `supervisor.py`
- `planner.py`
- `verifier.py`
- `registry.py`
- `risk_engine.py`
- `docs/deployment.md`

禁止单独决定：硬件急停、真实执行器认证、SROS2/DDS 生产策略和实机放行。

### 2. ROS 2 运行时与执行器安全

职责：

- ROS 2 消息、节点、参数和 launch；
- ACK、watchdog、command epoch、transmission identity；
- AMR 仿真闭环；
- SROS2/DDS、执行器适配器、HIL 和实机验证边界。

主要文件：

- `ros2_ws/src/guardian_interfaces/`
- `ros2_ws/src/guardian_core/guardian_core/guardian_node.py`
- `ros2_ws/src/guardian_core/guardian_core/amr_simulator.py`
- `ros2_ws/src/guardian_core/launch/`
- `configs/guardian.yaml`
- `deploy/`

每次修改必须验证：消息构建、参数契约、状态机回归和关闭清理。

### 3. ROS Security Graph 与代码审计

职责：

- Graphify 风格的代码关系图；
- Python AST、ROS 资源、权限摘要和危险控制路径；
- `GRAPH-*` 规则、证据来源、输入边界；
- 确保静态分析不导入、不执行、不启动源码。

主要文件：

- `ros2_ws/src/guardian_core/guardian_core/ros_graph_security.py`
- `ros2_ws/src/guardian_core/guardian_core/dashboard_code_security.py`
- `tests/test_ros_graph_security.py`
- `tests/test_dashboard_code_security.py`
- `docs/ros_security_graph.md`

禁止事项：不能把静态 `SAFE_STOP` 建议直接写入实时 Guardian 状态。

### 4. Dashboard 与前端体验

职责：

- Dashboard HTTP 路由、认证和请求边界；
- HTML、CSS、JavaScript、SVG 图；
- 工作区、响应式、可访问性和浏览器交互；
- API/DOM 契约与源码字段转义。

主要文件：

- `ros2_ws/src/guardian_core/guardian_core/dashboard.py`
- `ros2_ws/src/guardian_core/guardian_core/frontend/`
- `tests/test_dashboard_*.py`
- `tests/test_frontend_workspace.py`

每次修改必须验证：认证、请求上限、JavaScript 语法和前端契约测试。

## 主线程暂代职责

当前专业线程并发上限为 4 个，以下职责暂由主协调线程负责：

- 全量 pytest 和回归基线；
- Humble/Jazzy 构建与部署观察；
- CI、运行脚本和发布前检查；
- 开源项目、论文和标准的外部研究。

## 变更交接格式

每个专业线程提交结果时必须说明：

1. 修改了哪些文件；
2. 是否触碰实时安全契约；
3. 新增或更新了哪些测试；
4. 执行了哪些验证命令及结果；
5. 尚未覆盖的风险和下一步建议。

跨职责修改采用以下顺序：

`需求拆分 → 专业线程分析 → 主线程裁决接口 → 单线程实现 → 专业复核 → 全量验证`

未经主线程确认，不允许多个线程并行修改同一个生产代码文件。
