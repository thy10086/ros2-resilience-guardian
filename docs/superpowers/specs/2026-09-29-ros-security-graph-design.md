# ROS Security Graph v1 设计规格

日期：2026-09-29

## 目标

在现有 ROS 2 Resilience Guardian 中加入一个离线、只读、可追溯的
ROS Security Graph 分析层，用代码结构、ROS 2 资源关系和安全控制证据揭示
从输入到执行器的危险路径。分析结果用于 Dashboard 展示、上线前审计和
Guardian 风险解释，不直接改变实时 `SafetyStatus`、`MitigationCommand`
或机器人运动。

## 非目标

- 不在 `guardian_node` 的 100 ms 安全循环中运行图构建或复杂推理。
- 不执行、导入或启动用户提交的源码。
- 不把大模型或外部网络服务放入安全决策路径。
- 不替代 SROS2/DDS-Security、硬件急停、独立 watchdog 或真实执行器反馈。
- 第一版不复制完整 Graphify，也不引入 Graphify 运行时依赖。
- 第一版只对 Python ROS 2、Python launch、YAML/XML 配置和已知 ROS 资源
  做有界分析；无法解析的 C/C++ 文件必须标记为 `UNSUPPORTED`，不能判为安全。

## 核心数据模型

输出 schema 固定为 `ros-security-graph/v1`。

### 节点

节点至少包含：

```json
{
  "id": "topic:/cmd_vel",
  "kind": "topic",
  "label": "/cmd_vel",
  "file": "controller.py",
  "line": 42,
  "trust_zone": "unknown",
  "criticality": "high",
  "provenance": "EXTRACTED"
}
```

支持的 `kind`：

```text
file, module, class, function, ros_node, publisher, subscriber,
topic, service, action, parameter, controller, actuator, sensor,
trust_zone, security_profile
```

### 边

边至少包含：

```json
{
  "source": "function:controller.py:publish_cmd",
  "target": "topic:/cmd_vel",
  "kind": "publishes",
  "file": "controller.py",
  "line": 87,
  "confidence": 1.0,
  "provenance": "EXTRACTED",
  "security_relevance": "control_path"
}
```

支持的 `kind`：

```text
contains, imports, calls, publishes, subscribes, creates_service,
uses_parameter, controls, protected_by, crosses_trust_boundary,
requires_ack, declares_permission
```

### 证据和结论

每个 finding 必须绑定：

```text
rule_id
severity
title
file
line
evidence
recommendation
guardian_action
path_node_ids
path_edge_ids
confidence
```

`guardian_action` 只允许：

```text
NONE
REVIEW_REQUIRED
ISOLATE_COMPONENT
SAFE_STOP
```

图分析的总体结论遵循最严格规则：`SAFE_STOP` 高于
`ISOLATE_COMPONENT`，未知解析结果不能降级为 `PASS`。

## 第一版抽取规则

1. 复用现有 `dashboard_code_security.py` 的 Python AST 能力，提取文件、
   类、函数、import、publisher、subscription、service、ROS topic 和
   `rclpy` 运行入口。
2. 从 `create_publisher`、`create_subscription` 和显式控制主题推导
   `publishes`/`subscribes` 边。
3. 识别 `/cmd_vel`、`/joint_trajectory`、`/gripper/command` 以及
   Gazebo `/model/<name>/cmd_vel` 为高关键度执行器主题。
4. 识别 `mission_allowed`、`safety_ok`、`estop`、`safe_stop`、
   `speed_limit` 等安全门控和速度限幅证据。
5. 读取 `security_profile_json`、`configs/guardian.yaml` 和可提供的
   SROS2 权限摘要，建立资源、执行适配器和信任域关联。
6. 对 Python 之外的源文件保留文件节点，并生成 `UNSUPPORTED` 证据；
   不通过正则推断其为安全。
7. 所有节点和边都保留文件路径、行号、来源和置信度，支持后续图差异。

## 第一版安全规则

| 规则 | 条件 | 结论 |
| --- | --- | --- |
| `GRAPH-ACT-001` | 控制主题发布路径没有安全许可门控 | `ISOLATE_COMPONENT` |
| `GRAPH-ACT-002` | `/cmd_vel` 发布路径没有可验证速度限幅 | `ISOLATE_COMPONENT` |
| `GRAPH-DYN-001` | `eval`、`exec`、动态导入或动态编译进入控制路径 | `SAFE_STOP` |
| `GRAPH-DYN-002` | 控制节点导入或调用外部进程 | `ISOLATE_COMPONENT` |
| `GRAPH-TRUST-001` | 未知来源直接连接高关键度执行器 | `SAFE_STOP` |
| `GRAPH-FEEDBACK-001` | 控制路径没有 ACK、watchdog 或安全状态证据 | `REVIEW_REQUIRED` |
| `GRAPH-PERM-001` | 高关键度 ROS 资源没有可验证权限摘要 | `REVIEW_REQUIRED` |
| `GRAPH-PARSE-001` | 关键控制文件无法解析或语言不支持 | `SAFE_STOP` |

规则只产生审计结果和路径解释。实时 Guardian 仍使用已有
`EventVerifier`、`RiskEngine`、`MitigationPlanner` 和
`SafetySupervisor`。

## 接口和 Dashboard

新增离线接口：

```text
GET  /api/ros-graph/samples
POST /api/ros-graph/inspect
```

请求限制：

```text
最多 128 个文件
单文件最多 64 KiB
总源码最多 512 KiB
文件路径只能是相对路径，拒绝绝对路径、路径穿越和 NUL 字符
只接受 source、filename、profile 字段
```

`POST /api/ros-graph/inspect` 返回：

```text
schema
summary
nodes
edges
findings
paths
unsupported_files
assurance
```

前端新增“ROS 安全图”工作区，至少支持：

- 内置安全/危险样例导入；
- 节点和边的颜色区分；
- 高风险路径优先显示；
- 点击 finding 查看文件、行号、证据和 Guardian 建议动作；
- 显示 `EXTRACTED`、`INFERRED`、`UNSUPPORTED`；
- 明确显示“静态分析，不执行源码，不直接控制机器人”。

第一版使用现有前端和原生 SVG/DOM，不增加 CDN 或外部运行时依赖。

## 安全和性能边界

- 分析器只把源码当作字符串，不 `import`、`exec`、启动子进程或发布 ROS 2
  消息。
- 输入、节点、边、路径和 finding 均有硬上限。
- 图算法使用有界 BFS/DFS，最多保留 64 条危险路径。
- 任何解析异常、资源超限或不支持文件都进入有限错误或审计 finding，
  不影响 Guardian 实时线程。
- 语义模型调用默认关闭；后续若增加，只能接收脱敏摘要，不能接收原始源码，
  也不能改变安全结论。

## 测试要求

- 规则单测：安全样例、危险样例、动态执行、未限速、未门控、无法解析。
- 图结构测试：节点、边、行号、来源、关键主题和危险路径。
- 输入边界测试：文件数、单文件大小、总大小、路径穿越、NUL 和非法 profile。
- Dashboard HTTP 测试：未登录拒绝、登录后接口可用、响应不执行源码。
- 前端契约测试：工作区、图容器、finding 详情和安全边界文案。
- 全量 ROS 2 测试保持通过。

## 分阶段交付

### v1.0

离线多文件分析、JSON 结果、Dashboard 原生图视图、8 条安全规则和完整测试。

### v1.1

加入静态图与 ROS 2 live graph snapshot 的对比，但仍只用于观测和审计。

### v1.2

加入 SROS2/DDS 权限文件的结构化摘要、节点身份和权限边界可视化。

### 后续研究

将图快照、Guardian 风险记录、ACK 身份和任务阶段形成可追溯证据链；
任何自动停车规则仍需独立安全论证和 HIL/实机验收。
