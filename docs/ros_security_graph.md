# ROS Security Graph v1

ROS Security Graph 是一个离线、只读的 ROS 2 代码与配置审计层。它借鉴
Graphify 的“代码结构图 + 关系边 + 风险路径”思路，但不引入 Graphify
运行时依赖，也不执行、导入、启动或发布用户提交的源码。

## 适用范围

当前版本支持：

- Python、Python stub 和 Python launch 文件的 AST 结构提取；
- YAML、XML、SDF、URDF、JSON、TOML 中有限的字面 ROS 资源引用；
- `/cmd_vel`、`/joint_trajectory`、`/gripper/command` 和 Gazebo
  `/model/<name>/cmd_vel` 等高关键度控制主题；
- 文件、类、函数、ROS 节点、publisher、subscriber、topic、controller
  和 actuator 的节点及其关系；
- 不支持的 C/C++ 或其他控制源文件的 `UNSUPPORTED` 证据。

不支持的文件不能被判为 `PASS`。静态图结论不能替代 SROS2/DDS 权限、
硬件急停、独立 watchdog、执行器反馈、HIL 或真实机器人验收。

## 输入与接口

Dashboard 登录后可以使用：

- `GET /api/ros-graph/samples`：读取内置安全和危险样例；
- `POST /api/ros-graph/inspect`：提交 `{ "files": [...], "profile": "ros2_generic" }`。

每个文件只接受 `filename` 和 `source` 字段。输入边界为最多 128 个文件、
单文件最多 64 KiB、总源码最多 512 KiB。文件名必须是唯一的相对路径，拒绝
绝对路径、路径穿越、NUL 字符和非法 JSON。请求错误不会回显源码。

## 输出

输出 schema 固定为 `ros-security-graph/v1`，包含：

- `nodes`、`edges`：带文件、行号、置信度和 `EXTRACTED`/`INFERRED`/
  `UNSUPPORTED` 来源的图元素；
- `findings`：规则、严重程度、证据、建议、Guardian 动作和关联路径；
- `paths`：最多 64 条从可疑函数或文件到关键控制主题的有界路径；
- `summary`：`PASS`、`REVIEW` 或 `BLOCKED` 以及严重程度计数；
- `unsupported_files`：无法完成静态理解的文件；
- `assurance`：静态模式、源码未执行、运行时未验证和覆盖率说明；
- `execution`：固定为 `not_executed`。

`guardian_action` 只允许：
`NONE`、`REVIEW_REQUIRED`、`ISOLATE_COMPONENT`、`SAFE_STOP`。
它是上线前审计建议，不会修改 `SafetyStatus`、`MitigationCommand`、
`SAFE_STOP`、速度限制或恢复状态。

## 安全规则

| 规则 | 发现条件 | 审计动作 |
| --- | --- | --- |
| `GRAPH-ACT-001` | 控制主题发布路径没有安全许可门控 | `ISOLATE_COMPONENT` |
| `GRAPH-ACT-002` | `/cmd_vel` 发布路径没有可验证速度限幅 | `ISOLATE_COMPONENT` |
| `GRAPH-DYN-001` | 动态执行、动态编译或动态导入进入控制路径 | `SAFE_STOP` |
| `GRAPH-DYN-002` | 控制节点导入或调用外部进程 | `ISOLATE_COMPONENT` |
| `GRAPH-TRUST-001` | 未知来源直接连接高关键度执行器 | `SAFE_STOP` |
| `GRAPH-FEEDBACK-001` | 缺少 ACK、watchdog 或安全状态反馈证据 | `REVIEW_REQUIRED` |
| `GRAPH-PERM-001` | 高关键度 ROS 资源没有可验证权限摘要 | `REVIEW_REQUIRED` |
| `GRAPH-PARSE-001` | 关键文件无法解析或语言不受支持 | `SAFE_STOP` |

严重程度和动作聚合采用最严格结果：
`SAFE_STOP > ISOLATE_COMPONENT > REVIEW_REQUIRED > NONE`。

## Dashboard 操作

登录 Dashboard 后打开“ROS 安全图”工作区：

1. 选择内置安全/危险样例，或选择本地多个源码与配置文件；
2. 点击静态检查，查看文件、节点、边、finding 和危险路径；
3. 优先查看 `BLOCKED`、`UNSUPPORTED` 和 `SAFE_STOP` 结果；
4. 结合源码行号、证据来源、SROS2/DDS 权限和运行时测试做人工复核。

图视图使用原生 SVG 和可访问的文本列表，不依赖 CDN 或外部服务。页面中的
“静态分析，不执行源码，不直接控制机器人”是该工作区的固定边界说明。
