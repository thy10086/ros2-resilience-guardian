# 仓储 AMR 托盘运输安全案例

本案例把 Guardian 放在一个常见的仓储 AMR 任务中：机器人 `amr-07` 从货架
`A-12` 搬运托盘到装卸位 `P-07`。机器人处于低速对接和托盘稳定阶段，此时速度
指令和抓取器状态都直接影响人员、货物和设备安全。

## 工业数据如何进入 Guardian

真实部署时，适配器可以从 ROS 2/DDS、PLC 网关和安全扫描器收集原始记录。案例脚本
`experiments/run_warehouse_amr_case.py` 用 `RAW_EVENTS` 模拟这条边界，但不会发布真实
ROS 2 消息。适配器只把必要字段转换成有界的 `guardian-replay/v1` 事件：

| 原始工业来源 | 关键字段 | Guardian 检查 |
| --- | --- | --- |
| `/cmd_vel` | `linear_x=0.62`，期望上限 `0.12` | 来源、时间戳、序列号、关键轮组件 |
| `/cmd_vel` 重复消息 | 两条消息都使用 `sequence=7001` | 重放检查，第二条拒绝 |
| `/cmd_vel` 后续指令 | `sequence=7002`，仍然超过对接速度 | 接受事件并重新计算风险 |
| `/gripper/command` | `grip_force=0`，但 `load_present=true` | 语义异常进入活动攻击集合 |

运行离线案例：

```bash
cd /mnt/c/Users/user/Documents/Codex/2026-09-10/ban/ros2-resilience-guardian
python3 experiments/run_warehouse_amr_case.py
```

脚本输出原始事件、每一步的验证码、风险、缓解计划和最终安全状态。由于 Windows
PowerShell 的默认输出编码可能显示中文乱码，查看中文时可以在 WSL 中运行，或使用
`python3 -X utf8 experiments/run_warehouse_amr_case.py`。

## 预期结果与含义

四条记录的验证结果按顺序为：

```text
ACCEPTED → REPLAY → ACCEPTED → ACCEPTED
```

第二条记录没有进入攻击登记，因为它复用了左轮的序列号。第一条和第三条速度异常
仍然说明左轮组件存在持续风险；第四条又把右臂抓取器加入活动组件。最终结果为：

```text
state       = CONTAINING
action      = ISOLATE_COMPONENT
speed_limit = 0.15 m/s
accepted    = 3
rejected    = 1
```

这表示任务不能按原速度继续，安全适配器应隔离左轮相关控制路径并保持低速包络，直到
重新评估任务。案例脚本本身没有执行隔离，也不会向 `/cmd_vel` 发布命令；实际执行由
连接 `guardian/safety_status` 的机器人安全控制器负责。

## Jev 的介入位置

Jev 是经过本地验证后的语义复核旁路，不是运动控制器。数据流如下：

```text
ROS 2/DDS 原始事件
        ↓
Guardian 来源、时间戳、序列号和重放校验
        ↓
Guardian 风险、状态机和缓解动作（确定性安全结论）
        ↓
有界摘要（不包含高频原始遥测、密钥或完整日志）
        ↓
Jev 判断攻击类型、任务影响和人工复核建议
        ↓
软证据，供研究和运维界面查看
```

`experiments/warehouse_amr_jev_context.json` 就是这一摘要，可在前端的“Jev 语义分析”
页面通过“加载样例文件”导入。留空 API Key 时会复用本机已保存的 Key；没有 Key 时仍
可先查看摘要，但不能执行真实 provider 请求。真实调用只经过本地 dashboard 代理，
不会让浏览器直接访问 TypeSafe。

Jev 可以补充以下问题：

1. 这组事件更像速度指令注入、序列重放，还是抓取器语义失配？
2. 对接偏移、托盘碰撞和货物掉落哪个任务影响更紧急？
3. 是否需要人工检查左轮执行器、抓取器和装卸位安全区域？

Jev 不能执行以下动作：解除 `CONTAINING` 或 `SAFE_STOP`、修改 `speed_limit`、发布
`/cmd_vel`、替代事件来源验证，或在 Guardian 失败时把风险改为安全。Jev 请求超时、
返回非法内容或 Key 被拒绝时，本地确定性安全链路仍然保持原结论。

## 前端操作步骤

1. 打开 `http://127.0.0.1:8088`，使用 `admin/admin` 登录。
2. 进入“防护实验室”，在“内置防护样例”中选择“仓储 AMR 托盘运输”，点击“导入内置样例”。
   页面会显示 `amr-07`、`A-12 → P-07`、任务阶段、两个 ROS 2 主题和三类威胁。
3. 点击“执行防护判断”，逐步查看四条事件的验证码、风险分数、缓解动作和速度上限。
4. 点击案例卡片中的“带入 Jev 语义分析”，页面会把有界摘要填入 Jev 状态框；也可以进入
   “Jev 语义分析”后点击“加载样例文件”，选择 `experiments/warehouse_amr_jev_context.json`。
5. 在确认摘要中没有密钥、原始敏感日志或不必要的高频数据后，再点击“测试连接”。
   结果中的攻击类型、任务影响和人工复核建议属于 Jev 语义输出；防护实验室中的
   `REPLAY`、`CONTAINING`、`ISOLATE_COMPONENT` 和 `0.15 m/s` 属于 Guardian 确定性输出。
6. 需要改变场景时，点击“导入样例 JSON”上传回放文件，或复制回放 JSON，修改 `sequence`、`component`、`profile` 或事件
   时间，再次导入。`profile=no_isolation` 可验证无法隔离时是否进入 `SAFE_STOP`。

## ROS 2 闭环仿真操作

网页“防护实验室”是离线回放，适合逐步检查四条事件的判定；“工程仿真”则启动同一
仓储任务的 ROS 2 数字孪生，验证安全反馈是否真正改变运动输出。使用
`ros2 launch guardian_core guardian.launch.py` 后：

1. 在“工程仿真”点击“启动托盘任务”，观察 `DOCK_TO_PALLET`、位置增长和约
   `0.20 m/s` 的实际速度。
2. 点击“注入超速指令”。请求速度会变为 `0.62 m/s`，Guardian 收到
   `UNSAFE_COMMAND` 后进入 `CONTAINING`，发布 `ISOLATE_COMPONENT`/安全限速，页面的
   实际速度应变为 `0.00 m/s`，而请求速度仍保留 `0.62 m/s`。这证明安全反馈已经回到
   仿真节点，而不是只改变网页文本。
3. 点击“注入序列重放”，观察事件时间线中第一条接受、第二条 `REPLAY`；点击“注入抓取器故障”，观察抓取力从 `45 N` 变为 `0 N`，并在实时防护页查看右臂风险。
4. 点击“重置场景”后，仿真任务停止、位置清零、攻击模式清除；Guardian 已登记的
   攻击仍按 `max_event_age_sec`（默认 5 秒）保留，过期后安全状态才恢复到初始值。

仿真节点发布 `/cmd_vel`、`/amr_07/odom`、`/amr_07/gripper_state` 和
`guardian/sim_state`，消费 `/amr_07/sim_control`、`guardian/safety_status` 与
`guardian/mitigation_command`。它是笔记本级的确定性运动模型，不等价于 Webots 或
真实控制器；后续更换 Webots 适配器时，仍应保持 Guardian 的 `safety_status` 为最终
限速和停车边界。Jev 只用于已验证事件的语义旁路，不参与实时 ROS 2 控制。

## 研究边界

该案例可复现调度效率、来源信任、重放防护和安全状态转换，但不等价于真实机器人
认证。论文或专利实验还应接入带标签的 ROS 2/Webots 日志，测量检测延迟、误报率、
隔离成功率、Jev 请求成本和 provider 不可用时的安全保持时间。
