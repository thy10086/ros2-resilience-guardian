# 第九轮：冻结反馈的新缺陷验证与真实 DDS 审计

本轮接续第八轮的两个未决问题：持续健康反馈的收益是否能迁移到未参与其设计的新受控缺陷，以及同一断言能否读取并留存真实ROS 2消息闭环的审计轨迹。用户选择先使用已有三进程软件AMR闭环，因此轨迹来源明确为自有真实DDS实验；没有将它标为外部机器人数据或物理安全验证。

## 复用与扩展范围

沿用已安装的Hypothesis 6.168.5、原18动作/10时长/32动作策略、同一SafetyOracle、现有holdout时间预算和重放框架。新增缺陷只通过唯一站点AST变体生成独立离线类。ROS轨迹继续使用官方[launch_testing](https://docs.ros.org/en/ros2_packages/iron/api/launch_testing/)及已有AuditLogger、RecoveryFrame与dashboard_recovery.inspect_recovery_trace；不另写进程编排器或安全断言。

已查阅ROS官方[rosbag2 Python读取示例](https://github.com/ros2/ros2_documentation/blob/rolling/source/ROS-Framework/client-libraries/Working-with-Client-Libraries/Reading-From-A-Bag-File-Python.rst)。现有RecoveryFrame包含许可签发/消费、账本和精确上下文等专用字段，而当前ROS包未发布携带完整审计帧的topic，因此本轮保留现有JSONL审计，不从普通里程计/激光记录推测这些字段。

## 先冻结，再独立选型

在委派缺陷选型前，保存 `experiments/results/recovery_transfer_preregistration/protocol.json` 与四份目标/策略/Oracle源码快照，锁定第八轮完整报告SHA。独立只读审查只读取生产恢复代码、Oracle、原七族及动作模型，未读取反馈目标实现或实验结果。其选型另存 `defect_selection.json`；预登记未在选型后改写。

正式验证固定为seeds60..79、unguided/liveness两模式、每组5秒、上限10000次，共40组200秒名义预算。两组都采集相同的健康反馈，只有liveness优化新两标签；不混用前批种子，也不据结果改变默认。模式按种子位置轮换，缺陷探测按seed加输入索引轮换；计时、在途输入软超时、预算外发现排除、未检出按5秒截尾和配对聚合都复用原入口。

独立审查发现预登记最初未直接约束实际campaign driver。修复通过红绿回归后，登记校验利用已锁定的第八轮报告SHA，额外逐一对照11份保留源，包括真实输入分布、Hypothesis阶段/目标分派和控制模型。唯一允许改变的前批源是用于接入新缺陷集的runner。登记、选型、前批报告均复制到新目录，并在各组前及收尾检查原文件/快照SHA；本轮全部运行源再冻结为13份源码及对应快照。

这证明本轮沿用冻结目标和输入模型，并新增独立选定的受控缺陷；它仍处于自有输入模型内，不构成外部盲测。登记时间是本地工作流记录，不是第三方时间戳认证。

| 新缺陷族 | 唯一修改 | 资格见证 | 现有断言 |
| --- | --- | --- | --- |
| no_motion_envelope | 删除update中motion.mission_allowed失败后的停车分支 | near_obstacle(.3) | unsafe_candidate、unsafe_motion |
| nonzero_safe_stop_limit | _stop返回的速度上限0.0改为.2 | graph_missing(.01) | invalid_speed_limit |

两个资格见证在完整生产控制上均无违规。第一族保持准确的独立近障碍证据，却忽略包络拒绝；变体可能仍发布零上限，不能由任务授权错误推断发生碰撞。第二族保持mission_allowed=False及许可撤销，但破坏停车输出契约，不能据此推断执行器实际运动。它们与前七族不同，也无需新增动作或Oracle条件。

## 正式对照结果

40组全部完成并以wall_time停止，没有触及执行上限，等时间比较有效。共生成29,134个候选执行，完整机制违规0；82个资格/首次检出反例与40个corpus重放一致，源码及预登记验证通过。独立审查另外逐份复算40报告和全部配对统计、重放82反例及40语料内7,966个保存输入，结果一致。名义200秒预算的实际搜索计时201.391秒，累计在途输入尾部1.391秒，最大单组68.9毫秒；预算外发现0。

| 模式 | 包络拒绝缺陷 | 非零停车上限缺陷 | 每组生成中位数 | 转移覆盖中位数 | 最长健康窗口中位数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| unguided | 20/20 | 20/20 | 951 | 534 | 2.950秒 |
| liveness | 20/20 | 20/20 | 529 | 313 | 6.000秒 |

两组各族检出率的Wilson 95%描述性区间均为[83.9%, 100%]，同种子配对检出差均为0。包络族首检时间中位数为unguided 0.07064秒、liveness 0.05782秒，但配对截尾差（liveness减unguided）中位数仅-0.000234秒；停车上限族为0.01309/0.01336秒，配对差中位数+0.000071秒。此批早期检出已饱和，毫秒内的配对差不能支持效率优势。

新目标确实拉长了正确轨迹健康窗口，但没有提高这两类新缺陷的检出率，生成吞吐和广泛转移覆盖反而下降。第八轮的16/20停滞检出收益不能推广为所有安全缺陷上的全面收益。本轮保留默认模式，下一步应引入外部来源轨迹、更多独立缺陷和长预算重复实验；已有DDS间歇启动问题也不能由一次成功采集认定已根治。

原始统计和全部产物在 `experiments/results/recovery_transfer_validation/`，日志为 `output/recovery-transfer-validation.log`。正式登记、独立选型和第八轮报告的精确副本也在该目录。复现沿用同一登记并另选不存在的输出目录：

```bash
output/recovery-fuzz-venv/bin/python experiments/run_recovery_holdout.py \
  --defect-suite transfer \
  --preregistration experiments/results/recovery_transfer_preregistration/protocol.json \
  --seeds 60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79 \
  --modes unguided,liveness --wall-time-sec 5 --execution-cap 10000 \
  --output-dir experiments/results/recovery_transfer_reproduction
```

## 真实 ROS 2 轨迹留存结果

`GUARDIAN_RECOVERY_ARTIFACT_DIR`可选启用新产物目录。已有三进程launch test完成后，在post_shutdown阶段读取原始审计，原字节以排他创建保存；随后验证源码与快照、安装入口/已解析模块以及同一Oracle。失败也先保留原始证据。目录、审计与检测结果都拒绝覆盖；发现日志轮转时保留轮转文件并拒绝将单段日志当成完整轨迹。

2026-10-13正式采集：CLI退出0，19个验收场景通过，三个子进程正常退出。停止后审计共271帧、265,876字节；同一Oracle发现0违规和0采样空窗。保存输入SHA256为 `02d3c08c2dd8ab7a5aadc676a3ae0c10406dff317549f8f03e729209f8343278`。独立CLI用该哈希再次导入原文件，得到相同271帧和零违规结果。

本次单次测量的启动至运动为3.0828秒、攻击至观测零速0.2000秒、观察进程重启至运动3.6001秒。传感器来自软件AMR模型，共491条独立观察消息；这些时间是该软件闭环的观测值，不是实机最坏延迟。

采集协议保存12份仓库/实验源码快照，并记录ROS安装prefix、三个入口及九个已解析核心模块SHA。解析使用入口shebang解释器、入口目录和继承环境，逐模块匹配仓库版本，再于停机后检查文件未漂移。它是启动前来源解析及文件前后核验，未追踪子进程每次实际import，也未冻结全部解释器/ROS依赖。

产物在 `experiments/results/recovery_ros_trace_validation/`：`capture_protocol.json`、`acceptance.json`、原始`audit.jsonl`、`inspection.json`与`replayed_inspection.json`；控制台日志在 `output/recovery-ros-trace-validation.log`。默认不提供该环境变量时，原测试临时审计清理及默认报告入口保留。

## 有界导入接口

新增 `experiments/inspect_recovery_audit.py`接受帧数组、含frames的JSON封装或kind=recovery_trace的混合审计JSONL。它读取最多2MiB，复用已有2000帧/字段检查；坏JSONL、重复键、非有限常量和预期SHA不匹配都拒绝，不跳过坏行、不排序或重写时间。输入中自行声明的认证/物理安全字段不提升报告证据范围。

SHA仅固定字节身份；`source.kind`是来源声明，`authenticated=False`，`physical_safety_validated=False`。结果只说明提交轨迹是否触发现有断言；外部日志还需要可靠的来源和完整单会话记录。

```bash
source /opt/ros/humble/setup.bash
source install/humble/setup.bash
# 另选一个不存在的目录，保留正式批次。
GUARDIAN_RECOVERY_ARTIFACT_DIR=experiments/results/recovery_ros_trace_reproduction \
  launch_test experiments/independent_observation_launch_test.py

output/recovery-fuzz-venv/bin/python experiments/inspect_recovery_audit.py \
  --input experiments/results/recovery_ros_trace_validation/audit.jsonl \
  --output experiments/results/recovery_ros_trace_validation/another-inspection.json \
  --source-kind self_ros_dds \
  --expected-sha256 02d3c08c2dd8ab7a5aadc676a3ae0c10406dff317549f8f03e729209f8343278
```

发现违规时CLI保存检测结果并退出1；非法输入或输出已存在时退出2。`another-inspection.json`也必须不存在，数据本身不会被执行或发送给ROS/Jev。

## 回归验收

新增22项测试，覆盖导入身份/证据边界、无静默坏行、轮转拒绝、源码/快照漂移、实际安装来源、唯一缺陷站点、默认集兼容及预登记driver遗漏的红绿修复。最终全量696 passed/58.04s；experiments和guardian_core的compileall通过。独立复核确认DDS原始1,058行、271恢复帧和两个检测报告一致，源码/安装文件及所有实验产物快照吻合。该轮未修改生产恢复代码或系统服务，也未提交/推送。
