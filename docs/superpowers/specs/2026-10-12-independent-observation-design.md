# 第二轮：多进程与独立观测

用户已批准继续执行上一轮建议的第二轮范围。保留现有未提交工作，在当前 codex/evidence-bound-recovery 分支增量实现；不提交、部署服务或连接机器人。

## 方案与边界

选择独立 rclpy 观测节点读取现有 Odometry 和新增 LaserScan，配合 launch_testing 启动三个独立进程。直接把适配器报告搬到另一个进程不足以交叉验证；本轮另行计算速度和净距。完整 Gazebo/实机集成需要额外模型与环境，留到后续阶段。

复用 ROS 2 官方 launch_testing/launch_testing_ros、标准 nav_msgs/Odometry 和 sensor_msgs/LaserScan、rclpy 传感器 QoS、项目现有反馈 HMAC、恢复门控和图发现。只实现本项目的观测校验和关联，不复制通用进程管理或消息定义。

开源查阅：
- https://github.com/ros2/launch_ros/blob/humble/launch_testing_ros/test/examples/talker_listener_launch_test.py （Apache-2.0，多进程测试与清理）
- https://github.com/ros2/common_interfaces/blob/humble/nav_msgs/msg/Odometry.msg （标准里程计接口）
- https://github.com/ros2/common_interfaces/blob/humble/sensor_msgs/msg/LaserScan.msg （标准激光接口与距离有效范围）

## 数据链

适配器继续提供签名停车 ACK、攻击/旧命令/探测状态。recovery_observer 只读取标准里程计、激光扫描和签名命令，输出单独密钥认证的 IndependentObservation。报告包含发布时刻、原始两路采集时刻、命令 epoch/传输号、递增观测序号、速度、净距和有效性。独立观测不能解除来源告警；通用 IDS 解除协议不在本轮。

观测节点拒绝非有限速度、无有效扫描、错误坐标系、源时间过期/未来/倒退或重复、两路不同步。不得给缓存数据换新采集时刻；命令 epoch 变化立即清空缓存。使用前向扫描最小有效距离，不把无回波当作健康证据。静止时仍要求新的传感器样本。

Guardian 在 independent_observation_required=true 时强制需要单独 GUARDIAN_OBSERVATION_SECRET、启用证据绑定且具备原认证配置；无配置锁存停车。验证观测签名、身份、epoch、传输号、序号、源与接收时效。融合证据需要两路都新鲜、适配器与里程计速度相差不超过 0.03m/s。有效速度使用较大值，净距使用独立扫描；源时间与接收时间均晚于最近告警才能解除仿真来源。epoch 变化清空两路缓存。

验证中发现异步报告跨采样周期比较会误停车，因此适配器报告与里程计使用同一采集时刻，Guardian 用各最多8项有界缓存关联同拍数据（时间容差1微秒）。新完整配对矛盾立即阻断，不能退回旧健康配对；等待下一拍期间也不延长原有效期。方向覆盖限定前进平面 AMR，拒绝倒车/侧移/旋转。观测器重启使用签名随机启动会话与新唯一图 GID 重建水位；退休会话上限64，耗尽锁存停车。Humble 回调不提供报文来源元数据，不声称逐报文 GID 认证。

观测所需 raw 话题与报告端点加入许可图指纹；未知/额外发布者、丢失端点或重启改变恢复上下文。DDS 名称/GID 不构成密码学身份，原始传感器数据仍需生产 DDS 权限保护。

## 仿真与兼容

软件 AMR 增加由当前位置和场景障碍位置计算的前向激光距离。实验可控制传感器暂停、过期、无效、速度矛盾和障碍距离，以验证阻断与修复后的新许可。此场景不新增物理引擎，不声称独立物理传感器。原有单源第一轮模式保留；第二轮通过专用 launch 文件启用，缺少独立观测不会退回第一轮。

## 验收

1. 单元测试先失败再实现：无样本/过期/重放/异步/非有限/无效距离/epoch 清空和签名域隔离。
2. ROS 集成检查双路交叉核验、旧观测不解除新事件、缺失密钥和图变化停车。
3. launch_testing 实际启动 Guardian、执行器、观测器独立进程；检查健康恢复、攻击停车、reset 恢复、观测暂停、过期与重放、速度矛盾、近障碍、恢复修复及报告端点变化。验证进程退出码，生成机器可读报告。
4. 全量回归、Humble 构建、独立代码审查、更新说明与交接。所有延迟只报告软件测量，不外推实机制动。
