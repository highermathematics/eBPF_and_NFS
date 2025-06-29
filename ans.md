 系统启动示例
bash
运行
$ python nfs_monitor_loader.py -v2024-01-15 10:30:15,123 - NFSMonitor - INFO - 启动NFS eBPF监控系统2024-01-15 10:30:15,145 - NFSMonitor - INFO - 加载eBPF程序: nfs_monitor.bpf.c2024-01-15 10:30:15,892 - NFSMonitor - INFO - eBPF程序加载成功2024-01-15 10:30:15,893 - NFSMonitor - INFO - 安全策略配置完成2024-01-15 10:30:16,234 - NFSMonitor - INFO - ML服务初始化成功2024-01-15 10:30:16,235 - NFSMonitor - INFO - 用户控制台已启动2024-01-15 10:30:16,236 - NFSMonitor - INFO - 监控系统启动成功，开始处理事件...2024-01-15 10:30:16,237 - NFSMonitor - INFO - 输入 'help' 查看控制台命令╔══════════════════════════════════════════════════════════════╗║                    NFS监控系统 - 用户控制台                    ║╠══════════════════════════════════════════════════════════════╣║ 可用命令:                                                    ║║   stats     - 显示实时统计信息                               ║║   config    - 显示当前配置                                   ║║   threats   - 显示最近威胁                                   ║║   clients   - 显示活跃客户端                                 ║║   policy    - 安全策略管理                                   ║║   ml        - ML服务状态和控制                               ║║   filter    - 事件过滤设置                                   ║║   export    - 导出数据                                       ║║   reload    - 重新加载配置                                   ║║   pause     - 暂停/恢复监控                                  ║║   help      - 显示此帮助                                     ║║   quit/exit - 退出系统                                       ║╚══════════════════════════════════════════════════════════════╝NFS-Monitor> 
📊 实时事件监控示例
bash
运行
[2024-01-15 10:30:20.123456] FILE_OPEN  PID: 1234, UID: 1000, GID: 1000  文件: /export/shared/document.txt  客户端: 192.168.1.100:2049  权限掩码: 0x4[2024-01-15 10:30:21.234567] FILE_WRITE  PID: 1234, UID: 1000, GID: 1000  文件: /export/shared/document.txt  客户端: 192.168.1.100:2049  权限掩码: 0x2[2024-01-15 10:30:22.345678] XATTR_SET  PID: 1235, UID: 0, GID: 0  文件: /export/sensitive/config.conf  客户端: 192.168.1.101:2049  权限掩码: 0x8  扩展属性: security.selinux🚨 威胁告警 🚨时间: 2024-01-15T10:30:22.456789严重程度: HIGH事件类型: XATTR_SET客户端: 192.168.1.101风险分数: 0.85威胁类型: privilege_escalation, suspicious_xattr2024-01-15 10:30:22,456 - NFSMonitor - WARNING - 检测到威胁: {"timestamp": "2024-01-15T10:30:22.456789", "event": {...}, "ml_analysis": {...}, "severity": "HIGH"}
🎛️ 用户控制台交互示例
查看统计信息
bash
运行
NFS-Monitor> stats============================================================                    NFS监控系统 - 详细统                    计                    ============================================================运行时间: 300.5 秒处理事件数: 1,247 ML预测数: 1,247威胁检测数: 23事件处理速率: 4.15 事件/秒威胁检测率: 1.84%ML服务状态:  模型状态: 运行中  训练样本数: 15,432  模型准确率: 94.50%============================================================
查看活跃客户端
bash
运行
NFS-Monitor> clients活跃客户端:192.168.1.100: 856 事件, 最后活动: 2024-01-15T10:35:15.123456192.168.1.101: 234 事件, 最后活动: 2024-01-15T10:35:10.987654192.168.1.102: 157 事件, 最后活动: 2024-01-15T10:34:58.45678910.0.0.50: 45 事件, 最后活动: 2024-01-15T10:33:22.111222
查看最近威胁
bash
运行
NFS-Monitor> threats 5最近 5 个威胁:1. [2024-01-15T10:35:12.123456] HIGH - EXEC_CHECK   客户端: 192.168.1.101   风险分数: 0.922. [2024-01-15T10:34:45.234567] MEDIUM - FILE_DELETE   客户端: 192.168.1.100   风险分数: 0.733. [2024-01-15T10:33:28.345678] HIGH - XATTR_SET   客户端: 192.168.1.101   风险分数: 0.854. [2024-01-15T10:32:15.456789] MEDIUM - PERMISSION_DENIED   客户端: 10.0.0.50   风险分数: 0.685. [2024-01-15T10:30:22.567890] HIGH - MOUNT   客户端: 192.168.1.102   风险分数: 0.89
安全策略管理
bash
运行
NFS-Monitor> policy show当前安全策略:  enable_access_control: 1  enable_xattr_protection: 1  enable_exec_control: 1  enable_mount_control: 1  strict_mode: 0  log_level: 2NFS-Monitor> policy set strict_mode 1策略 strict_mode 已设置为 1
ML服务控制
bash
运行
NFS-Monitor> ml statusML服务状态: 运行中异常阈值: 0.7训练样本数: 15432NFS-Monitor> ml threshold 0.8异常阈值已设置为 0.8NFS-Monitor> ml retrain开始重新训练模型...模型重新训练完成
事件过滤管理
bash
运行
NFS-Monitor> filter add FILE_READ已添加过滤: FILE_READNFS-Monitor> filter show当前过滤事件类型: FILE_READNFS-Monitor> filter remove FILE_READ已移除过滤: FILE_READ
数据导出
bash
运行
NFS-Monitor> export threats威胁数据已导出到: nfs_threats_20240115_103520.jsonNFS-Monitor> export stats统计数据已导出到: nfs_stats_20240115_103525.json
📈 定期统计报告示例
bash
运行
=== 运行统计 (运行时间: 1800.3秒) ===处理事件数: 7,892 ML预测数: 7,892威胁检测数: 156事件处理速率: 4.38 事件/秒
🔧 测试模式示例
bash
运行
$ python nfs_monitor_loader.py --test测试模式 - 验证配置和依赖✓ eBPF程序文件存在: nfs_monitor.bpf.c✓ ML服务模块可用配置: {  "ebpf_program": "nfs_monitor.bpf.c",  "ml_service": {    "enabled": true,    "model_path": "./models/",    "training_interval": 3600,    "anomaly_threshold": 0.7  },  "security_policy": {    "enable_access_control": 1,    "enable_xattr_protection": 1,    "enable_exec_control": 1,    "enable_mount_control": 1,    "strict_mode": 0,    "log_level": 2  },  "monitoring": {    "event_buffer_size": 10240,    "poll_timeout": 1000,    "stats_interval": 30  },  "output": {    "log_file": "/var/log/nfs_monitor.log",    "json_output": true,    "console_output": true  },  "console": {    "enabled": true,    "prompt": "NFS-Monitor> "  }}
🚨 高级威胁检测示例
bash
运行
[2024-01-15 10:45:33.789012] EXEC_CHECK  PID: 2468, UID: 0, GID: 0  文件: /export/bin/suspicious_script.sh  客户端: 192.168.1.101:2049  权限掩码: 0x1🚨 威胁告警 🚨时间: 2024-01-15T10:45:33.890123严重程度: HIGH事件类型: EXEC_CHECK客户端: 192.168.1.101风险分数: 0.94威胁类型: malware_execution, privilege_escalation, suspicious_binary[2024-01-15 10:46:15.123456] MOUNT  PID: 3579, UID: 1001, GID: 1001  文件: /export/restricted/  客户端: 10.0.0.99:2049  权限掩码: 0x20  目标路径: /mnt/external_device  挂载标志: 0x8000🚨 威胁告警 🚨时间: 2024-01-15T10:46:15.234567严重程度: HIGH事件类型: MOUNT客户端: 10.0.0.99风险分数: 0.88威胁类型: unauthorized_mount, data_exfiltration, suspicious_device
📊 JSON格式日志示例
json

{  "pid": 1234,  "uid": 1000,  "gid": 1000,  "event_type": 3,  "event_type_name": "FILE_WRITE",  "timestamp": 1705304421234567890,  "filename": "/export/shared/document.txt",  "file_size": 2048,  "access_mode": 2,  "permission_mask": 2,  "client_ip": "192.168.1.100",  "client_port": 2049,  "inode_number": 123456,  "file_mode": 33188,  "parent_inode": 123400,  "xattr_name": "",  "target_path": "",  "mount_flags": 0,  "security_flags": 0}
🔄 系统优雅关闭示例
bash
运行
NFS-Monitor> quit正在退出系统...2024-01-15 10:50:15,123 - NFSMonitor - INFO - 接收到信号 2，正在停止...2024-01-15 10:50:15,124 - NFSMonitor - INFO - 用户控制台已停止=== 运行统计 (运行时间: 1200.8秒) ===处理事件数: 5,234 ML预测数: 5,234威胁检测数: 98事件处理速率: 4.36 事件/秒2024-01-15 10:50:15,456 - NFSMonitor - INFO - 监控系统已停止
这些示例展示了NFS eBPF监控系统的完整运行流程，包括启动、实时监控、威胁检测、用户交互和系统管理等各个方面的功能。
