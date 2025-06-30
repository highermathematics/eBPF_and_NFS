#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NFS eBPF监控系统用户态加载器
集成eBPF程序加载、ML服务管理和实时监控功能
"""

import os
import sys
import time
import json
import signal
import struct
import socket
import threading
import subprocess
import select
from datetime import datetime
from ctypes import *
from bcc import BPF
import argparse
import logging
from pathlib import Path

# 导入ML服务
from ml_service import NFSSecurityMLService

class NFSMonitorLoader:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.bpf = None
        self.ml_service = None
        self.running = False
        self.console_enabled = False
        self.console_thread = None
        self.monitoring_paused = False
        
        # 统计信息
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'ml_predictions': 0,
            'start_time': None
        }
        
        # 客户端统计
        self.client_stats = {}
        
        # 威胁记录
        self.recent_threats = []
        
        # 事件过滤
        self.event_filters = set()
        
        # 事件类型映射
        self.event_types = {
            1: 'FILE_OPEN', 2: 'FILE_READ', 3: 'FILE_WRITE', 4: 'FILE_DELETE',
            5: 'PERMISSION_DENIED', 6: 'INODE_PERMISSION', 7: 'FILE_PERMISSION',
            8: 'SETATTR', 9: 'XATTR_SET', 10: 'XATTR_GET', 11: 'LINK_CREATE',
            12: 'RENAME', 13: 'MKDIR', 14: 'RMDIR', 15: 'CREATE',
            16: 'MOUNT', 17: 'REMOUNT', 18: 'STATFS', 19: 'MMAP',
            20: 'MPROTECT', 21: 'EXEC_CHECK', 22: 'CRED_CHANGE'
        }
        
    def load_config(self, config_file):
        """加载配置文件"""
        default_config = {
            'ebpf_program': 'nfs_monitor.bpf.c',
            'ml_service': {
                'enabled': True,
                'model_path': './models/',
                'training_interval': 3600,
                'anomaly_threshold': 0.7
            },
            'security_policy': {
                'enable_access_control': 1,
                'enable_xattr_protection': 1,
                'enable_exec_control': 1,
                'enable_mount_control': 1,
                'strict_mode': 0,
                'log_level': 2
            },
            'monitoring': {
                'event_buffer_size': 10240,
                'poll_timeout': 1000,
                'stats_interval': 30
            },
            'output': {
                'log_file': '/var/log/nfs_monitor.log',
                'json_output': True,
                'console_output': True
            },
            'console': {
                'enabled': True,
                'prompt': 'NFS-Monitor> '
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"配置文件加载失败: {e}，使用默认配置")
                
        return default_config
    
    def setup_logging(self):
        """设置日志系统"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # 确保日志目录存在
        log_file = self.config['output']['log_file']
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('NFSMonitor')
        
    def load_ebpf_program(self):
        """加载eBPF程序"""
        try:
            # 检查eBPF程序文件
            ebpf_file = self.config['ebpf_program']
            if not os.path.exists(ebpf_file):
                raise FileNotFoundError(f"eBPF程序文件不存在: {ebpf_file}")
            
            self.logger.info(f"加载eBPF程序: {ebpf_file}")
            
            # 读取eBPF程序源码
            with open(ebpf_file, 'r') as f:
                bpf_text = f.read()
            
            # 编译并加载eBPF程序
            self.bpf = BPF(text=bpf_text)
            
            # 配置安全策略
            self.configure_security_policy()
            
            # 启用ML开关
            if self.config['ml_service']['enabled']:
                ml_switch = self.bpf["ml_switch_map"]
                ml_switch[c_uint32(0)] = c_uint32(1)
                
            self.logger.info("eBPF程序加载成功")
            return True
            
        except Exception as e:
            self.logger.error(f"eBPF程序加载失败: {e}")
            return False
    
    def configure_security_policy(self):
        """配置安全策略"""
        try:
            policy_map = self.bpf["security_policy_map"]
            policy = self.config['security_policy']
            
            # 创建策略结构
            policy_struct = struct.pack('IIIIII',
                policy['enable_access_control'],
                policy['enable_xattr_protection'], 
                policy['enable_exec_control'],
                policy['enable_mount_control'],
                policy['strict_mode'],
                policy['log_level']
            )
            
            policy_map[c_uint32(0)] = policy_struct
            self.logger.info("安全策略配置完成")
            
        except Exception as e:
            self.logger.error(f"安全策略配置失败: {e}")
    
    def initialize_ml_service(self):
        """初始化ML服务"""
        if not self.config['ml_service']['enabled']:
            self.logger.info("ML服务已禁用")
            return True
            
        try:
            self.ml_service = NFSSecurityMLService(
                model_path=self.config['ml_service']['model_path'],
                anomaly_threshold=self.config['ml_service']['anomaly_threshold']
            )
            
            # 启动ML服务
            self.ml_service.start()
            self.logger.info("ML服务初始化成功")
            return True
            
        except Exception as e:
            self.logger.error(f"ML服务初始化失败: {e}")
            return False
    
    def parse_event(self, cpu, data, size):
        """解析eBPF事件"""
        try:
            # 解析事件结构 (简化版本)
            event_data = struct.unpack('IIIIQI256sIIIHIH64s256sII', data[:600])
            
            event = {
                'pid': event_data[0],
                'uid': event_data[1], 
                'gid': event_data[2],
                'event_type': event_data[3],
                'timestamp': event_data[4],
                'filename': event_data[6].decode('utf-8', errors='ignore').rstrip('\x00'),
                'file_size': event_data[7],
                'access_mode': event_data[8],
                'permission_mask': event_data[9],
                'client_ip': socket.inet_ntoa(struct.pack('I', event_data[10])),
                'client_port': event_data[11],
                'inode_number': event_data[12],
                'file_mode': event_data[13],
                'parent_inode': event_data[14],
                'xattr_name': event_data[15].decode('utf-8', errors='ignore').rstrip('\x00'),
                'target_path': event_data[16].decode('utf-8', errors='ignore').rstrip('\x00'),
                'mount_flags': event_data[17],
                'security_flags': event_data[18]
            }
            
            # 添加事件类型名称
            event['event_type_name'] = self.event_types.get(event['event_type'], 'UNKNOWN')
            
            # 处理事件
            self.process_event(event)
            
        except Exception as e:
            self.logger.error(f"事件解析失败: {e}")
    
    def process_event(self, event):
        """处理单个事件"""
        # 检查是否暂停监控
        if self.monitoring_paused:
            return
            
        # 检查事件过滤
        if event['event_type_name'] in self.event_filters:
            return
            
        self.stats['events_processed'] += 1
        
        # 更新客户端统计
        client_ip = event['client_ip']
        if client_ip not in self.client_stats:
            self.client_stats[client_ip] = {'events': 0, 'last_seen': None}
        
        self.client_stats[client_ip]['events'] += 1
        self.client_stats[client_ip]['last_seen'] = datetime.now().isoformat()
        
        # 输出到控制台
        if self.config['output']['console_output']:
            self.print_event(event)
        
        # ML分析
        if self.ml_service:
            try:
                result = self.ml_service.analyze_event(event)
                self.stats['ml_predictions'] += 1
                
                if result['is_anomaly']:
                    self.stats['threats_detected'] += 1
                    self.handle_threat(event, result)
                    
            except Exception as e:
                self.logger.error(f"ML分析失败: {e}")
        
        # JSON输出
        if self.config['output']['json_output']:
            self.logger.info(json.dumps(event, default=str))
    
    def print_event(self, event):
        """格式化输出事件"""
        timestamp = datetime.fromtimestamp(event['timestamp'] / 1000000000)
        print(f"\n[{timestamp}] {event['event_type_name']}")
        print(f"  PID: {event['pid']}, UID: {event['uid']}, GID: {event['gid']}")
        print(f"  文件: {event['filename']}")
        print(f"  客户端: {event['client_ip']}:{event['client_port']}")
        print(f"  权限掩码: 0x{event['permission_mask']:x}")
        
        if event['xattr_name']:
            print(f"  扩展属性: {event['xattr_name']}")
        if event['target_path']:
            print(f"  目标路径: {event['target_path']}")
    
    def handle_threat(self, event, ml_result):
        """处理威胁事件"""
        threat_info = {
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'ml_analysis': ml_result,
            'severity': 'HIGH' if ml_result['risk_score'] > 0.8 else 'MEDIUM'
        }
        
        # 记录威胁
        self.recent_threats.append(threat_info)
        
        # 只保留最近100个威胁
        if len(self.recent_threats) > 100:
            self.recent_threats = self.recent_threats[-100:]
        
        self.logger.warning(f"检测到威胁: {json.dumps(threat_info, default=str)}")
        
        # 控制台告警
        print(f"\n🚨 威胁告警 🚨")
        print(f"时间: {threat_info['timestamp']}")
        print(f"严重程度: {threat_info['severity']}")
        print(f"事件类型: {event['event_type_name']}")
        print(f"客户端: {event['client_ip']}")
        print(f"风险分数: {ml_result['risk_score']:.2f}")
        print(f"威胁类型: {', '.join(ml_result.get('threat_types', []))}")
    
    def print_stats(self):
        """打印统计信息"""
        if self.stats['start_time']:
            runtime = time.time() - self.stats['start_time']
            print(f"\n=== 运行统计 (运行时间: {runtime:.1f}秒) ===")
            print(f"处理事件数: {self.stats['events_processed']}")
            print(f"ML预测数: {self.stats['ml_predictions']}")
            print(f"威胁检测数: {self.stats['threats_detected']}")
            if runtime > 0:
                print(f"事件处理速率: {self.stats['events_processed']/runtime:.2f} 事件/秒")
    
    def stats_thread(self):
        """统计信息线程"""
        while self.running:
            time.sleep(self.config['monitoring']['stats_interval'])
            if self.running:
                self.print_stats()
    
    def signal_handler(self, signum, frame):
        """信号处理器"""
        self.logger.info(f"接收到信号 {signum}，正在停止...")
        self.stop()
    
    # ==================== 用户控制台功能 ====================
    
    def start_console(self):
        """启动用户控制台"""
        if not self.config['console']['enabled']:
            return
            
        if not self.console_enabled:
            self.console_enabled = True
            self.console_thread = threading.Thread(target=self.console_loop, daemon=True)
            self.console_thread.start()
            self.logger.info("用户控制台已启动")
    
    def stop_console(self):
        """停止用户控制台"""
        self.console_enabled = False
        if self.console_thread:
            self.console_thread.join(timeout=1)
        self.logger.info("用户控制台已停止")
    
    def console_loop(self):
        """控制台主循环"""
        self.print_console_help()
        
        while self.console_enabled and self.running:
            try:
                # Windows系统的非阻塞输入处理
                if os.name == 'nt':  # Windows
                    import msvcrt
                    if msvcrt.kbhit():
                        command = input(self.config['console']['prompt']).strip().lower()
                        if command:
                            self.handle_console_command(command)
                    time.sleep(0.1)
                else:  # Unix-like系统
                    if sys.stdin in select.select([sys.stdin], [], [], 0.5)[0]:
                        command = input(self.config['console']['prompt']).strip().lower()
                        if command:
                            self.handle_console_command(command)
                    
            except (EOFError, KeyboardInterrupt):
                break
            except Exception as e:
                self.logger.error(f"控制台错误: {e}")
    
    def print_console_help(self):
        """打印控制台帮助信息"""
        help_text = """
╔══════════════════════════════════════════════════════════════╗
║                    NFS监控系统 - 用户控制台                    ║
╠══════════════════════════════════════════════════════════════╣
║ 可用命令:                                                    ║
║   stats     - 显示实时统计信息                               ║
║   config    - 显示当前配置                                   ║
║   threats   - 显示最近威胁                                   ║
║   clients   - 显示活跃客户端                                 ║
║   policy    - 安全策略管理                                   ║
║   ml        - ML服务状态和控制                               ║
║   filter    - 事件过滤设置                                   ║
║   export    - 导出数据                                       ║
║   reload    - 重新加载配置                                   ║
║   pause     - 暂停/恢复监控                                  ║
║   help      - 显示此帮助                                     ║
║   quit/exit - 退出系统                                       ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(help_text)
    
    def handle_console_command(self, command):
        """处理控制台命令"""
        if not command:
            return
            
        parts = command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        try:
            if cmd in ['quit', 'exit', 'q']:
                print("正在退出系统...")
                self.stop()
                
            elif cmd == 'stats':
                self.show_detailed_stats()
                
            elif cmd == 'config':
                self.show_config()
                
            elif cmd == 'threats':
                self.show_recent_threats(args)
                
            elif cmd == 'clients':
                self.show_active_clients()
                
            elif cmd == 'policy':
                self.handle_policy_command(args)
                
            elif cmd == 'ml':
                self.handle_ml_command(args)
                
            elif cmd == 'filter':
                self.handle_filter_command(args)
                
            elif cmd == 'export':
                self.handle_export_command(args)
                
            elif cmd == 'reload':
                self.reload_config()
                
            elif cmd == 'pause':
                self.toggle_monitoring()
                
            elif cmd == 'help':
                self.print_console_help()
                
            else:
                print(f"未知命令: {cmd}，输入 'help' 查看可用命令")
                
        except Exception as e:
            print(f"命令执行错误: {e}")
    
    def show_detailed_stats(self):
        """显示详细统计信息"""
        if not self.stats['start_time']:
            print("系统尚未启动")
            return
            
        runtime = time.time() - self.stats['start_time']
        
        print("\n" + "="*60)
        print(f"{'NFS监控系统 - 详细统计':^60}")
        print("="*60)
        print(f"运行时间: {runtime:.1f} 秒")
        print(f"处理事件数: {self.stats['events_processed']:,}")
        print(f"ML预测数: {self.stats['ml_predictions']:,}")
        print(f"威胁检测数: {self.stats['threats_detected']:,}")
        
        if runtime > 0:
            print(f"事件处理速率: {self.stats['events_processed']/runtime:.2f} 事件/秒")
            print(f"威胁检测率: {(self.stats['threats_detected']/max(1,self.stats['events_processed']))*100:.2f}%")
        
        # ML服务状态
        if self.ml_service:
            try:
                ml_stats = self.ml_service.get_stats()
                print(f"\nML服务状态:")
                print(f"  模型状态: {'运行中' if ml_stats.get('running') else '已停止'}")
                print(f"  训练样本数: {ml_stats.get('training_samples', 0):,}")
                print(f"  模型准确率: {ml_stats.get('accuracy', 0):.2%}")
            except:
                print(f"\nML服务状态: 无法获取详细信息")
        
        print("="*60)
    
    def show_config(self):
        """显示当前配置"""
        print("\n当前配置:")
        print(json.dumps(self.config, indent=2, ensure_ascii=False))
    
    def show_recent_threats(self, args):
        """显示最近威胁"""
        limit = int(args[0]) if args and args[0].isdigit() else 10
        
        threats = self.recent_threats[-limit:]
        if threats:
            print(f"\n最近 {len(threats)} 个威胁:")
            for i, threat in enumerate(threats, 1):
                print(f"{i}. [{threat['timestamp']}] {threat['severity']} - {threat['event']['event_type_name']}")
                print(f"   客户端: {threat['event']['client_ip']}")
                print(f"   风险分数: {threat['ml_analysis']['risk_score']:.2f}")
        else:
            print("暂无威胁记录")
    
    def show_active_clients(self):
        """显示活跃客户端"""
        if self.client_stats:
            print("\n活跃客户端:")
            for ip, stats in self.client_stats.items():
                print(f"{ip}: {stats['events']} 事件, 最后活动: {stats['last_seen']}")
        else:
            print("暂无客户端活动记录")
    
    def handle_policy_command(self, args):
        """处理安全策略命令"""
        if not args:
            print("策略命令: show | set <key> <value> | reset")
            return
            
        if args[0] == 'show':
            print("\n当前安全策略:")
            for key, value in self.config['security_policy'].items():
                print(f"  {key}: {value}")
                
        elif args[0] == 'set' and len(args) >= 3:
            key, value = args[1], args[2]
            if key in self.config['security_policy']:
                try:
                    # 尝试转换为整数
                    self.config['security_policy'][key] = int(value)
                    self.configure_security_policy()
                    print(f"策略 {key} 已设置为 {value}")
                except ValueError:
                    print(f"无效值: {value}")
            else:
                print(f"未知策略: {key}")
                
        elif args[0] == 'reset':
            # 重置为默认策略
            default_policy = {
                'enable_access_control': 1,
                'enable_xattr_protection': 1,
                'enable_exec_control': 1,
                'enable_mount_control': 1,
                'strict_mode': 0,
                'log_level': 2
            }
            self.config['security_policy'] = default_policy
            self.configure_security_policy()
            print("安全策略已重置为默认值")
    
    def handle_ml_command(self, args):
        """处理ML服务命令"""
        if not self.ml_service:
            print("ML服务未启用")
            return
            
        if not args:
            print("ML命令: status | retrain | threshold <value> | stats")
            return
            
        if args[0] == 'status':
            try:
                stats = self.ml_service.get_stats()
                print(f"\nML服务状态: {'运行中' if stats.get('running') else '已停止'}")
                print(f"异常阈值: {self.config['ml_service']['anomaly_threshold']}")
                print(f"训练样本数: {stats.get('training_samples', 0)}")
            except:
                print("\nML服务状态: 无法获取状态信息")
            
        elif args[0] == 'retrain':
            print("开始重新训练模型...")
            try:
                self.ml_service.retrain_models()
                print("模型重新训练完成")
            except Exception as e:
                print(f"模型训练失败: {e}")
            
        elif args[0] == 'threshold' and len(args) >= 2:
            try:
                threshold = float(args[1])
                if 0 <= threshold <= 1:
                    self.config['ml_service']['anomaly_threshold'] = threshold
                    if hasattr(self.ml_service, 'set_threshold'):
                        self.ml_service.set_threshold(threshold)
                    print(f"异常阈值已设置为 {threshold}")
                else:
                    print("阈值必须在 0-1 之间")
            except ValueError:
                print(f"无效阈值: {args[1]}")
                
        elif args[0] == 'stats':
            try:
                stats = self.ml_service.get_detailed_stats()
                print("\nML详细统计:")
                for key, value in stats.items():
                    print(f"  {key}: {value}")
            except:
                print("无法获取ML详细统计")
    
    def handle_filter_command(self, args):
        """处理事件过滤命令"""
        if not args:
            print("过滤命令: show | add <type> | remove <type> | clear")
            return
            
        if args[0] == 'show':
            if self.event_filters:
                print(f"当前过滤事件类型: {', '.join(self.event_filters)}")
            else:
                print("无事件过滤")
                
        elif args[0] == 'add' and len(args) >= 2:
            event_type = args[1].upper()
            if event_type in self.event_types.values():
                self.event_filters.add(event_type)
                print(f"已添加过滤: {event_type}")
            else:
                print(f"未知事件类型: {event_type}")
                print(f"可用类型: {', '.join(self.event_types.values())}")
                
        elif args[0] == 'remove' and len(args) >= 2:
            event_type = args[1].upper()
            if event_type in self.event_filters:
                self.event_filters.remove(event_type)
                print(f"已移除过滤: {event_type}")
            else:
                print(f"过滤中不存在: {event_type}")
                
        elif args[0] == 'clear':
            self.event_filters.clear()
            print("已清除所有过滤")
    
    def handle_export_command(self, args):
        """处理数据导出命令"""
        if not args:
            print("导出命令: stats | threats | config | events")
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        try:
            if args[0] == 'stats':
                filename = f"nfs_stats_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(self.stats, f, indent=2, default=str)
                print(f"统计数据已导出到: {filename}")
                
            elif args[0] == 'config':
                filename = f"nfs_config_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(self.config, f, indent=2, ensure_ascii=False)
                print(f"配置已导出到: {filename}")
                
            elif args[0] == 'threats':
                if self.recent_threats:
                    filename = f"nfs_threats_{timestamp}.json"
                    with open(filename, 'w') as f:
                        json.dump(self.recent_threats, f, indent=2, default=str, ensure_ascii=False)
                    print(f"威胁数据已导出到: {filename}")
                else:
                    print("无威胁数据可导出")
                    
        except Exception as e:
            print(f"导出失败: {e}")
    
    def reload_config(self):
        """重新加载配置"""
        try:
            old_config = self.config.copy()
            self.config = self.load_config(None)  # 重新加载默认配置
            
            # 重新配置安全策略
            if self.bpf:
                self.configure_security_policy()
            
            # 重新配置ML服务
            if self.ml_service and self.config['ml_service']['enabled']:
                if hasattr(self.ml_service, 'update_config'):
                    self.ml_service.update_config(self.config['ml_service'])
            
            print("配置重新加载成功")
            
        except Exception as e:
            self.config = old_config  # 恢复旧配置
            print(f"配置重新加载失败: {e}")
    
    def toggle_monitoring(self):
        """切换监控状态"""
        self.monitoring_paused = not self.monitoring_paused
        status = "已暂停" if self.monitoring_paused else "已恢复"
        print(f"监控 {status}")
    
    # ==================== 主要控制方法 ====================
    
    def start(self):
        """启动监控系统"""
        try:
            self.logger.info("启动NFS eBPF监控系统")
            
            # 加载eBPF程序
            if not self.load_ebpf_program():
                return False
            
            # 初始化ML服务
            if not self.initialize_ml_service():
                return False
            
            # 设置信号处理
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            # 启动统计线程
            stats_thread = threading.Thread(target=self.stats_thread, daemon=True)
            stats_thread.start()
            
            # 启动用户控制台
            self.start_console()
            
            # 开始监控
            self.running = True
            self.stats['start_time'] = time.time()
            
            self.logger.info("监控系统启动成功，开始处理事件...")
            if self.config['console']['enabled']:
                self.logger.info("输入 'help' 查看控制台命令")
            
            # 打开事件缓冲区
            self.bpf["events"].open_perf_buffer(
                self.parse_event,
                page_cnt=64
            )
            
            # 主循环
            while self.running:
                try:
                    self.bpf.perf_buffer_poll(timeout=self.config['monitoring']['poll_timeout'])
                except KeyboardInterrupt:
                    break
                    
            return True
            
        except Exception as e:
            self.logger.error(f"启动失败: {e}")
            return False
    
    def stop(self):
        """停止监控系统"""
        self.running = False
        
        # 停止控制台
        self.stop_console()
        
        if self.ml_service:
            self.ml_service.stop()
            
        self.print_stats()
        self.logger.info("监控系统已停止")

def main():
    parser = argparse.ArgumentParser(description='NFS eBPF监控系统')
    parser.add_argument('-c', '--config', help='配置文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('--test', action='store_true', help='测试模式')
    parser.add_argument('--no-console', action='store_true', help='禁用控制台')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 创建监控器
    monitor = NFSMonitorLoader(args.config)
    
    # 禁用控制台选项
    if args.no_console:
        monitor.config['console']['enabled'] = False
    
    if args.test:
        print("测试模式 - 验证配置和依赖")
        print(f"配置: {json.dumps(monitor.config, indent=2, ensure_ascii=False)}")
        
        # 测试eBPF程序文件
        ebpf_file = monitor.config['ebpf_program']
        if os.path.exists(ebpf_file):
            print(f"✓ eBPF程序文件存在: {ebpf_file}")
        else:
            print(f"✗ eBPF程序文件不存在: {ebpf_file}")
        
        # 测试ML服务
        if monitor.config['ml_service']['enabled']:
            try:
                from ml_service import NFSSecurityMLService
                print("✓ ML服务模块可用")
            except ImportError as e:
                print(f"✗ ML服务模块导入失败: {e}")
        
        return
    
    # 启动监控
    try:
        monitor.start()
    except Exception as e:
        print(f"启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()