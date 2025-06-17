#!/usr/bin/env python3
from bcc import BPF
import ctypes
import time
import argparse
import os
import signal
import threading
import select
import sys
import json
from ml_service import ThreatDetector, OPERATION_OPEN, OPERATION_READ, OPERATION_WRITE, OPERATION_UNLINK, OPERATION_SETATTR

# 特征数据结构
class MLFeature(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_ulonglong),
        ("inode", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("gid", ctypes.c_uint),
        ("operation", ctypes.c_uint),
        ("access_flags", ctypes.c_uint),
        ("file_size", ctypes.c_uint),
        ("mode", ctypes.c_uint),
        ("parent_inode", ctypes.c_ulonglong),
        ("session_id", ctypes.c_ulonglong),
        ("filename", ctypes.c_char * 256),
        ("client_ip", ctypes.c_char * 16),
        ("process_name", ctypes.c_char * 16),
        ("username", ctypes.c_char * 32),
        ("full_path", ctypes.c_char * 512)
    ]

# 拦截规则结构
class BlockRule(ctypes.Structure):
    _fields_ = [
        ("inode", ctypes.c_ulonglong),
        ("operation", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("expire_time", ctypes.c_ulonglong)
    ]

class MLService(threading.Thread):
    def __init__(self, bpf, model_path='threat_model.onnx'):
        super().__init__(daemon=True)
        self.bpf = bpf
        self.running = True
        self.detector = ThreatDetector(model_path)
        self.block_rules = bpf["block_rules"]
        self.stats = {
            "total_events": 0,
            "ml_events_processed": 0,
            "anomalies_detected": 0,
            "rules_added": 0
        }
        
    def run(self):
        print("ML服务已启动")
        while self.running:
            try:
                # 处理ML特征事件
                self.bpf["ml_events"].ring_buffer_consume(self.process_ml_event)
                time.sleep(0.01)
            except Exception as e:
                print(f"ML服务错误: {str(e)}")
    
    def process_ml_event(self, cpu, data, size):
        """处理ML特征事件"""
        self.stats["total_events"] += 1
        event = MLFeature.from_buffer_copy(data)
        
        # 转换为字典格式
        event_dict = {
            name: getattr(event, name) for name, _ in MLFeature._fields_
        }
        event_dict["filename"] = event_dict["filename"].decode(errors='ignore')
        event_dict["client_ip"] = event_dict["client_ip"].decode(errors='ignore')
        event_dict["process_name"] = event_dict["process_name"].decode(errors='ignore')
        event_dict["username"] = event_dict["username"].decode(errors='ignore')
        event_dict["full_path"] = event_dict["full_path"].decode(errors='ignore')
        
        # 检测威胁
        is_threat, reason = self.detector.detect_threat(event_dict)
        if is_threat:
            self.stats["anomalies_detected"] += 1
            self.stats["ml_events_processed"] += 1
            
            # 添加拦截规则
            rule = BlockRule()
            rule.inode = event.inode
            rule.operation = event.operation
            rule.flags = BLOCK_RULE_TEMPORARY
            rule.expire_time = event.timestamp + (3600 * 1000000000)  # 1小时
            
            # 更新eBPF map
            self.block_rules[ctypes.pointer(rule)] = ctypes.c_uint8(1)
            self.stats["rules_added"] += 1
            
            # 打印警报
            op_map = {
                OPERATION_OPEN: "OPEN",
                OPERATION_READ: "READ",
                OPERATION_WRITE: "WRITE",
                OPERATION_UNLINK: "UNLINK",
                OPERATION_SETATTR: "SETATTR"
            }
            operation = op_map.get(event.operation, "UNKNOWN")
            
            ts_sec = event.timestamp // 1000000000
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts_sec))
            
            print(f"\n\033[91m[安全警报] {timestamp} {operation} {event_dict['full_path']}\033[0m")
            print(f"  原因: {reason}")
            print(f"  进程: {event_dict['process_name']}({event.pid}), 用户: {event_dict['username']}")
            print(f"  客户端: {event_dict['client_ip']}, 大小: {event.file_size}字节")
            print(f"  添加临时拦截规则: inode={event.inode}, 操作={operation}")
    
    def stop(self):
        self.running = False
        print("ML服务已停止")
        
    def get_stats(self):
        return self.stats

def handle_base_event(cpu, data, size):
    """处理基础事件"""
    event = MLFeature.from_buffer_copy(data)
    
    ts_sec = event.timestamp // 1000000000
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts_sec))
    
    op_map = {
        OPERATION_OPEN: "OPEN",
        OPERATION_READ: "READ",
        OPERATION_WRITE: "WRITE",
        OPERATION_UNLINK: "UNLINK",
        OPERATION_SETATTR: "SETATTR"
    }
    operation = op_map.get(event.operation, "UNKNOWN")
    
    print(f"[基础事件] {timestamp} {operation} {event.filename.decode(errors='ignore')}")

def set_ml_switch(bpf, enabled):
    """设置ML开关状态"""
    key = ctypes.c_uint32(0)
    value = ctypes.c_uint32(1 if enabled else 0)
    
    ml_switch = bpf["ml_switch"]
    ml_switch[ctypes.pointer(key)] = ctypes.pointer(value)
    
    status = "开启" if enabled else "关闭"
    print(f"ML功能已{status}")

def signal_handler(sig, frame):
    """处理信号"""
    print("\n接收到终止信号, 清理资源...")
    if 'ml_service' in globals() and ml_service.is_alive():
        ml_service.stop()
        ml_service.join()
    if 'bpf' in globals():
        bpf.cleanup()
    exit(0)

def print_stats(ml_service):
    """打印统计信息"""
    stats = ml_service.get_stats()
    print("\n\033[94m===== 系统统计 =====\033[0m")
    print(f"总事件数: {stats['total_events']}")
    print(f"ML处理事件: {stats['ml_events_processed']}")
    print(f"检测异常: {stats['anomalies_detected']}")
    print(f"添加规则: {stats['rules_added']}")
    
    # 打印ML模型统计
    ml_stats = ml_service.detector.stats
    print(f"\n\033[94m===== ML模型统计 =====\033[0m")
    print(f"总事件数: {ml_stats['total_events']}")
    print(f"异常事件数: {ml_stats['anomalies_detected']}")
    if ml_stats['last_anomaly']:
        print(f"最后异常时间: {ml_stats['last_anomaly']}")

def interactive_control(bpf, ml_service):
    """交互式控制界面"""
    print("\n交互命令:")
    print("  m: 切换ML功能开关")
    print("  s: 显示统计信息")
    print("  t: 训练新模型")
    print("  r: 重置所有拦截规则")
    print("  q: 退出")
    
    while True:
        # 检查用户输入
        rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
        if rlist:
            cmd = sys.stdin.readline().strip().lower()
            
            if cmd == 'm':
                # 切换ML开关
                key = ctypes.c_uint32(0)
                ml_switch = bpf["ml_switch"]
                current_state = ml_switch[key].value
                new_state = not current_state
                set_ml_switch(bpf, new_state)
                
            elif cmd == 's':
                # 显示统计信息
                print_stats(ml_service)
                
            elif cmd == 't':
                # 训练新模型
                print("启动模型训练...")
                success = ml_service.detector.train_new_model()
                if success:
                    print("模型训练完成，重新加载...")
                    ml_service.detector.load_model()
                
            elif cmd == 'r':
                # 重置拦截规则
                block_rules = bpf["block_rules"]
                keys = []
                for k, _ in block_rules.items():
                    keys.append(k)
                for k in keys:
                    del block_rules[k]
                print("已重置所有拦截规则")
                
            elif cmd == 'q':
                # 退出
                signal_handler(signal.SIGINT, None)
                
        # 消费基础事件缓冲区
        bpf.ring_buffer_consume()

def main():
    global bpf, ml_service
    
    # 命令行参数
    parser = argparse.ArgumentParser(description='NFS安全监控系统')
    parser.add_argument('--ml', choices=['on', 'off'], default='on', 
                        help='ML功能开关 (默认: on)')
    parser.add_argument('--model', default='threat_model.onnx', 
                        help='ML模型文件路径 (默认: threat_model.onnx)')
    parser.add_argument('--verbose', '-v', action='store_true', 
                        help='详细输出模式')
    args = parser.parse_args()
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 加载eBPF程序
    try:
        print("编译和加载eBPF程序...")
        bpf = BPF(src_file="nfs_monitor.bpf.c", cflags=[
            "-Wno-macro-redefined", 
            "-Wno-ignored-attributes",
            "-Wno-frame-address",
            "-Wno-unknown-warning-option"
        ])
    except Exception as e:
        print(f"加载eBPF程序失败: {str(e)}")
        print("请确保: 1) 内核版本>=5.7 2) 启用CONFIG_BPF_LSM 3) 安装LLVM/clang")
        return
    
    # 设置初始ML开关状态
    set_ml_switch(bpf, args.ml == 'on')
    
    # 附加LSM钩子
    lsm_hooks = [
        ("file_open", "nfs_file_open"),
        ("inode_unlink", "nfs_unlink"),
        ("inode_setattr", "nfs_setattr"),
        ("inode_create", "nfs_create"),
        ("inode_symlink", "nfs_symlink"),
        ("inode_rename", "nfs_rename")
    ]
    
    for hook, func in lsm_hooks:
        try:
            bpf.attach_lsm_hook(hook=hook, fn_name=func)
            if args.verbose:
                print(f"已附加LSM钩子: {hook} -> {func}")
        except Exception as e:
            print(f"附加LSM钩子失败 {hook}: {str(e)}")
    
    # 设置事件回调
    bpf["ml_events"].open_ring_buffer(lambda cpu, data, size: None)  # 由ML服务处理
    bpf["base_events"].open_ring_buffer(handle_base_event)
    
    # 启动ML服务线程
    ml_service = MLService(bpf, args.model)
    ml_service.start()
    
    print("NFS安全监控系统已启动")
    print("基础防护层始终运行")
    print(f"机器学习层: {'启用' if args.ml == 'on' else '禁用'}")
    print("按 'm' 键切换ML开关, 's' 查看统计, 'q' 退出")
    
    # 进入交互式控制
    interactive_control(bpf, ml_service)

if __name__ == "__main__":
    main()
