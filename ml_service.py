import asyncio
import json
import logging
import numpy as np
import pickle
from datetime import datetime, timedelta
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.cluster import DBSCAN
import threading
import time
import hashlib
import os
import struct

class NFSSecurityMLService:
    def __init__(self):
        self.logger = self._setup_logger()
        
        # 多个ML模型
        self.anomaly_model = None  # Isolation Forest for anomaly detection
        self.threat_classifier = None  # Random Forest for threat classification
        self.behavior_model = None  # Gradient Boosting for behavior analysis
        self.clustering_model = None  # DBSCAN for pattern clustering
        
        # 数据预处理
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # 训练数据缓存
        self.anomaly_training_data = []
        self.classification_training_data = []
        self.behavior_training_data = []
        
        # 模型状态
        self.is_anomaly_trained = False
        self.is_threat_trained = False
        self.is_behavior_trained = False
        
        # 客户端行为档案 - 针对NFS LSM钩子
        self.client_profiles = defaultdict(lambda: {
            # 文件访问模式
            'inode_permissions': deque(maxlen=1000),
            'file_permissions': deque(maxlen=1000),
            'file_opens': deque(maxlen=500),
            
            # 元数据操作
            'setattr_operations': deque(maxlen=300),
            'xattr_operations': deque(maxlen=200),
            
            # 文件系统操作
            'link_operations': deque(maxlen=100),
            'rename_operations': deque(maxlen=100),
            'mkdir_operations': deque(maxlen=100),
            'rmdir_operations': deque(maxlen=100),
            'unlink_operations': deque(maxlen=200),
            'create_operations': deque(maxlen=200),
            
            # 挂载和文件系统操作
            'mount_operations': deque(maxlen=50),
            'statfs_operations': deque(maxlen=100),
            
            # 内存映射操作
            'mmap_operations': deque(maxlen=100),
            'mprotect_operations': deque(maxlen=100),
            
            # 执行和权限变更
            'exec_checks': deque(maxlen=100),
            'cred_changes': deque(maxlen=100),
            
            # 统计信息
            'access_times': deque(maxlen=1000),
            'file_types': defaultdict(int),
            'permission_patterns': defaultdict(int),
            'suspicious_score': 0.0,
            'risk_level': 'LOW',
            'last_violation': None,
            'violation_count': 0,
            'threat_category': 'UNKNOWN'
        })
        
        # LSM钩子事件类型映射
        self.lsm_event_types = {
            # 核心文件操作钩子
            1: 'INODE_PERMISSION',
            2: 'FILE_PERMISSION', 
            3: 'FILE_OPEN',
            4: 'INODE_SETATTR',
            
            # 扩展属性钩子
            5: 'INODE_SETXATTR',
            6: 'INODE_GETXATTR',
            7: 'INODE_LISTXATTR',
            8: 'INODE_REMOVEXATTR',
            
            # 文件系统结构操作钩子
            9: 'PATH_LINK',
            10: 'PATH_RENAME',
            11: 'PATH_MKDIR',
            12: 'INODE_MKDIR',
            13: 'PATH_RMDIR',
            14: 'INODE_RMDIR',
            15: 'INODE_UNLINK',
            16: 'INODE_CREATE',
            
            # 挂载相关钩子
            17: 'SB_MOUNT',
            18: 'SB_REMOUNT',
            19: 'SB_STATFS',
            
            # 内存映射钩子
            20: 'FILE_MPROTECT',
            21: 'MMAP_FILE',
            
            # 执行和权限钩子
            22: 'BPRM_CHECK_SECURITY',
            23: 'BPRM_CREDS_FOR_EXEC',
            24: 'TASK_FIX_SETUID',
            25: 'TASK_FIX_SETGID',
            26: 'TASK_FIX_SETPRIVS'
        }
        
        # 威胁分类
        self.threat_categories = {
            'PRIVILEGE_ESCALATION': ['INODE_SETATTR', 'TASK_FIX_SETUID', 'TASK_FIX_SETGID'],
            'DATA_EXFILTRATION': ['FILE_OPEN', 'INODE_PERMISSION', 'FILE_PERMISSION'],
            'SYSTEM_MANIPULATION': ['SB_MOUNT', 'SB_REMOUNT', 'INODE_SETXATTR'],
            'MALWARE_EXECUTION': ['BPRM_CHECK_SECURITY', 'FILE_MPROTECT', 'MMAP_FILE'],
            'FILE_DESTRUCTION': ['INODE_UNLINK', 'PATH_RMDIR', 'INODE_RMDIR'],
            'RECONNAISSANCE': ['SB_STATFS', 'INODE_LISTXATTR', 'INODE_GETXATTR']
        }
        
        # 风险权重 - 基于LSM钩子的安全重要性
        self.lsm_risk_weights = {
            'INODE_PERMISSION': 0.6,
            'FILE_PERMISSION': 0.5,
            'FILE_OPEN': 0.4,
            'INODE_SETATTR': 0.8,
            'INODE_SETXATTR': 0.9,
            'INODE_GETXATTR': 0.3,
            'INODE_LISTXATTR': 0.3,
            'INODE_REMOVEXATTR': 0.7,
            'PATH_LINK': 0.6,
            'PATH_RENAME': 0.5,
            'PATH_MKDIR': 0.3,
            'INODE_MKDIR': 0.3,
            'PATH_RMDIR': 0.6,
            'INODE_RMDIR': 0.6,
            'INODE_UNLINK': 0.7,
            'INODE_CREATE': 0.4,
            'SB_MOUNT': 1.0,
            'SB_REMOUNT': 1.0,
            'SB_STATFS': 0.2,
            'FILE_MPROTECT': 0.9,
            'MMAP_FILE': 0.7,
            'BPRM_CHECK_SECURITY': 0.8,
            'BPRM_CREDS_FOR_EXEC': 0.9,
            'TASK_FIX_SETUID': 1.0,
            'TASK_FIX_SETGID': 1.0,
            'TASK_FIX_SETPRIVS': 1.0
        }
        
        # 启动后台训练线程
        self.training_thread = threading.Thread(target=self._background_training, daemon=True)
        self.training_thread.start()
        
    def _setup_logger(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('nfs_ml_security.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('NFSSecurityML')
    
    def extract_lsm_features(self, event_data):
        """提取LSM钩子特征"""
        try:
            features = []
            
            # 基础LSM事件特征
            features.extend([
                event_data.get('pid', 0),
                event_data.get('uid', 0),
                event_data.get('gid', 0),
                event_data.get('event_type', 0),
                event_data.get('permission_mask', 0),
                event_data.get('access_mode', 0),
                event_data.get('file_mode', 0),
                event_data.get('inode_number', 0),
                event_data.get('parent_inode', 0),
                event_data.get('device_id', 0),
                event_data.get('file_size', 0),
                event_data.get('client_ip', 0),
                event_data.get('client_port', 0)
            ])
            
            # 扩展属性特征
            xattr_name = event_data.get('xattr_name', '')
            features.extend([
                len(xattr_name),
                1 if 'security' in xattr_name else 0,
                1 if 'selinux' in xattr_name else 0,
                1 if 'capability' in xattr_name else 0,
                1 if 'trusted' in xattr_name else 0
            ])
            
            # 挂载特征
            mount_flags = event_data.get('mount_flags', 0)
            features.extend([
                mount_flags,
                1 if mount_flags & 0x1 else 0,  # MS_RDONLY
                1 if mount_flags & 0x2 else 0,  # MS_NOSUID
                1 if mount_flags & 0x4 else 0,  # MS_NODEV
                1 if mount_flags & 0x8 else 0   # MS_NOEXEC
            ])
            
            # 时间特征
            timestamp = event_data.get('timestamp', 0)
            if timestamp:
                dt = datetime.fromtimestamp(timestamp / 1e9)
                features.extend([
                    dt.hour,
                    dt.weekday(),
                    dt.minute,
                    1 if 22 <= dt.hour or dt.hour <= 6 else 0,  # 夜间
                    1 if dt.weekday() >= 5 else 0  # 周末
                ])
            else:
                features.extend([0, 0, 0, 0, 0])
            
            # 文件路径特征
            filename = event_data.get('filename', '')
            features.extend([
                len(filename),
                filename.count('/'),
                1 if filename.startswith('/tmp') else 0,
                1 if filename.startswith('/var') else 0,
                1 if filename.startswith('/etc') else 0,
                1 if filename.startswith('/proc') else 0,
                1 if filename.startswith('/sys') else 0,
                1 if any(ext in filename.lower() for ext in ['.so', '.exe', '.bin']) else 0,
                1 if filename.startswith('.') else 0
            ])
            
            # 客户端行为特征
            client_ip = event_data.get('client_ip', 0)
            profile = self.client_profiles[client_ip]
            
            # LSM钩子调用频率
            current_time = time.time()
            event_type = event_data.get('event_type', 0)
            event_name = self.lsm_event_types.get(event_type, 'UNKNOWN')
            
            # 各类操作的频率统计
            recent_inode_perms = len([t for t in profile['inode_permissions'] 
                                    if current_time - t['time'] < 300])
            recent_file_perms = len([t for t in profile['file_permissions'] 
                                   if current_time - t['time'] < 300])
            recent_setattrs = len([t for t in profile['setattr_operations'] 
                                 if current_time - t['time'] < 300])
            recent_xattrs = len([t for t in profile['xattr_operations'] 
                               if current_time - t['time'] < 300])
            
            features.extend([recent_inode_perms, recent_file_perms, recent_setattrs, recent_xattrs])
            
            # 权限模式分析
            permission_diversity = len(profile['permission_patterns'])
            features.append(permission_diversity)
            
            # 威胁分类特征
            threat_score = 0.0
            for category, events in self.threat_categories.items():
                if event_name in events:
                    threat_score = self.lsm_risk_weights.get(event_name, 0.1)
                    break
            features.append(threat_score)
            
            # 序列模式特征
            if len(profile['access_times']) >= 5:
                recent_intervals = []
                times = list(profile['access_times'])[-5:]
                for i in range(1, len(times)):
                    recent_intervals.append(times[i] - times[i-1])
                
                features.extend([
                    np.mean(recent_intervals) if recent_intervals else 0,
                    np.std(recent_intervals) if recent_intervals else 0,
                    min(recent_intervals) if recent_intervals else 0,
                    max(recent_intervals) if recent_intervals else 0
                ])
            else:
                features.extend([0, 0, 0, 0])
            
            # 更新客户端档案
            self._update_client_profile(event_data, profile, current_time)
            
            return np.array(features, dtype=np.float32)
            
        except Exception as e:
            self.logger.error(f"LSM特征提取错误: {e}")
            return np.zeros(50, dtype=np.float32)
    
    def _update_client_profile(self, event_data, profile, current_time):
        """更新客户端档案"""
        event_type = event_data.get('event_type', 0)
        event_name = self.lsm_event_types.get(event_type, 'UNKNOWN')
        
        # 更新对应的操作记录
        event_record = {
            'time': current_time,
            'event_type': event_type,
            'filename': event_data.get('filename', ''),
            'permission_mask': event_data.get('permission_mask', 0),
            'result': event_data.get('result', 0)
        }
        
        if event_name == 'INODE_PERMISSION':
            profile['inode_permissions'].append(event_record)
        elif event_name == 'FILE_PERMISSION':
            profile['file_permissions'].append(event_record)
        elif event_name == 'FILE_OPEN':
            profile['file_opens'].append(event_record)
        elif event_name == 'INODE_SETATTR':
            profile['setattr_operations'].append(event_record)
        elif event_name in ['INODE_SETXATTR', 'INODE_GETXATTR', 'INODE_LISTXATTR', 'INODE_REMOVEXATTR']:
            profile['xattr_operations'].append(event_record)
        elif event_name == 'PATH_LINK':
            profile['link_operations'].append(event_record)
        elif event_name == 'PATH_RENAME':
            profile['rename_operations'].append(event_record)
        elif event_name in ['PATH_MKDIR', 'INODE_MKDIR']:
            profile['mkdir_operations'].append(event_record)
        elif event_name in ['PATH_RMDIR', 'INODE_RMDIR']:
            profile['rmdir_operations'].append(event_record)
        elif event_name == 'INODE_UNLINK':
            profile['unlink_operations'].append(event_record)
        elif event_name == 'INODE_CREATE':
            profile['create_operations'].append(event_record)
        elif event_name in ['SB_MOUNT', 'SB_REMOUNT']:
            profile['mount_operations'].append(event_record)
        elif event_name == 'SB_STATFS':
            profile['statfs_operations'].append(event_record)
        elif event_name == 'MMAP_FILE':
            profile['mmap_operations'].append(event_record)
        elif event_name == 'FILE_MPROTECT':
            profile['mprotect_operations'].append(event_record)
        elif event_name in ['BPRM_CHECK_SECURITY', 'BPRM_CREDS_FOR_EXEC']:
            profile['exec_checks'].append(event_record)
        elif event_name in ['TASK_FIX_SETUID', 'TASK_FIX_SETGID', 'TASK_FIX_SETPRIVS']:
            profile['cred_changes'].append(event_record)
        
        # 更新通用统计
        profile['access_times'].append(current_time)
        profile['permission_patterns'][event_data.get('permission_mask', 0)] += 1
        
        # 更新文件类型统计
        filename = event_data.get('filename', '')
        if '.' in filename:
            file_ext = filename.split('.')[-1]
            profile['file_types'][file_ext] += 1
    
    def detect_lsm_anomaly(self, event_data):
        """LSM钩子异常检测"""
        try:
            features = self.extract_lsm_features(event_data)
            client_ip = event_data.get('client_ip', 0)
            profile = self.client_profiles[client_ip]
            
            # 多层检测
            detection_results = {
                'lsm_rule_based': self._lsm_rule_based_detection(event_data),
                'lsm_statistical': self._lsm_statistical_detection(event_data, profile),
                'lsm_behavioral': self._lsm_behavioral_analysis(event_data, profile),
                'lsm_sequence': self._lsm_sequence_analysis(event_data, profile)
            }
            
            # ML模型检测
            if self.is_anomaly_trained:
                detection_results['ml_anomaly'] = self._ml_anomaly_detection(features)
            
            if self.is_threat_trained:
                detection_results['threat_classification'] = self._threat_classification(features)
            
            if self.is_behavior_trained:
                detection_results['behavior_analysis'] = self._behavior_prediction(features)
            
            # 综合评分
            final_result = self._combine_lsm_results(detection_results, profile, event_data)
            
            # 更新威胁分类
            self._update_threat_classification(event_data, final_result, profile)
            
            self.logger.info(f"LSM异常检测结果: {final_result}")
            return final_result
            
        except Exception as e:
            self.logger.error(f"LSM异常检测错误: {e}")
            return {'is_anomaly': False, 'error': str(e)}
    
    def _lsm_rule_based_detection(self, event_data):
        """基于LSM钩子的规则检测"""
        is_anomaly = False
        reasons = []
        score = 0.0
        
        event_type = event_data.get('event_type', 0)
        event_name = self.lsm_event_types.get(event_type, 'UNKNOWN')
        
        # 规则1: 高风险LSM钩子
        high_risk_events = ['SB_MOUNT', 'SB_REMOUNT', 'TASK_FIX_SETUID', 'TASK_FIX_SETGID', 'FILE_MPROTECT']
        if event_name in high_risk_events:
            is_anomaly = True
            reasons.append(f'高风险LSM操作: {event_name}')
            score += 0.8
        
        # 规则2: 敏感扩展属性操作
        if event_name in ['INODE_SETXATTR', 'INODE_REMOVEXATTR']:
            xattr_name = event_data.get('xattr_name', '')
            if any(sensitive in xattr_name for sensitive in ['security', 'selinux', 'capability']):
                is_anomaly = True
                reasons.append('敏感扩展属性操作')
                score += 0.9
        
        # 规则3: SUID/SGID文件操作
        if event_name == 'INODE_SETATTR':
            file_mode = event_data.get('file_mode', 0)
            if file_mode & (0o4000 | 0o2000):  # SUID或SGID位
                is_anomaly = True
                reasons.append('SUID/SGID权限设置')
                score += 0.9
        
        # 规则4: 系统目录操作
        filename = event_data.get('filename', '')
        if any(path in filename for path in ['/etc/', '/proc/', '/sys/', '/dev/']):
            if event_name in ['INODE_CREATE', 'INODE_UNLINK', 'INODE_SETATTR']:
                is_anomaly = True
                reasons.append('系统目录敏感操作')
                score += 0.7
        
        # 规则5: 可执行文件内存保护修改
        if event_name == 'FILE_MPROTECT':
            filename = event_data.get('filename', '')
            if any(ext in filename.lower() for ext in ['.so', '.exe', '.bin']):
                is_anomaly = True
                reasons.append('可执行文件内存保护修改')
                score += 0.8
        
        return {
            'is_anomaly': is_anomaly,
            'score': min(score, 1.0),
            'reasons': reasons,
            'method': 'lsm_rule_based'
        }
    
    def _lsm_statistical_detection(self, event_data, profile):
        """LSM统计异常检测"""
        is_anomaly = False
        score = 0.0
        
        current_time = time.time()
        
        # 检查各类LSM操作的频率异常
        recent_window = 300  # 5分钟窗口
        
        # 权限检查频率异常
        recent_perms = len([t for t in profile['inode_permissions'] 
                          if current_time - t['time'] < recent_window])
        if recent_perms > 100:  # 5分钟内超过100次权限检查
            is_anomaly = True
            score += 0.4
        
        # 文件属性修改频率异常
        recent_setattrs = len([t for t in profile['setattr_operations'] 
                             if current_time - t['time'] < recent_window])
        if recent_setattrs > 20:  # 5分钟内超过20次属性修改
            is_anomaly = True
            score += 0.6
        
        # 扩展属性操作频率异常
        recent_xattrs = len([t for t in profile['xattr_operations'] 
                           if current_time - t['time'] < recent_window])
        if recent_xattrs > 10:  # 5分钟内超过10次扩展属性操作
            is_anomaly = True
            score += 0.5
        
        # 文件删除频率异常
        recent_unlinks = len([t for t in profile['unlink_operations'] 
                            if current_time - t['time'] < recent_window])
        if recent_unlinks > 50:  # 5分钟内超过50次文件删除
            is_anomaly = True
            score += 0.7
        
        return {
            'is_anomaly': is_anomaly,
            'score': min(score, 1.0),
            'method': 'lsm_statistical'
        }
    
    def _lsm_behavioral_analysis(self, event_data, profile):
        """LSM行为分析"""
        is_anomaly = False
        score = 0.0
        reasons = []
        
        # 检查权限提升模式
        if self._detect_privilege_escalation_pattern(profile):
            is_anomaly = True
            reasons.append('权限提升攻击模式')
            score += 0.9
        
        # 检查数据渗透模式
        if self._detect_data_exfiltration_pattern(profile):
            is_anomaly = True
            reasons.append('数据渗透攻击模式')
            score += 0.8
        
        # 检查系统操控模式
        if self._detect_system_manipulation_pattern(profile):
            is_anomaly = True
            reasons.append('系统操控攻击模式')
            score += 0.8
        
        # 检查恶意软件执行模式
        if self._detect_malware_execution_pattern(profile):
            is_anomaly = True
            reasons.append('恶意软件执行模式')
            score += 0.9
        
        return {
            'is_anomaly': is_anomaly,
            'score': min(score, 1.0),
            'reasons': reasons,
            'method': 'lsm_behavioral'
        }
    
    def _lsm_sequence_analysis(self, event_data, profile):
        """LSM序列分析"""
        is_anomaly = False
        score = 0.0
        
        # 分析最近的LSM事件序列
        recent_events = []
        current_time = time.time()
        
        # 收集最近30秒内的所有事件
        for event_list in [profile['inode_permissions'], profile['file_permissions'], 
                          profile['setattr_operations'], profile['xattr_operations']]:
            recent_events.extend([e for e in event_list if current_time - e['time'] < 30])
        
        recent_events.sort(key=lambda x: x['time'])
        
        if len(recent_events) >= 5:
            # 检查攻击序列模式
            event_sequence = [e['event_type'] for e in recent_events[-5:]]
            
            # 已知攻击序列模式
            attack_patterns = [
                [1, 3, 4, 5, 24],  # 权限检查 -> 文件打开 -> 属性修改 -> 扩展属性设置 -> UID修改
                [1, 1, 1, 15, 15], # 大量权限检查 -> 文件删除
                [17, 18, 4, 5],    # 挂载 -> 重新挂载 -> 属性修改 -> 扩展属性
            ]
            
            for pattern in attack_patterns:
                if self._sequence_similarity(event_sequence, pattern) > 0.8:
                    is_anomaly = True
                    score += 0.8
                    break
        
        return {
            'is_anomaly': is_anomaly,
            'score': min(score, 1.0),
            'method': 'lsm_sequence'
        }
    
    def _detect_privilege_escalation_pattern(self, profile):
        """检测权限提升模式"""
        current_time = time.time()
        window = 600  # 10分钟窗口
        
        # 检查是否有SUID/SGID设置 + 权限修改的组合
        recent_setattrs = [e for e in profile['setattr_operations'] 
                          if current_time - e['time'] < window]
        recent_cred_changes = [e for e in profile['cred_changes'] 
                             if current_time - e['time'] < window]
        
        return len(recent_setattrs) > 0 and len(recent_cred_changes) > 0
    
    def _detect_data_exfiltration_pattern(self, profile):
        """检测数据渗透模式"""
        current_time = time.time()
        window = 300  # 5分钟窗口
        
        # 大量文件读取 + 权限检查
        recent_perms = len([e for e in profile['inode_permissions'] 
                          if current_time - e['time'] < window])
        recent_opens = len([e for e in profile['file_opens'] 
                          if current_time - e['time'] < window])
        
        return recent_perms > 50 and recent_opens > 20
    
    def _detect_system_manipulation_pattern(self, profile):
        """检测系统操控模式"""
        current_time = time.time()
        window = 600  # 10分钟窗口
        
        # 挂载操作 + 扩展属性修改
        recent_mounts = len([e for e in profile['mount_operations'] 
                           if current_time - e['time'] < window])
        recent_xattrs = len([e for e in profile['xattr_operations'] 
                           if current_time - e['time'] < window])
        
        return recent_mounts > 0 and recent_xattrs > 5
    
    def _detect_malware_execution_pattern(self, profile):
        """检测恶意软件执行模式"""
        current_time = time.time()
        window = 300  # 5分钟窗口
        
        # 内存保护修改 + 执行检查
        recent_mprotects = len([e for e in profile['mprotect_operations'] 
                              if current_time - e['time'] < window])
        recent_exec_checks = len([e for e in profile['exec_checks'] 
                                if current_time - e['time'] < window])
        
        return recent_mprotects > 0 and recent_exec_checks > 0
    
    def _sequence_similarity(self, seq1, seq2):
        """计算序列相似度"""
        if len(seq1) != len(seq2):
            return 0.0
        
        matches = sum(1 for a, b in zip(seq1, seq2) if a == b)
        return matches / len(seq1)
    
    def _ml_anomaly_detection(self, features):
        """ML异常检测"""
        try:
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            anomaly_score = self.anomaly_model.decision_function(features_scaled)[0]
            is_anomaly = self.anomaly_model.predict(features_scaled)[0] == -1
            
            return {
                'is_anomaly': bool(is_anomaly),
                'score': float(abs(anomaly_score)),
                'method': 'ml_anomaly'
            }
        except Exception as e:
            self.logger.error(f"ML异常检测错误: {e}")
            return {'is_anomaly': False, 'score': 0.0, 'method': 'ml_anomaly'}
    
    def _threat_classification(self, features):
        """威胁分类"""
        try:
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            threat_proba = self.threat_classifier.predict_proba(features_scaled)[0]
            threat_class = self.threat_classifier.predict(features_scaled)[0]
            
            threat_categories = ['BENIGN', 'PRIVILEGE_ESCALATION', 'DATA_EXFILTRATION', 
                               'SYSTEM_MANIPULATION', 'MALWARE_EXECUTION', 'FILE_DESTRUCTION']
            
            return {
                'threat_class': threat_categories[threat_class] if threat_class < len(threat_categories) else 'UNKNOWN',
                'confidence': float(max(threat_proba)),
                'probabilities': {cat: float(prob) for cat, prob in zip(threat_categories, threat_proba)},
                'method': 'threat_classification'
            }
        except Exception as e:
            self.logger.error(f"威胁分类错误: {e}")
            return {'threat_class': 'UNKNOWN', 'confidence': 0.0, 'method': 'threat_classification'}
    
    def _behavior_prediction(self, features):
        """行为预测"""
        try:
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            behavior_score = self.behavior_model.predict(features_scaled)[0]
            
            return {
                'behavior_score': float(behavior_score),
                'risk_level': 'HIGH' if behavior_score > 0.7 else 'MEDIUM' if behavior_score > 0.4 else 'LOW',
                'method': 'behavior_prediction'
            }
        except Exception as e:
            self.logger.error(f"行为预测错误: {e}")
            return {'behavior_score': 0.0, 'risk_level': 'LOW', 'method': 'behavior_prediction'}
    
    def _combine_lsm_results(self, detection_results, profile, event_data):
        """综合LSM检测结果"""
        total_score = 0.0
        total_weight = 0.0
        is_anomaly = False
        all_reasons = []
        methods_used = []
        
        # 权重分配
        weights = {
            'lsm_rule_based': 0.3,
            'lsm_statistical': 0.2,
            'lsm_behavioral': 0.25,
            'lsm_sequence': 0.15,
            'ml_anomaly': 0.1,
            'threat_classification': 0.15,
            'behavior_analysis': 0.1
        }
        
        for method, result in detection_results.items():
            if result and method in weights:
                weight = weights[method]
                score = result.get('score', 0.0)
                total_score += score * weight
                total_weight += weight
                
                if result.get('is_anomaly', False):
                    is_anomaly = True
                
                if 'reasons' in result:
                    all_reasons.extend(result['reasons'])
                
                methods_used.append(method)
        
        final_score = total_score / total_weight if total_weight > 0 else 0.0
        
        # 更新客户端可疑度
        if is_anomaly:
            profile['suspicious_score'] = min(profile['suspicious_score'] + 0.1, 1.0)
            profile['violation_count'] += 1
            profile['last_violation'] = time.time()
        else:
            profile['suspicious_score'] = max(profile['suspicious_score'] - 0.02, 0.0)
        
        # 确定风险等级
        if final_score > 0.8:
            risk_level = 'CRITICAL'
        elif final_score > 0.6:
            risk_level = 'HIGH'
        elif final_score > 0.4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        profile['risk_level'] = risk_level
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': final_score,
            'risk_level': risk_level,
            'client_suspicious_score': profile['suspicious_score'],
            'reasons': list(set(all_reasons)),
            'methods_used': methods_used,
            'detection_details': detection_results,
            'event_type': self.lsm_event_types.get(event_data.get('event_type', 0), 'UNKNOWN'),
            'timestamp': datetime.now().isoformat()
        }
    
    def _update_threat_classification(self, event_data, result, profile):
        """更新威胁分类"""
        if 'threat_classification' in result.get('detection_details', {}):
            threat_info = result['detection_details']['threat_classification']
            threat_class = threat_info.get('threat_class', 'UNKNOWN')
            confidence = threat_info.get('confidence', 0.0)
            
            if confidence > 0.7:
                profile['threat_category'] = threat_class
    
    def update_training_data(self, event_data, label=0, threat_label=0):
        """更新训练数据"""
        features = self.extract_lsm_features(event_data)
        
        # 异常检测训练数据
        self.anomaly_training_data.append((features, label))
        
        # 威胁分类训练数据
        self.classification_training_data.append((features, threat_label))
        
        # 行为分析训练数据
        behavior_score = self._calculate_behavior_score(event_data)
        self.behavior_training_data.append((features, behavior_score))
        
        # 限制数据大小
        if len(self.anomaly_training_data) > 10000:
            self.anomaly_training_data = self.anomaly_training_data[-8000:]
        if len(self.classification_training_data) > 10000:
            self.classification_training_data = self.classification_training_data[-8000:]
        if len(self.behavior_training_data) > 10000:
            self.behavior_training_data = self.behavior_training_data[-8000:]
    
    def _calculate_behavior_score(self, event_data):
        """计算行为分数"""
        event_type = event_data.get('event_type', 0)
        event_name = self.lsm_event_types.get(event_type, 'UNKNOWN')
        base_score = self.lsm_risk_weights.get(event_name, 0.1)
        
        # 根据上下文调整分数
        filename = event_data.get('filename', '')
        if any(path in filename for path in ['/etc/', '/proc/', '/sys/']):
            base_score += 0.2
        
        timestamp = event_data.get('timestamp', 0)
        if timestamp:
            dt = datetime.fromtimestamp(timestamp / 1e9)
            if 22 <= dt.hour or dt.hour <= 6:  # 夜间操作
                base_score += 0.1
        
        return min(base_score, 1.0)
    
    def _background_training(self):
        """后台训练线程"""
        while True:
            try:
                time.sleep(600)  # 每10分钟检查一次
                
                # 训练异常检测模型
                if len(self.anomaly_training_data) >= 100:
                    self._train_anomaly_model()
                
                # 训练威胁分类模型
                if len(self.classification_training_data) >= 100:
                    self._train_threat_classifier()
                
                # 训练行为分析模型
                if len(self.behavior_training_data) >= 100:
                    self._train_behavior_model()
                    
            except Exception as e:
                self.logger.error(f"后台训练错误: {e}")
    
    def _train_anomaly_model(self):
        """训练异常检测模型"""
        try:
            self.logger.info(f"开始训练异常检测模型，数据量: {len(self.anomaly_training_data)}")
            
            X = np.array([item[0] for item in self.anomaly_training_data])
            X_scaled = self.scaler.fit_transform(X)
            
            self.anomaly_model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            self.anomaly_model.fit(X_scaled)
            self.is_anomaly_trained = True
            
            self.logger.info("异常检测模型训练完成")
            
        except Exception as e:
            self.logger.error(f"异常检测模型训练错误: {e}")
    
    def _train_threat_classifier(self):
        """训练威胁分类模型"""
        try:
            self.logger.info(f"开始训练威胁分类模型，数据量: {len(self.classification_training_data)}")
            
            X = np.array([item[0] for item in self.classification_training_data])
            y = np.array([item[1] for item in self.classification_training_data])
            
            if len(np.unique(y)) > 1:  # 确保有多个类别
                X_scaled = self.scaler.fit_transform(X)
                
                self.threat_classifier = RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                    max_depth=10
                )
                
                self.threat_classifier.fit(X_scaled, y)
                self.is_threat_trained = True
                
                self.logger.info("威胁分类模型训练完成")
            
        except Exception as e:
            self.logger.error(f"威胁分类模型训练错误: {e}")
    
    def _train_behavior_model(self):
        """训练行为分析模型"""
        try:
            self.logger.info(f"开始训练行为分析模型，数据量: {len(self.behavior_training_data)}")
            
            X = np.array([item[0] for item in self.behavior_training_data])
            y = np.array([item[1] for item in self.behavior_training_data])
            
            X_scaled = self.scaler.fit_transform(X)
            
            self.behavior_model = GradientBoostingClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=6
            )
            
            # 将连续的行为分数转换为分类标签
            y_categorical = np.digitize(y, bins=[0.3, 0.6, 0.8]) - 1
            
            self.behavior_model.fit(X_scaled, y_categorical)
            self.is_behavior_trained = True
            
            self.logger.info("行为分析模型训练完成")
            
        except Exception as e:
            self.logger.error(f"行为分析模型训练错误: {e}")
    
    def save_models(self, model_dir='nfs_ml_models'):
        """保存所有模型"""
        try:
            os.makedirs(model_dir, exist_ok=True)
            
            models_data = {
                'anomaly_model': self.anomaly_model,
                'threat_classifier': self.threat_classifier,
                'behavior_model': self.behavior_model,
                'scaler': self.scaler,
                'is_anomaly_trained': self.is_anomaly_trained,
                'is_threat_trained': self.is_threat_trained,
                'is_behavior_trained': self.is_behavior_trained
            }
            
            with open(os.path.join(model_dir, 'nfs_security_models.pkl'), 'wb') as f:
                pickle.dump(models_data, f)
            
            self.logger.info(f"模型已保存到 {model_dir}")
            
        except Exception as e:
            self.logger.error(f"模型保存错误: {e}")
    
    def load_models(self, model_dir='trained_models'):
        """加载训练好的模型"""
        try:
            model_path = os.path.join(model_dir, 'nfs_security_models.pkl')
            
            with open(model_path, 'rb') as f:
                models_data = pickle.load(f)
            
            self.anomaly_model = models_data.get('anomaly_model')
            self.threat_classifier = models_data.get('threat_classifier')
            self.behavior_model = models_data.get('behavior_model')
            self.clustering_model = models_data.get('clustering_model')
            self.scaler = models_data.get('scaler', StandardScaler())
            self.label_encoder = models_data.get('label_encoder', LabelEncoder())
            
            self.is_anomaly_trained = self.anomaly_model is not None
            self.is_threat_trained = self.threat_classifier is not None
            self.is_behavior_trained = self.behavior_model is not None
            
            self.logger.info("训练好的模型加载成功")
            
        except FileNotFoundError:
            self.logger.info("未找到训练好的模型文件，使用在线学习模式")
        except Exception as e:
            self.logger.error(f"模型加载错误: {e}")
    
    def get_client_security_report(self, client_ip):
        """获取客户端安全报告"""
        profile = self.client_profiles.get(client_ip, {})
        current_time = time.time()
        
        # 统计各类操作数量
        operations_stats = {}
        for op_type in ['inode_permissions', 'file_permissions', 'setattr_operations', 
                       'xattr_operations', 'unlink_operations', 'create_operations']:
            operations = profile.get(op_type, [])
            operations_stats[op_type] = {
                'total': len(operations),
                'recent_hour': len([op for op in operations if current_time - op.get('time', 0) < 3600]),
                'recent_day': len([op for op in operations if current_time - op.get('time', 0) < 86400])
            }
        
        return {
            'client_ip': self._ip_to_str(client_ip),
            'risk_level': profile.get('risk_level', 'LOW'),
            'suspicious_score': profile.get('suspicious_score', 0.0),
            'threat_category': profile.get('threat_category', 'UNKNOWN'),
            'violation_count': profile.get('violation_count', 0),
            'last_violation': datetime.fromtimestamp(profile['last_violation']).isoformat() if profile.get('last_violation') else None,
            'operations_statistics': operations_stats,
            'file_types_accessed': dict(profile.get('file_types', {})),
            'total_accesses': len(profile.get('access_times', [])),
            'report_time': datetime.now().isoformat()
        }
    
    def _ip_to_str(self, ip_int):
        """将整数IP转换为字符串"""
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

# 全局ML服务实例
nfs_ml_service = NFSSecurityMLService()

if __name__ == "__main__":
    # 加载已保存的模型
    nfs_ml_service.load_models()
    
    # 测试LSM事件
    test_lsm_event = {
        'pid': 1234,
        'uid': 1000,
        'gid': 1000,
        'event_type': 1,  # INODE_PERMISSION
        'timestamp': time.time() * 1e9,
        'filename': '/etc/passwd',
        'permission_mask': 4,  # R_OK
        'access_mode': 1,
        'file_mode': 0o644,
        'inode_number': 12345,
        'client_ip': 3232235777,  # 192.168.1.1
        'client_port': 12345
    }
    
    result = nfs_ml_service.detect_lsm_anomaly(test_lsm_event)
    print(f"LSM异常检测结果: {result}")
    
    # 获取客户端安全报告
    report = nfs_ml_service.get_client_security_report(3232235777)
    print(f"\n客户端安全报告: {json.dumps(report, indent=2, ensure_ascii=False)}")