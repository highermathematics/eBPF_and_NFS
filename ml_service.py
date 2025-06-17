#!/usr/bin/env python3
import numpy as np
import onnxruntime as ort
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import os
import json
import time
import threading
from datetime import datetime

class ThreatDetector:
    """NFS威胁检测模型服务"""
    def __init__(self, model_path='threat_model.onnx', config_path='model_config.json'):
        self.model_path = model_path
        self.config_path = config_path
        self.model = None
        self.preprocessor = None
        self.config = {}
        self.anomaly_threshold = -0.5
        self.load_model()
        
        # 威胁情报数据库
        self.threat_intel = {
            "suspicious_processes": ["crypt", "locker", "ransom", "miner", "backdoor"],
            "sensitive_paths": ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/"],
            "malicious_clients": ["192.168.1.100", "10.0.0.55"]
        }
        
        # 性能统计
        self.stats = {
            "total_events": 0,
            "anomalies_detected": 0,
            "last_anomaly": None
        }
        
        # 模型更新线程
        self.update_thread = threading.Thread(target=self.periodic_model_update, daemon=True)
        self.update_thread.start()
    
    def load_model(self):
        """加载模型和配置"""
        try:
            # 加载模型配置
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                print(f"加载模型配置: {self.config_path}")
            
            # 加载ONNX模型
            if os.path.exists(self.model_path):
                self.model = ort.InferenceSession(self.model_path)
                print(f"加载ONNX模型: {self.model_path}")
            else:
                print(f"模型文件不存在: {self.model_path}, 使用基于规则的检测")
        except Exception as e:
            print(f"加载模型失败: {str(e)}")
    
    def periodic_model_update(self):
        """定期检查模型更新"""
        last_mtime = os.path.getmtime(self.model_path) if os.path.exists(self.model_path) else 0
        while True:
            try:
                if os.path.exists(self.model_path):
                    current_mtime = os.path.getmtime(self.model_path)
                    if current_mtime > last_mtime:
                        print("检测到模型更新, 重新加载...")
                        self.load_model()
                        last_mtime = current_mtime
            except Exception as e:
                print(f"模型更新检查失败: {str(e)}")
            
            time.sleep(60)  # 每分钟检查一次
    
    def preprocess_features(self, features):
        """预处理特征数据"""
        # 创建DataFrame
        df = pd.DataFrame([features])
        
        # 特征工程
        df['hour'] = pd.to_datetime(df['timestamp'], unit='ns').dt.hour
        df['is_privileged'] = df['uid'].apply(lambda x: 1 if x == 0 else 0)
        df['sensitive_path'] = df['full_path'].apply(
            lambda x: 1 if any(p in x for p in self.threat_intel['sensitive_paths']) else 0
        )
        df['suspicious_process'] = df['process_name'].apply(
            lambda x: 1 if any(p in x.lower() for p in self.threat_intel['suspicious_processes']) else 0
        )
        df['malicious_client'] = df['client_ip'].apply(
            lambda x: 1 if x in self.threat_intel['malicious_clients'] else 0
        )
        
        # 选择最终特征
        feature_cols = [
            'operation', 'file_size', 'mode', 'hour', 
            'is_privileged', 'sensitive_path', 
            'suspicious_process', 'malicious_client'
        ]
        return df[feature_cols].values.astype(np.float32)
    
    def rule_based_detection(self, features):
        """基于规则的威胁检测"""
        # 规则1: 非特权用户修改敏感文件
        if features['uid'] != 0:
            if any(p in features['full_path'] for p in self.threat_intel['sensitive_paths']):
                if features['operation'] in [OPERATION_WRITE, OPERATION_UNLINK, OPERATION_SETATTR]:
                    return True, "非特权用户修改敏感文件"
        
        # 规则2: 异常时间操作 (22:00-06:00 UTC)
        hour = pd.to_datetime(features['timestamp'], unit='ns').hour
        if 22 <= hour or hour < 6:
            if features['operation'] in [OPERATION_WRITE, OPERATION_UNLINK, OPERATION_SETATTR]:
                return True, "异常时间操作"
        
        # 规则3: 已知恶意客户端
        if features['client_ip'] in self.threat_intel['malicious_clients']:
            return True, "已知恶意客户端"
        
        # 规则4: 可疑进程名
        proc_lower = features['process_name'].lower()
        if any(p in proc_lower for p in self.threat_intel['suspicious_processes']):
            return True, "可疑进程"
        
        return False, ""
    
    def detect_threat(self, features):
        """检测威胁"""
        self.stats['total_events'] += 1
        
        # 首先执行基于规则的检测
        is_threat, reason = self.rule_based_detection(features)
        if is_threat:
            self.stats['anomalies_detected'] += 1
            self.stats['last_anomaly'] = datetime.now().isoformat()
            return True, reason
        
        # 如果ML模型可用，执行模型推理
        if self.model:
            try:
                # 预处理特征
                input_data = self.preprocess_features(features)
                
                # ONNX模型推理
                input_name = self.model.get_inputs()[0].name
                output_name = self.model.get_outputs()[0].name
                anomaly_score = self.model.run([output_name], {input_name: input_data})[0][0][0]
                
                if anomaly_score < self.anomaly_threshold:
                    self.stats['anomalies_detected'] += 1
                    self.stats['last_anomaly'] = datetime.now().isoformat()
                    return True, f"异常行为 (分数: {anomaly_score:.2f})"
            except Exception as e:
                print(f"模型推理失败: {str(e)}")
        
        return False, ""

    def train_new_model(self, data_path='nfs_events.csv', save_path='threat_model.onnx'):
        """训练新模型并导出为ONNX格式"""
        try:
            print("开始训练新威胁检测模型...")
            
            # 加载数据集
            df = pd.read_csv(data_path)
            print(f"加载数据集: {len(df)} 条记录")
            
            # 预处理
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
            df['is_privileged'] = df['uid'].apply(lambda x: 1 if x == 0 else 0)
            df['sensitive_path'] = df['full_path'].apply(
                lambda x: 1 if any(p in x for p in self.threat_intel['sensitive_paths']) else 0
            )
            df['suspicious_process'] = df['process_name'].apply(
                lambda x: 1 if any(p in x.lower() for p in self.threat_intel['suspicious_processes']) else 0
            )
            
            # 特征选择
            feature_cols = [
                'operation', 'file_size', 'mode', 'hour', 
                'is_privileged', 'sensitive_path', 'suspicious_process'
            ]
            X = df[feature_cols]
            
            # 训练隔离森林模型
            model = IsolationForest(
                n_estimators=200,
                max_samples='auto',
                contamination=0.05,
                random_state=42,
                verbose=1
            )
            model.fit(X)
            
            # 导出模型配置
            self.config = {
                "features": feature_cols,
                "threshold": self.anomaly_threshold,
                "training_date": datetime.now().isoformat(),
                "dataset_size": len(df)
            }
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            # 导出为ONNX格式
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType
            initial_type = [('float_input', FloatTensorType([None, len(feature_cols)]))]
            onx = convert_sklearn(model, initial_types=initial_type)
            with open(save_path, "wb") as f:
                f.write(onx.SerializeToString())
            
            print(f"模型训练完成并导出到: {save_path}")
            return True
        except Exception as e:
            print(f"模型训练失败: {str(e)}")
            return False

# 操作常量 (与eBPF程序中的定义一致)
OPERATION_OPEN = 0
OPERATION_READ = 1
OPERATION_WRITE = 2
OPERATION_UNLINK = 3
OPERATION_SETATTR = 4
OPERATION_RENAME = 5
OPERATION_CREATE = 6
OPERATION_SYMLINK = 7

if __name__ == "__main__":
    # 示例用法
    detector = ThreatDetector()
    
    # 训练新模型 (如果有数据)
    if os.path.exists('nfs_events.csv'):
        detector.train_new_model()
    
    # 示例检测
    sample_event = {
        "timestamp": time.time_ns(),
        "inode": 123456,
        "pid": 5678,
        "uid": 1001,
        "gid": 1001,
        "operation": OPERATION_UNLINK,
        "access_flags": 0,
        "file_size": 1024,
        "mode": 33188,
        "parent_inode": 789012,
        "session_id": 135790,
        "filename": "important.conf",
        "client_ip": "192.168.1.100",
        "process_name": "crypt_tool",
        "username": "user_1001",
        "full_path": "/etc/important.conf"
    }
    
    is_threat, reason = detector.detect_threat(sample_event)
    print(f"威胁检测结果: {is_threat}, 原因: {reason}")
    
    # 打印统计信息
    print(f"\n检测统计:")
    print(f"总事件数: {detector.stats['total_events']}")
    print(f"异常事件数: {detector.stats['anomalies_detected']}")
    print(f"最后异常时间: {detector.stats['last_anomaly']}")
