#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NFS eBPF监控系统ML模型训练脚本
使用CSV数据训练异常检测、威胁分类和行为分析模型
"""

import pandas as pd
import numpy as np
import pickle
import os
import logging
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt
import seaborn as sns

class NFSMLTrainer:
    def __init__(self, models_dir='models'):
        self.models_dir = models_dir
        self.logger = self._setup_logger()
        
        # 初始化模型
        self.anomaly_model = None
        self.threat_classifier = None
        self.behavior_model = None
        self.clustering_model = None
        
        # 数据预处理器
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # 威胁类型映射
        self.threat_mapping = {
            'RECONNAISSANCE': 0,
            'PRIVILEGE_ESCALATION': 1,
            'MALWARE_DEPLOYMENT': 2,
            'DATA_EXFILTRATION': 3,
            'LOG_TAMPERING': 4,
            'PERSISTENCE': 5,
            'CREDENTIAL_THEFT': 6,
            'ACCOUNT_MANIPULATION': 7,
            'LOG_ANALYSIS': 8
        }
        
    def _setup_logger(self):
        """设置日志记录器"""
        logger = logging.getLogger('NFSMLTrainer')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def load_training_data(self):
        """加载所有训练数据"""
        self.logger.info("开始加载训练数据...")
        
        try:
            # 加载异常检测数据
            self.anomaly_data = pd.read_csv(os.path.join(self.models_dir, 'anomaly_detection_train.csv'))
            self.logger.info(f"异常检测数据: {len(self.anomaly_data)} 条记录")
            
            # 加载威胁分类数据
            self.threat_data = pd.read_csv(os.path.join(self.models_dir, 'threat_classification_train.csv'))
            self.logger.info(f"威胁分类数据: {len(self.threat_data)} 条记录")
            
            # 加载行为分析数据
            self.behavior_data = pd.read_csv(os.path.join(self.models_dir, 'client_behavior_analysis.csv'))
            self.logger.info(f"行为分析数据: {len(self.behavior_data)} 条记录")
            
            # 加载文件访问模式数据
            self.access_patterns = pd.read_csv(os.path.join(self.models_dir, 'file_access_patterns.csv'))
            self.logger.info(f"文件访问模式数据: {len(self.access_patterns)} 条记录")
            
            # 加载测试数据
            self.test_data = pd.read_csv(os.path.join(self.models_dir, 'test_dataset.csv'))
            self.logger.info(f"测试数据: {len(self.test_data)} 条记录")
            
            self.logger.info("训练数据加载完成")
            
        except Exception as e:
            self.logger.error(f"数据加载失败: {e}")
            raise
    
    def preprocess_anomaly_data(self):
        """预处理异常检测数据"""
        self.logger.info("预处理异常检测数据...")
        
        # 选择特征列
        feature_columns = [
            'operation_count', 'file_size', 'read_bytes', 'write_bytes',
            'error_count', 'response_time'
        ]
        
        # 添加IP地址特征
        self.anomaly_data['ip_last_octet'] = self.anomaly_data['client_ip'].str.split('.').str[3].astype(int)
        feature_columns.append('ip_last_octet')
        
        # 添加操作类型编码
        operation_encoder = LabelEncoder()
        self.anomaly_data['operation_encoded'] = operation_encoder.fit_transform(self.anomaly_data['operation_type'])
        feature_columns.append('operation_encoded')
        
        # 添加文件路径特征
        self.anomaly_data['path_length'] = self.anomaly_data['file_path'].str.len()
        self.anomaly_data['path_depth'] = self.anomaly_data['file_path'].str.count('/')
        self.anomaly_data['is_system_file'] = self.anomaly_data['file_path'].str.contains('/etc/|/proc/|/sys/').astype(int)
        feature_columns.extend(['path_length', 'path_depth', 'is_system_file'])
        
        # 添加时间特征
        self.anomaly_data['hour'] = pd.to_datetime(self.anomaly_data['access_time'], unit='s').dt.hour
        self.anomaly_data['is_night'] = ((self.anomaly_data['hour'] >= 22) | (self.anomaly_data['hour'] <= 6)).astype(int)
        feature_columns.extend(['hour', 'is_night'])
        
        X = self.anomaly_data[feature_columns]
        y = self.anomaly_data['is_anomaly']
        
        return X, y
    
    def preprocess_threat_data(self):
        """预处理威胁分类数据"""
        self.logger.info("预处理威胁分类数据...")
        
        # 选择特征列
        feature_columns = ['uid', 'gid']
        
        # 编码操作类型
        operation_encoder = LabelEncoder()
        self.threat_data['operation_encoded'] = operation_encoder.fit_transform(self.threat_data['operation_type'])
        feature_columns.append('operation_encoded')
        
        # 编码访问模式
        pattern_encoder = LabelEncoder()
        self.threat_data['pattern_encoded'] = pattern_encoder.fit_transform(self.threat_data['access_pattern'])
        feature_columns.append('pattern_encoded')
        
        # 编码频率
        freq_mapping = {'low': 0, 'medium': 1, 'high': 2}
        self.threat_data['frequency_encoded'] = self.threat_data['frequency'].map(freq_mapping)
        feature_columns.append('frequency_encoded')
        
        # 添加文件路径特征
        self.threat_data['path_length'] = self.threat_data['file_path'].str.len()
        self.threat_data['path_depth'] = self.threat_data['file_path'].str.count('/')
        self.threat_data['is_system_file'] = self.threat_data['file_path'].str.contains('/etc/|/proc/|/sys/').astype(int)
        self.threat_data['is_tmp_file'] = self.threat_data['file_path'].str.contains('/tmp/').astype(int)
        feature_columns.extend(['path_length', 'path_depth', 'is_system_file', 'is_tmp_file'])
        
        # IP特征
        self.threat_data['ip_last_octet'] = self.threat_data['client_ip'].str.split('.').str[3].astype(int)
        feature_columns.append('ip_last_octet')
        
        X = self.threat_data[feature_columns]
        y = self.threat_data['threat_type'].map(self.threat_mapping)
        
        return X, y
    
    def preprocess_behavior_data(self):
        """预处理行为分析数据"""
        self.logger.info("预处理行为分析数据...")
        
        # 选择特征列
        feature_columns = [
            'session_duration', 'total_operations', 'read_ops', 'write_ops', 'setattr_ops',
            'avg_response_time', 'error_rate', 'unique_files', 'suspicious_patterns'
        ]
        
        # IP特征
        self.behavior_data['ip_last_octet'] = self.behavior_data['client_ip'].str.split('.').str[3].astype(int)
        feature_columns.append('ip_last_octet')
        
        # 计算比率特征
        self.behavior_data['read_write_ratio'] = self.behavior_data['read_ops'] / (self.behavior_data['write_ops'] + 1)
        self.behavior_data['ops_per_minute'] = self.behavior_data['total_operations'] / (self.behavior_data['session_duration'] / 60 + 1)
        feature_columns.extend(['read_write_ratio', 'ops_per_minute'])
        
        X = self.behavior_data[feature_columns]
        y = self.behavior_data['risk_score']
        
        return X, y
    
    def train_anomaly_detection_model(self):
        """训练异常检测模型"""
        self.logger.info("开始训练异常检测模型...")
        
        X, y = self.preprocess_anomaly_data()
        
        # 数据标准化
        X_scaled = self.scaler.fit_transform(X)
        
        # 训练Isolation Forest模型
        self.anomaly_model = IsolationForest(
            contamination=0.1,  # 假设10%的数据是异常
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0
        )
        
        self.anomaly_model.fit(X_scaled)
        
        # 评估模型
        predictions = self.anomaly_model.predict(X_scaled)
        predictions_binary = (predictions == -1).astype(int)
        
        accuracy = accuracy_score(y, predictions_binary)
        self.logger.info(f"异常检测模型准确率: {accuracy:.4f}")
        
        # 打印分类报告
        print("\n异常检测分类报告:")
        print(classification_report(y, predictions_binary, target_names=['正常', '异常']))
        
        return self.anomaly_model
    
    def train_threat_classification_model(self):
        """训练威胁分类模型"""
        self.logger.info("开始训练威胁分类模型...")
        
        X, y = self.preprocess_threat_data()
        
        # 移除缺失值
        mask = ~y.isna()
        X = X[mask]
        y = y[mask]
        
        # 数据标准化
        X_scaled = self.scaler.fit_transform(X)
        
        # 分割训练和测试数据
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # 训练随机森林分类器
        self.threat_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced'
        )
        
        self.threat_classifier.fit(X_train, y_train)
        
        # 评估模型
        train_score = self.threat_classifier.score(X_train, y_train)
        test_score = self.threat_classifier.score(X_test, y_test)
        
        self.logger.info(f"威胁分类模型训练准确率: {train_score:.4f}")
        self.logger.info(f"威胁分类模型测试准确率: {test_score:.4f}")
        
        # 预测和评估
        y_pred = self.threat_classifier.predict(X_test)
        
        # 打印分类报告
        threat_names = list(self.threat_mapping.keys())
        print("\n威胁分类报告:")
        print(classification_report(y_test, y_pred, target_names=threat_names))
        
        # 特征重要性
        feature_importance = self.threat_classifier.feature_importances_
        feature_names = X.columns
        
        print("\n特征重要性:")
        for name, importance in zip(feature_names, feature_importance):
            print(f"{name}: {importance:.4f}")
        
        return self.threat_classifier
    
    def train_behavior_analysis_model(self):
        """训练行为分析模型"""
        self.logger.info("开始训练行为分析模型...")
        
        X, y = self.preprocess_behavior_data()
        
        # 数据标准化
        X_scaled = self.scaler.fit_transform(X)
        
        # 将连续的风险分数转换为分类标签
        y_categorical = pd.cut(y, bins=[0, 0.3, 0.6, 1.0], labels=[0, 1, 2], include_lowest=True)
        
        # 分割训练和测试数据
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_categorical, test_size=0.2, random_state=42
        )
        
        # 训练梯度提升分类器
        self.behavior_model = GradientBoostingClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=6,
            learning_rate=0.1,
            min_samples_split=5,
            min_samples_leaf=2
        )
        
        self.behavior_model.fit(X_train, y_train)
        
        # 评估模型
        train_score = self.behavior_model.score(X_train, y_train)
        test_score = self.behavior_model.score(X_test, y_test)
        
        self.logger.info(f"行为分析模型训练准确率: {train_score:.4f}")
        self.logger.info(f"行为分析模型测试准确率: {test_score:.4f}")
        
        # 预测和评估
        y_pred = self.behavior_model.predict(X_test)
        
        # 打印分类报告
        risk_levels = ['低风险', '中风险', '高风险']
        print("\n行为分析分类报告:")
        print(classification_report(y_test, y_pred, target_names=risk_levels))
        
        return self.behavior_model
    
    def train_clustering_model(self):
        """训练聚类模型用于模式发现"""
        self.logger.info("开始训练聚类模型...")
        
        # 使用文件访问模式数据
        feature_columns = [
            'access_frequency', 'unique_clients', 'avg_file_size', 
            'read_write_ratio', 'access_time_variance'
        ]
        
        # 编码分类特征
        variance_mapping = {'low': 0, 'medium': 1, 'high': 2}
        self.access_patterns['variance_encoded'] = self.access_patterns['access_time_variance'].map(variance_mapping)
        
        sensitivity_mapping = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        self.access_patterns['sensitivity_encoded'] = self.access_patterns['sensitivity_level'].map(sensitivity_mapping)
        
        feature_columns.extend(['variance_encoded', 'sensitivity_encoded'])
        
        X = self.access_patterns[feature_columns]
        X_scaled = self.scaler.fit_transform(X)
        
        # 训练DBSCAN聚类模型
        self.clustering_model = DBSCAN(
            eps=0.5,
            min_samples=3,
            metric='euclidean'
        )
        
        cluster_labels = self.clustering_model.fit_predict(X_scaled)
        
        # 分析聚类结果
        n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
        n_noise = list(cluster_labels).count(-1)
        
        self.logger.info(f"聚类数量: {n_clusters}")
        self.logger.info(f"噪声点数量: {n_noise}")
        
        # 添加聚类标签到数据
        self.access_patterns['cluster'] = cluster_labels
        
        return self.clustering_model
    
    def save_models(self, output_dir='trained_models'):
        """保存所有训练好的模型"""
        self.logger.info(f"保存模型到 {output_dir}...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        models_data = {
            'anomaly_model': self.anomaly_model,
            'threat_classifier': self.threat_classifier,
            'behavior_model': self.behavior_model,
            'clustering_model': self.clustering_model,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'threat_mapping': self.threat_mapping,
            'training_timestamp': datetime.now().isoformat()
        }
        
        # 保存模型
        with open(os.path.join(output_dir, 'nfs_security_models.pkl'), 'wb') as f:
            pickle.dump(models_data, f)
        
        # 保存模型元数据
        metadata = {
            'anomaly_model_type': 'IsolationForest',
            'threat_classifier_type': 'RandomForestClassifier',
            'behavior_model_type': 'GradientBoostingClassifier',
            'clustering_model_type': 'DBSCAN',
            'feature_count': {
                'anomaly': len(self.anomaly_data.columns) if hasattr(self, 'anomaly_data') else 0,
                'threat': len(self.threat_data.columns) if hasattr(self, 'threat_data') else 0,
                'behavior': len(self.behavior_data.columns) if hasattr(self, 'behavior_data') else 0
            },
            'training_data_size': {
                'anomaly': len(self.anomaly_data) if hasattr(self, 'anomaly_data') else 0,
                'threat': len(self.threat_data) if hasattr(self, 'threat_data') else 0,
                'behavior': len(self.behavior_data) if hasattr(self, 'behavior_data') else 0
            }
        }
        
        with open(os.path.join(output_dir, 'model_metadata.json'), 'w') as f:
            import json
            json.dump(metadata, f, indent=2)
        
        self.logger.info("模型保存完成")
    
    def train_all_models(self):
        """训练所有模型"""
        self.logger.info("开始训练所有ML模型...")
        
        # 加载数据
        self.load_training_data()
        
        # 训练各个模型
        self.train_anomaly_detection_model()
        self.train_threat_classification_model()
        self.train_behavior_analysis_model()
        self.train_clustering_model()
        
        # 保存模型
        self.save_models()
        
        self.logger.info("所有模型训练完成！")

def main():
    """主函数"""
    print("NFS eBPF监控系统ML模型训练")
    print("=" * 50)
    
    trainer = NFSMLTrainer()
    trainer.train_all_models()
    
    print("\n训练完成！模型已保存到 'trained_models' 目录")
    print("\n使用方法:")
    print("1. 将训练好的模型复制到NFS监控系统目录")
    print("2. 在nfs_monitor_loader.py中加载模型")
    print("3. 启动NFS eBPF监控系统")

if __name__ == "__main__":
    main()