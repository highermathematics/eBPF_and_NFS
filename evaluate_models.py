#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NFS eBPF监控系统ML模型评估脚本
"""

import pandas as pd
import numpy as np
import pickle
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from sklearn.model_selection import cross_val_score

class NFSModelEvaluator:
    def __init__(self, models_dir='trained_models', data_dir='models'):
        self.models_dir = models_dir
        self.data_dir = data_dir
        self.models = None
        
    def load_models(self):
        """加载训练好的模型"""
        model_path = os.path.join(self.models_dir, 'nfs_security_models.pkl')
        
        with open(model_path, 'rb') as f:
            self.models = pickle.load(f)
        
        print("模型加载成功")
    
    def evaluate_anomaly_model(self):
        """评估异常检测模型"""
        print("\n=== 异常检测模型评估 ===")
        
        # 加载测试数据
        test_data = pd.read_csv(os.path.join(self.data_dir, 'test_dataset.csv'))
        
        # 预处理测试数据（与训练时相同的处理）
        feature_columns = [
            'operation_count', 'file_size', 'read_bytes', 'write_bytes',
            'error_count', 'response_time'
        ]
        
        # 添加特征
        test_data['ip_last_octet'] = test_data['client_ip'].str.split('.').str[3].astype(int)
        
        from sklearn.preprocessing import LabelEncoder
        operation_encoder = LabelEncoder()
        test_data['operation_encoded'] = operation_encoder.fit_transform(test_data['operation_type'])
        
        test_data['path_length'] = test_data['file_path'].str.len()
        test_data['path_depth'] = test_data['file_path'].str.count('/')
        test_data['is_system_file'] = test_data['file_path'].str.contains('/etc/|/proc/|/sys/').astype(int)
        
        test_data['hour'] = pd.to_datetime(test_data['access_time'], unit='s').dt.hour
        test_data['is_night'] = ((test_data['hour'] >= 22) | (test_data['hour'] <= 6)).astype(int)
        
        feature_columns.extend(['ip_last_octet', 'operation_encoded', 'path_length', 'path_depth', 'is_system_file', 'hour', 'is_night'])
        
        X_test = test_data[feature_columns]
        X_test_scaled = self.models['scaler'].transform(X_test)
        
        # 预测
        predictions = self.models['anomaly_model'].predict(X_test_scaled)
        anomaly_scores = self.models['anomaly_model'].decision_function(X_test_scaled)
        
        # 创建真实标签（基于规则）
        y_true = ((test_data['error_count'] > 1) | 
                 (test_data['response_time'] > 0.2) | 
                 (test_data['file_path'].str.contains('/etc/shadow|/tmp/backdoor'))).astype(int)
        
        y_pred = (predictions == -1).astype(int)
        
        print(f"检测到的异常数量: {sum(y_pred)}")
        print(f"异常检测准确率: {sum(y_true == y_pred) / len(y_true):.4f}")
        
        # 绘制异常分数分布
        plt.figure(figsize=(10, 6))
        plt.hist(anomaly_scores, bins=30, alpha=0.7)
        plt.title('异常分数分布')
        plt.xlabel('异常分数')
        plt.ylabel('频率')
        plt.savefig('anomaly_scores_distribution.png')
        plt.show()
    
    def evaluate_threat_model(self):
        """评估威胁分类模型"""
        print("\n=== 威胁分类模型评估 ===")
        
        # 加载威胁分类数据
        threat_data = pd.read_csv(os.path.join(self.data_dir, 'threat_classification_train.csv'))
        
        # 预处理（与训练时相同）
        feature_columns = ['uid', 'gid']
        
        from sklearn.preprocessing import LabelEncoder
        operation_encoder = LabelEncoder()
        threat_data['operation_encoded'] = operation_encoder.fit_transform(threat_data['operation_type'])
        
        pattern_encoder = LabelEncoder()
        threat_data['pattern_encoded'] = pattern_encoder.fit_transform(threat_data['access_pattern'])
        
        freq_mapping = {'low': 0, 'medium': 1, 'high': 2}
        threat_data['frequency_encoded'] = threat_data['frequency'].map(freq_mapping)
        
        threat_data['path_length'] = threat_data['file_path'].str.len()
        threat_data['path_depth'] = threat_data['file_path'].str.count('/')
        threat_data['is_system_file'] = threat_data['file_path'].str.contains('/etc/|/proc/|/sys/').astype(int)
        threat_data['is_tmp_file'] = threat_data['file_path'].str.contains('/tmp/').astype(int)
        threat_data['ip_last_octet'] = threat_data['client_ip'].str.split('.').str[3].astype(int)
        
        feature_columns.extend(['operation_encoded', 'pattern_encoded', 'frequency_encoded', 
                               'path_length', 'path_depth', 'is_system_file', 'is_tmp_file', 'ip_last_octet'])
        
        X = threat_data[feature_columns]
        X_scaled = self.models['scaler'].transform(X)
        
        # 预测
        predictions = self.models['threat_classifier'].predict(X_scaled)
        probabilities = self.models['threat_classifier'].predict_proba(X_scaled)
        
        # 威胁类型映射
        threat_mapping = {
            'RECONNAISSANCE': 0, 'PRIVILEGE_ESCALATION': 1, 'MALWARE_DEPLOYMENT': 2,
            'DATA_EXFILTRATION': 3, 'LOG_TAMPERING': 4, 'PERSISTENCE': 5,
            'CREDENTIAL_THEFT': 6, 'ACCOUNT_MANIPULATION': 7, 'LOG_ANALYSIS': 8
        }
        
        y_true = threat_data['threat_type'].map(threat_mapping)
        
        # 评估结果
        accuracy = sum(y_true == predictions) / len(y_true)
        print(f"威胁分类准确率: {accuracy:.4f}")
        
        # 混淆矩阵
        cm = confusion_matrix(y_true, predictions)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('威胁分类混淆矩阵')
        plt.ylabel('真实标签')
        plt.xlabel('预测标签')
        plt.savefig('threat_confusion_matrix.png')
        plt.show()
    
    def generate_evaluation_report(self):
        """生成评估报告"""
        print("\n=== 模型评估报告 ===")
        
        self.evaluate_anomaly_model()
        self.evaluate_threat_model()
        
        print("\n评估完成！结果图表已保存。")

def main():
    evaluator = NFSModelEvaluator()
    evaluator.load_models()
    evaluator.generate_evaluation_report()

if __name__ == "__main__":
    main()