#!/bin/bash
# 项目测试脚本

set -e

echo "运行NFS eBPF监控系统测试..."

# 激活虚拟环境
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# 测试Python模块导入
echo "测试Python模块..."
python3 -c "import ml_service; print('ML服务模块导入成功')"
python3 -c "from nfs_monitor_loader import NFSMonitorLoader; print('监控加载器模块导入成功')"

# 测试训练数据
echo "测试训练数据..."
if [ -f "models/anomaly_detection_train.csv" ]; then
    echo "异常检测训练数据存在"
else
    echo "警告：异常检测训练数据缺失"
fi

# 测试模型训练（快速测试）
echo "测试模型训练..."
if [ -f "train_models.py" ]; then
    python3 -c "from train_models import NFSMLTrainer; trainer = NFSMLTrainer(); print('训练器初始化成功')"
else
    echo "警告：训练脚本不存在"
fi

# 测试eBPF编译
echo "测试eBPF程序编译..."
make clean
make all

echo "所有测试通过！"