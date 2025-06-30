#!/bin/bash
# 环境检查脚本

set -e

echo "检查eBPF NFS项目运行环境..."

# 检查内核版本
echo "检查内核版本..."
KERNEL_VERSION=$(uname -r)
echo "当前内核版本: $KERNEL_VERSION"

# 检查eBPF支持
echo "检查eBPF支持..."
if [ ! -d "/sys/fs/bpf" ]; then
    echo "错误：eBPF文件系统未挂载"
    echo "请运行: sudo mount -t bpf bpf /sys/fs/bpf"
    exit 1
fi

# 检查必要工具
echo "检查必要工具..."
command -v clang >/dev/null 2>&1 || { echo "错误：clang未安装"; exit 1; }
command -v llc >/dev/null 2>&1 || { echo "错误：llc未安装"; exit 1; }
command -v bpftool >/dev/null 2>&1 || { echo "错误：bpftool未安装"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "错误：python3未安装"; exit 1; }

# 检查Python包
echo "检查Python包..."
python3 -c "import bcc" 2>/dev/null || { echo "错误：BCC Python包未安装"; exit 1; }
python3 -c "import sklearn" 2>/dev/null || { echo "错误：scikit-learn未安装"; exit 1; }
python3 -c "import numpy" 2>/dev/null || { echo "错误：numpy未安装"; exit 1; }
python3 -c "import pandas" 2>/dev/null || { echo "错误：pandas未安装"; exit 1; }

# 检查模型目录
echo "检查模型目录..."
if [ ! -d "models" ]; then
    echo "警告：models目录不存在，创建中..."
    mkdir -p models
fi

if [ ! -d "trained_models" ]; then
    echo "警告：trained_models目录不存在，创建中..."
    mkdir -p trained_models
fi

# 检查训练数据
echo "检查训练数据..."
if [ ! -f "models/anomaly_detection_train.csv" ]; then
    echo "警告：异常检测训练数据不存在"
fi

if [ ! -f "models/threat_classification_train.csv" ]; then
    echo "警告：威胁分类训练数据不存在"
fi

# 检查权限
echo "检查权限..."
if [ "$EUID" -ne 0 ]; then
    echo "警告：需要root权限运行eBPF程序"
fi

# 检查内核配置
echo "检查内核配置..."
if [ -f /proc/config.gz ]; then
    CONFIG_BPF=$(zcat /proc/config.gz | grep "CONFIG_BPF=y" || echo "")
    CONFIG_KPROBES=$(zcat /proc/config.gz | grep "CONFIG_KPROBES=y" || echo "")
    
    if [ -z "$CONFIG_BPF" ]; then
        echo "警告：CONFIG_BPF未启用"
    fi
    
    if [ -z "$CONFIG_KPROBES" ]; then
        echo "警告：CONFIG_KPROBES未启用"
    fi
fi

# 检查NFS服务
echo "检查NFS服务..."
systemctl is-active --quiet nfs-kernel-server && echo "NFS服务运行中" || echo "NFS服务未运行"

echo "环境检查完成！"
