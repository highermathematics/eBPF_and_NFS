#!/bin/bash
# NFS eBPF项目启动脚本

set -e

# 项目根目录
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "启动NFS eBPF监控系统..."

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "错误：需要root权限运行"
    echo "请使用: sudo ./start.sh"
    exit 1
fi

# 检查环境
echo "检查运行环境..."
./scripts/check_env.sh

# 激活Python虚拟环境
if [ -d "venv" ]; then
    echo "激活Python虚拟环境..."
    source venv/bin/activate
fi

# 构建项目
echo "构建项目..."
make clean
make all

# 挂载eBPF文件系统
if [ ! -d "/sys/fs/bpf" ]; then
    echo "挂载eBPF文件系统..."
    mount -t bpf bpf /sys/fs/bpf
fi

# 启动NFS服务（如果未运行）
if ! systemctl is-active --quiet nfs-kernel-server; then
    echo "启动NFS服务..."
    systemctl start nfs-kernel-server
fi

# 检查是否需要训练模型
if [ ! -f "trained_models/nfs_security_models.pkl" ]; then
    echo "未找到训练好的模型，开始训练..."
    if [ -f "train_models.py" ]; then
        python3 train_models.py
    else
        echo "警告：未找到训练脚本，将使用在线学习模式"
    fi
fi

# 启动监控程序
echo "启动NFS eBPF监控程序..."
if [ -f "config/nfs_monitor.json" ]; then
    python3 nfs_monitor_loader.py --config config/nfs_monitor.json --verbose
else
    python3 nfs_monitor_loader.py --verbose
fi
if [ -f "config/nfs_monitor.json" ]; then
    ./nfs_ebpf_loader --config config/nfs_monitor.json
else
    ./nfs_ebpf_loader
fi