#!/bin/bash
# Ubuntu 22.04.2 LTS 依赖安装脚本

set -e

echo "开始安装eBPF NFS项目依赖..."

# 更新软件包列表
echo "更新软件包列表..."
sudo apt update

# 安装基础开发工具
echo "安装基础开发工具..."
sudo apt install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    libelf-dev \
    libcap-dev \
    libz-dev

# 安装内核开发包
echo "安装内核开发包..."
sudo apt install -y \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    linux-tools-generic

# 安装LLVM和Clang
echo "安装LLVM和Clang..."
sudo apt install -y \
    llvm \
    clang \
    libbpf-dev \
    bpftool

# 安装Python依赖
echo "安装Python依赖..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv

# 创建Python虚拟环境
echo "创建Python虚拟环境..."
python3 -m venv venv
source venv/bin/activate

# 安装Python包
echo "安装Python机器学习包..."
pip install --upgrade pip
pip install \
    bcc \
    scikit-learn==1.3.0 \
    numpy \
    pandas \
    psutil \
    colorama \
    matplotlib \
    seaborn \
    joblib \
    scipy

# 安装NFS相关工具
echo "安装NFS工具..."
sudo apt install -y \
    nfs-kernel-server \
    nfs-common \
    rpcbind

# 检查BCC安装
echo "验证BCC安装..."
python3 -c "from bcc import BPF; print('BCC安装成功')"

# 检查机器学习包安装
echo "验证机器学习包安装..."
python3 -c "import sklearn, numpy, pandas, matplotlib; print('ML包安装成功')"

# 检查eBPF支持
echo "检查eBPF内核支持..."
if [ -f /proc/config.gz ]; then
    zcat /proc/config.gz | grep -E "CONFIG_BPF|CONFIG_KPROBES" || echo "警告：某些eBPF配置可能缺失"
fi

# 设置权限
echo "设置必要权限..."
sudo sysctl -w net.core.bpf_jit_enable=1
sudo sysctl -w net.core.bpf_jit_harden=0
sudo sysctl -w kernel.unprivileged_bpf_disabled=0

# 创建模型目录
echo "创建模型存储目录..."
mkdir -p models trained_models

echo "依赖安装完成！"
echo "请运行 'source venv/bin/activate' 激活Python虚拟环境"
echo "然后可以运行 'python train_models.py' 训练ML模型"