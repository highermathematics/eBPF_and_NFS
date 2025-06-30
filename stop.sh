#!/bin/bash
# NFS eBPF项目停止脚本

echo "停止NFS eBPF监控系统..."

# 停止监控程序
echo "停止监控程序..."
sudo pkill -f nfs_ebpf_loader || true
sudo pkill -f nfs_monitor_loader.py || true

# 卸载eBPF程序
echo "卸载eBPF程序..."
sudo bpftool prog show | grep -E "xdp|tc" | awk '{print $1}' | sed 's/://' | xargs -I {} sudo bpftool prog detach id {} || true

# 清理eBPF Maps
echo "清理eBPF Maps..."
sudo bpftool map show | grep nfs | awk '{print $1}' | sed 's/://' | xargs -I {} sudo bpftool map delete id {} || true

echo "NFS eBPF监控系统已停止"