#!/usr/bin/env python3
import os
import random
import concurrent.futures
import argparse
from pathlib import Path

def parse_size(size_str):
    units = {"K": 1024, "M": 1024**2, "G": 1024**3}
    unit = size_str[-1].upper()
    if unit.isdigit():
        return int(size_str)
    return int(size_str[:-1]) * units[unit]

def write_file(file_path, size_bytes):
    try:
        # 生成随机内容并写入
        data = os.urandom(size_bytes)
        with open(file_path, "wb") as f:
            f.write(data)
        return True
    except Exception as e:
        print(f"写入失败 {file_path}: {str(e)}")
        return False

def read_file(file_path):
    try:
        with open(file_path, "rb") as f:
            while f.read(4096):  # 模拟真实读取
                pass
        return True
    except Exception as e:
        print(f"读取失败 {file_path}: {str(e)}")
        return False

def delete_file(file_path):
    try:
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"删除失败 {file_path}: {str(e)}")
        return False

def nfs_stress_test(mount_point, file_count, file_size, concurrency):
    size_bytes = parse_size(file_size)
    test_dir = Path(mount_point) / "test_dir"
    
    # 创建测试目录
    test_dir.mkdir(exist_ok=True)
    print(f"测试目录: {test_dir}")

    # 生成文件路径列表
    files = [test_dir / f"file_{i}" for i in range(1, file_count+1)]

    # 并发写入测试
    print(f"开始写入 {file_count} 个文件 (每个 {file_size})...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(write_file, str(path), size_bytes) for path in files]
        success = sum(f.result() for f in futures)
    print(f"写入完成: {success}/{file_count} 成功")

    # 并发读取测试
    print(f"\n开始读取 {file_count} 个文件...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(read_file, str(path)) for path in files]
        success = sum(f.result() for f in futures)
    print(f"读取完成: {success}/{file_count} 成功")

    # 并发清理测试
    print(f"\n开始清理 {file_count} 个文件...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(delete_file, str(path)) for path in files]
        success = sum(f.result() for f in futures)
    print(f"清理完成: {success}/{file_count} 成功")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NFS 压力测试脚本")
    parser.add_argument("--mount", default="/mnt/nfs_clientshare", help="NFS 挂载点路径")
    parser.add_argument("--count", type=int, default=100, help="测试文件数量")
    parser.add_argument("--size", default="1M", help="文件大小 (支持 K/M/G，如 4K, 2M)")
    parser.add_argument("--concurrency", type=int, default=10, help="并发线程数")
    
    args = parser.parse_args()

    print(f"""
    NFS 压力测试参数:
    - 挂载点: {args.mount}
    - 文件数量: {args.count}
    - 文件大小: {args.size}
    - 并发数: {args.concurrency}
    """)

    nfs_stress_test(
        mount_point=args.mount,
        file_count=args.count,
        file_size=args.size,
        concurrency=args.concurrency
    )
