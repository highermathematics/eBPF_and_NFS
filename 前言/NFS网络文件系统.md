# NFS (Network File System) 网络文件系统

## 基本概念
NFS（Network File System）是由Sun Microsystems开发的**分布式文件系统协议**，允许用户通过网络访问远程文件，如同访问本地文件。

## 工作原理
### 架构模型
- **客户端/服务器架构**
  - 服务器端：提供文件系统访问
  - 客户端：通过网络挂载远程文件系统
- **通信机制**
  - 基于RPC（远程过程调用）
  - 使用XDR协议保证跨系统数据一致性

### 核心操作
| 操作类型 | 功能描述 |
|---------|----------|
| mount   | 将远程文件系统挂载到本地命名空间 |
| read    | 通过RPC请求读取数据 |
| write   | 通过RPC请求写入数据 |

## 核心特性
- **透明访问**：远程文件与本地文件操作方式一致
- **高性能**
  - 支持大文件传输
  - 异步写入机制
- **灵活配置**：可定制访问权限和传输模式

## 部署指南
### 服务端配置
```bash
# 安装必要软件
yum -y install nfs-utils rpcbind

# 创建共享目录
mkdir /test
chmod 777 /test

# 配置共享规则
echo "/test 192.168.1.20(rw,sync,no_root_squash)" > /etc/exports

# 启动服务
systemctl start nfs
systemctl start rpcbind

# 防火墙配置
firewall-cmd --add-service=nfs --permanent
firewall-cmd --add-service=mountd --permanent
firewall-cmd --add-service=rpc-bind --permanent
firewall-cmd --reload
```

### 客户端配置
```bash
# 创建挂载点
mkdir /hello

# 挂载远程目录
mount -t nfs 192.168.1.10:/test /hello
```

## 应用场景
- 企业集群架构
- 分布式存储系统
- 文件共享与备份系统

## 版本演进
| 版本   | 重大改进 |
|--------|----------|
| NFSv4  | 引入状态协议，增强安全性 |
| NFSv4.1| 支持pNFS（并行NFS），提升传输效率 |

## 总结
NFS作为成熟的网络文件系统协议，提供：
- 透明的远程文件访问
- 高性能数据传输
- 灵活的配置选项

广泛应用于各类网络存储场景
