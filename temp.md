#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fs_context.h>
#include <linux/nfs_fs_sb.h>
#include <linux/sunrpc/svc.h>
#include <linux/lsm_hooks.h>

/* ================= 全局数据结构定义 ================= */
// 客户端信息结构
struct client_info {
    __u32 ipv4_addr;
    __u16 port;
    __u8 protocol;
    __u64 last_access;
};

// 文件操作事件
struct file_event {
    __u64 timestamp;
    __u64 inode;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 operation; // OPEN=0, READ=1, WRITE=2, UNLINK=3, SETATTR=4
    char filename[256];
    char client_ip[16];
};

// 规则引擎结构
struct path_rule {
    char path[256];
    __u32 flags; // PROTECTED=1, EXEC_CHECK=2, SIGNATURE=4
};

/* ================= eBPF Maps 定义 ================= */
// 黑名单Map (客户端IP)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // IPv4地址
    __type(value, __u8); // 阻止原因码
} blocklist SEC(".maps");

// 关键路径保护Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct path_rule);
    __type(value, __u8); // 保护级别
} critical_paths SEC(".maps");

// 文件签名Map (inode->签名)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); // inode编号
    __type(value, __u64); // 文件签名
} file_signatures SEC(".maps");

// 事件上报Ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 访问时间规则Map (小时位图)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32); // 路径哈希
    __type(value, __u32); // 24位时间位图(每bit代表1小时)
} access_times SEC(".maps");

// 客户端会话Map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sockaddr_in); // 客户端地址
    __type(value, struct client_info); // 客户端信息
} client_sessions SEC(".maps");

/* ================= 辅助函数 ================= */
// 获取客户端IP地址 (简化版)
static int get_client_ip(struct svc_rqst *rqstp, char *buf) {
    struct sockaddr *sa = rqstp->rq_xprt->xpt_remote;
    
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        __u32 addr = sin->sin_addr.s_addr;
        bpf_snprintf(buf, 16, "%d.%d.%d.%d", 
                    addr & 0xFF, (addr >> 8) & 0xFF,
                    (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
        return 0;
    }
    return -1;
}

// 检查路径是否关键文件
static bool is_critical_path(struct dentry *dentry) {
    struct path_rule rule = {};
    struct qstr qname = dentry->d_name;
    
    // 获取完整路径 (简化实现)
    char path[256];
    bpf_probe_read_kernel_str(path, sizeof(path), qname.name);
    
    // 检查路径规则 (实际应遍历critical_paths map)
    __u32 key = bpf_crc32(path, bpf_strnlen(path, 256));
    __u8 *level = bpf_map_lookup_elem(&critical_paths, &key);
    
    return level != NULL;
}

// 验证文件签名
static bool verify_signature(struct file *file) {
    __u64 ino = file->f_inode->i_ino;
    __u64 *stored_sig = bpf_map_lookup_elem(&file_signatures, &ino);
    if (!stored_sig) return true; // 未注册文件默认通过
    
    // 计算当前签名 (简化)
    __u64 current_sig = file->f_inode->i_size + file->f_inode->i_mtime.tv_sec;
    return *stored_sig == current_sig;
}

// 检查访问时间是否允许
static bool check_access_time(struct dentry *dentry) {
    struct qstr qname = dentry->d_name;
    char path[256];
    bpf_probe_read_kernel_str(path, sizeof(path), qname.name);
    
    __u32 key = bpf_crc32(path, bpf_strnlen(path, 256));
    __u32 *bitmap = bpf_map_lookup_elem(&access_times, &key);
    if (!bitmap) return true; // 无时间限制
    
    // 获取当前小时 (UTC)
    __u64 ts = bpf_ktime_get_ns();
    __u32 hour = (ts / (3600 * NSEC_PER_SEC)) % 24;
    
    return (*bitmap >> hour) & 1;
}

/* ================= LSM 钩子实现 ================= */
// 1. 文件访问控制
SEC("lsm/file_open")
int BPF_PROG(nfs_file_open, struct file *file) {
    // 检查客户端IP黑名单
    struct sockaddr_in client_addr = {};
    __u32 *block_reason = bpf_map_lookup_elem(&blocklist, &client_addr.sin_addr.s_addr);
    if (block_reason) {
        bpf_printk("阻止黑名单客户端访问");
        return -EACCES;
    }
    
    // 验证文件签名
    if (!verify_signature(file)) {
        bpf_printk("文件签名验证失败: %s", file->f_path.dentry->d_name.name);
        return -EACCES;
    }
    
    // 检查访问时间规则
    if (!check_access_time(file->f_path.dentry)) {
        bpf_printk("非允许时间访问: %s", file->f_path.dentry->d_name.name);
        return -EACCES;
    }
    
    // 事件上报
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->inode = file->f_inode->i_ino;
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = bpf_get_current_uid_gid();
        event->operation = 0; // OPEN
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), 
                   file->f_path.dentry->d_name.name);
        get_client_ip(NULL, event->client_ip);
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// 2. 权限验证
SEC("lsm/file_permission")
int BPF_PROG(nfs_file_permission, struct file *file, int mask) {
    // 写保护文件检测
    if (mask & MAY_WRITE && is_critical_path(file->f_path.dentry)) {
        bpf_printk("阻止写保护文件: %s", file->f_path.dentry->d_name.name);
        return -EPERM;
    }
    
    // 可执行文件验证
    if (mask & MAY_EXEC) {
        // 实际应检查文件签名/哈希
        if (!verify_signature(file)) {
            bpf_printk("阻止未验证可执行文件: %s", file->f_path.dentry->d_name.name);
            return -EACCES;
        }
    }
    return 0;
}

// 3. 删除防护
SEC("lsm/inode_unlink")
int BPF_PROG(nfs_unlink, struct inode *dir, struct dentry *dentry) {
    if (is_critical_path(dentry)) {
        bpf_printk("阻止删除关键文件: %s", dentry->d_name.name);
        return -EPERM;
    }
    
    // 事件上报
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->inode = dentry->d_inode->i_ino;
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = bpf_get_current_uid_gid();
        event->operation = 3; // UNLINK
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), 
                   dentry->d_name.name);
        get_client_ip(NULL, event->client_ip);
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// 4. 属性篡改防护
SEC("lsm/inode_setattr")
int BPF_PROG(nfs_setattr, struct dentry *dentry, struct iattr *attr) {
    // 防止权限提升攻击
    if (attr->ia_valid & ATTR_MODE) {
        if ((attr->ia_mode & S_ISUID) && !capable(CAP_SETUID)) {
            bpf_printk("阻止权限提升尝试: %s", dentry->d_name.name);
            return -EPERM;
        }
    }
    
    // 检测隐藏文件操作
    if ((attr->ia_valid & ATTR_ATIME) && 
        (bpf_ktime_get_ns() - dentry->d_inode->i_atime.tv_nsec) > 3600 * NSEC_PER_SEC) {
        bpf_printk("检测到时间篡改: %s", dentry->d_name.name);
    }
    
    return 0;
}

// 5. 符号链接劫持防护
SEC("lsm/inode_follow_link")
int BPF_PROG(nfs_follow_link, struct dentry *dentry, struct inode *inode) {
    char target[256];
    bpf_probe_read_kernel_str(target, sizeof(target), dentry->d_iname);
    
    // 检查是否指向敏感区域
    if (bpf_strstr(target, "/etc") || bpf_strstr(target, "/root")) {
        bpf_printk("阻止敏感符号链接: %s -> %s", dentry->d_name.name, target);
        return -EACCES;
    }
    return 0;
}

// 6. 文件锁定监控
SEC("lsm/file_lock")
int BPF_PROG(nfs_file_lock, struct file *file, unsigned int cmd) {
    // 长时间写锁定检测 (勒索软件特征)
    if (cmd == F_WRLCK) {
        __u64 now = bpf_ktime_get_ns();
        __u64 *lock_time = bpf_map_lookup_elem(&file_lock_times, &file->f_inode->i_ino);
        
        if (!lock_time) {
            __u64 init_time = now;
            bpf_map_update_elem(&file_lock_times, &file->f_inode->i_ino, &init_time, BPF_ANY);
        } else if ((now - *lock_time) > 60 * NSEC_PER_SEC) { // 60秒阈值
            bpf_printk("检测到长时间文件锁定: %s", file->f_path.dentry->d_name.name);
            return -EAGAIN; // 强制解锁
        }
    }
    return 0;
}

// 7. RPC 请求验证
SEC("kprobe/nfsd_dispatch")
int BPF_KPROBE(nfsd_dispatch, struct svc_rqst *rqstp) {
    char client_ip[16];
    get_client_ip(rqstp, client_ip);
    
    // 高频小文件写入检测
    if (rqstp->rq_proc == NFSPROC3_WRITE) {
        // 更新客户端统计
        struct client_info *info = bpf_map_lookup_elem(&client_sessions, &rqstp->rq_xprt->xpt_remote);
        if (!info) {
            struct client_info new_info = {
                .ipv4_addr = ((struct sockaddr_in *)rqstp->rq_xprt->xpt_remote)->sin_addr.s_addr,
                .last_access = bpf_ktime_get_ns(),
                .write_count = 1
            };
            bpf_map_update_elem(&client_sessions, &rqstp->rq_xprt->xpt_remote, &new_info, BPF_ANY);
        } else {
            // 高频写入检测 (1秒内超过100次)
            if (bpf_ktime_get_ns() - info->last_access < NSEC_PER_SEC) {
                if (info->write_count++ > 100) {
                    bpf_printk("检测到高频写入攻击: %s", client_ip);
                    bpf_map_update_elem(&blocklist, &info->ipv4_addr, 1, BPF_ANY);
                }
            } else {
                info->write_count = 1;
            }
            info->last_access = bpf_ktime_get_ns();
        }
    }
    return 0;
}

// 8. 文件委托防护
SEC("kprobe/nfsd_deleg_return")
int BPF_KPROBE(deleg_return, struct inode *inode) {
    // 检测异常委托释放
    __u64 *deleg_time = bpf_map_lookup_elem(&delegation_times, inode);
    if (deleg_time) {
        if (bpf_ktime_get_ns() - *deleg_time < 5 * NSEC_PER_SEC) {
            bpf_printk("检测到异常委托释放: inode %lu", inode->i_ino);
        }
        bpf_map_delete_elem(&delegation_times, inode);
    }
    return 0;
}

// 9. NFS 状态监控
SEC("kprobe/nfsd_file_close")
int BPF_KPROBE(nfsd_file_close, struct inode *inode) {
    // 检测异常关闭模式
    if (current->flags & PF_EXITING) {
        bpf_printk("进程退出时关闭NFS文件: inode %lu", inode->i_ino);
    }
    return 0;
}

// 10. 客户端身份验证
SEC("kprobe/nfsd_init_request")
int BPF_KPROBE(nfsd_init_request, struct svc_rqst *rqstp) {
    struct sockaddr *client = rqstp->rq_xprt->xpt_remote;
    char client_ip[16];
    get_client_ip(rqstp, client_ip);
    
    // 实际应检查X.509证书
    if (!bpf_map_lookup_elem(&trusted_clients, client)) {
        bpf_printk("未授权客户端访问: %s", client_ip);
        return -EACCES;
    }
    return 0;
}

// 11. 进程行为分析
SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(check_exec, struct linux_binprm *bprm) {
    // 检测通过NFS执行的恶意程序
    if (bprm->file->f_path.dentry->d_sb->s_magic == NFS_SUPER_MAGIC) {
        // 实际应检查文件签名
        if (!verify_signature(bprm->file)) {
            bpf_printk("阻止未验证NFS可执行文件: %s", 
                      bprm->file->f_path.dentry->d_name.name);
            return -EACCES;
        }
    }
    return 0;
}

/* ====== 路径规则引擎 (用户态加载) ====== */
// 重要文件路径规则库
const struct path_rule CRITICAL_PATH_RULES[] = {
    { .path = "/etc/passwd", .flags = 0x1 },
    { .path = "/etc/shadow", .flags = 0x1 },
    { .path = "/etc/sudoers", .flags = 0x1 },
    { .path = "/etc/ssh/sshd_config", .flags = 0x1 },
    { .path = "/root/.ssh/", .flags = 0x1 },
    { .path = "/var/log/secure", .flags = 0x1 },
    { .path = "/var/log/auth.log", .flags = 0x1 },
    { .path = "/var/log/audit/audit.log", .flags = 0x1 },
    { .path = "/opt/app/conf/", .flags = 0x1 },
    { .path = "/opt/finance/conf/", .flags = 0x1 },
    { .path = "/data/finance/", .flags = 0x1 },
    { .path = "/data/hr/", .flags = 0x1 },
    { .path = "/backups/", .flags = 0x1 },
    { .path = "/usr/bin/sudo", .flags = 0x2 },
    { .path = "/usr/bin/su", .flags = 0x2 },
    { .path = "/usr/bin/ssh", .flags = 0x2 },
    { .path = "/usr/bin/scp", .flags = 0x2 },
    { .path = "/opt/app/bin/", .flags = 0x2 }
};

char _license[] SEC("license") = "GPL";






nfs_security_loader.py
#!/usr/bin/env python3
from bcc import BPF
import ctypes
import time
import argparse
import os
import ipaddress
import hashlib

# 命令行参数解析
parser = argparse.ArgumentParser(description='NFS安全监控系统')
parser.add_argument('--verbose', '-v', action='store_true', help='详细输出模式')
parser.add_argument('--no-attach', action='store_true', help='仅加载程序不附加探针')
parser.add_argument('--rules', default='rules.conf', help='规则配置文件路径')
args = parser.parse_args()

# 路径规则结构定义 (必须与eBPF程序中的结构匹配)
class PathRule(ctypes.Structure):
    _fields_ = [
        ("path", ctypes.c_char * 256),
        ("flags", ctypes.c_uint32)
    ]

# 访问时间规则结构
class AccessTimeRule(ctypes.Structure):
    _fields_ = [
        ("path_hash", ctypes.c_uint32),
        ("bitmap", ctypes.c_uint32)
    ]

# 黑名单条目
class BlocklistEntry(ctypes.Structure):
    _fields_ = [
        ("ip", ctypes.c_uint32),
        ("reason", ctypes.c_uint8)
    ]

def load_configuration(bpf):
    """从配置文件加载规则"""
    if not os.path.exists(args.rules):
        print(f"警告: 规则文件 {args.rules} 不存在, 使用默认规则")
        return
    
    print(f"加载规则文件: {args.rules}")
    with open(args.rules, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split()
            rule_type = parts[0]
            
            if rule_type == 'PROTECT_PATH':
                path = parts[1].encode()
                flags = int(parts[2]) if len(parts) > 2 else 1
                add_protected_path(bpf, path, flags)
                
            elif rule_type == 'ACCESS_TIME':
                path = parts[1].encode()
                hours = parts[2].split(',')
                set_access_time(bpf, path, hours)
                
            elif rule_type == 'BLOCK_CLIENT':
                ip = parts[1]
                reason = int(parts[2]) if len(parts) > 2 else 1
                block_client(bpf, ip, reason)
                
            elif rule_type == 'FILE_SIGNATURE':
                path = parts[1]
                signature = int(parts[2])
                # 实际应用中需要计算文件签名
                print(f"文件签名规则: {path} -> {signature} (暂未实现)")

def add_protected_path(bpf, path, flags=1):
    """添加受保护路径规则"""
    if args.verbose:
        print(f"添加保护路径: {path.decode()} (flags={flags})")
    
    rule = PathRule()
    rule.path = path
    rule.flags = flags
    
    # 计算路径哈希作为键
    path_hash = hashlib.md5(path).hexdigest()
    key = ctypes.c_uint32(int(path_hash[:8], 16))
    
    critical_paths = bpf["critical_paths"]
    critical_paths[ctypes.pointer(key)] = ctypes.c_uint8(1)

def set_access_time(bpf, path, allowed_hours):
    """设置文件访问时间规则"""
    if args.verbose:
        print(f"设置访问时间: {path.decode()} -> {allowed_hours}")
    
    # 计算时间位图
    bitmap = 0
    for hour in allowed_hours:
        try:
            h = int(hour)
            if 0 <= h <= 23:
                bitmap |= (1 << h)
        except ValueError:
            continue
    
    # 计算路径哈希
    path_hash = hashlib.md5(path).hexdigest()
    key = ctypes.c_uint32(int(path_hash[:8], 16))
    
    access_map = bpf["access_times"]
    access_map[ctypes.pointer(key)] = ctypes.c_uint32(bitmap)

def block_client(bpf, ip_str, reason=1):
    """添加客户端到黑名单"""
    try:
        ip = int(ipaddress.IPv4Address(ip_str))
    except ipaddress.AddressValueError:
        print(f"无效IP地址: {ip_str}")
        return
        
    if args.verbose:
        print(f"添加黑名单客户端: {ip_str} (原因: {reason})")
    
    block_map = bpf["blocklist"]
    key = ctypes.c_uint32(ip)
    block_map[ctypes.pointer(key)] = ctypes.c_uint8(reason)

def handle_event(cpu, data, size):
    """处理内核事件回调"""
    event = bpf["events"].event(data)
    op_types = ["OPEN", "READ", "WRITE", "UNLINK", "SETATTR"]
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp))
    operation = op_types[event.operation] if event.operation < len(op_types) else "UNKNOWN"
    
    print(f"[{timestamp}] 安全事件: {operation} {event.filename.decode()}")
    print(f"  客户端: {event.client_ip.decode()}, PID: {event.pid}, UID: {event.uid}")
    print(f"  Inode: {event.inode}, 时间: {event.timestamp}")

def load_default_rules(bpf):
    """加载默认规则集"""
    # 关键文件保护
    protected_paths = [
        (b"/etc/passwd", 1),
        (b"/etc/shadow", 1),
        (b"/etc/sudoers", 1),
        (b"/etc/ssh/sshd_config", 1),
        (b"/root/.ssh/", 1),
        (b"/var/log/secure", 1),
        (b"/var/log/auth.log", 1),
        (b"/var/log/audit/audit.log", 1),
        (b"/opt/app/conf/", 1),
        (b"/opt/finance/conf/", 1),
        (b"/data/finance/", 1),
        (b"/data/hr/", 1),
        (b"/backups/", 1)
    ]
    
    # 可执行文件验证
    executable_paths = [
        (b"/usr/bin/sudo", 2),
        (b"/usr/bin/su", 2),
        (b"/usr/bin/ssh", 2),
        (b"/usr/bin/scp", 2),
        (b"/opt/app/bin/", 2)
    ]
    
    # 访问时间规则
    access_rules = [
        (b"/data/finance/", [9, 10, 11, 12, 13, 14, 15, 16, 17]),  # 工作时间
        (b"/backups/", list(range(0, 24))),  # 全天访问
        (b"/root/", [22, 23, 0, 1, 2, 3, 4, 5, 6])  # 夜间维护时段
    ]
    
    # 黑名单客户端
    blocked_clients = [
        ("192.168.1.100", 1),  # 已知恶意IP
        ("10.0.0.55", 2)       # 可疑活动IP
    ]
    
    # 加载规则
    for path, flags in protected_paths + executable_paths:
        add_protected_path(bpf, path, flags)
    
    for path, hours in access_rules:
        set_access_time(bpf, path, hours)
    
    for ip, reason in blocked_clients:
        block_client(bpf, ip, reason)

def main():
    # 加载并编译eBPF程序
    try:
        if args.verbose:
            print("编译和加载eBPF程序...")
        bpf = BPF(src_file="nfs_security.bpf.c", cflags=["-Wno-macro-redefined"])
    except Exception as e:
        print(f"加载eBPF程序失败: {str(e)}")
        print("请确保: 1) 内核版本>=5.7 2) 启用CONFIG_BPF_LSM 3) 安装LLVM/clang")
        return
    
    # 初始化规则
    if os.path.exists(args.rules):
        load_configuration(bpf)
    else:
        if args.verbose:
            print("使用默认规则集")
        load_default_rules(bpf)
    
    # 附加LSM钩子
    if not args.no_attach:
        lsm_hooks = [
            ("file_open", "nfs_file_open"),
            ("file_permission", "nfs_file_permission"),
            ("inode_unlink", "nfs_unlink"),
            ("inode_setattr", "nfs_setattr"),
            ("inode_follow_link", "nfs_follow_link"),
            ("file_lock", "nfs_file_lock"),
            ("bprm_creds_for_exec", "check_exec")
        ]
        
        for hook, func in lsm_hooks:
            try:
                bpf.attach_lsm_hook(hook=hook, fn_name=func)
                if args.verbose:
                    print(f"已附加LSM钩子: {hook} -> {func}")
            except Exception as e:
                print(f"附加LSM钩子失败 {hook}: {str(e)}")
        
        # 附加kprobes
        kprobes = [
            ("nfsd_dispatch", "nfsd_dispatch"),
            ("nfsd_deleg_return", "deleg_return"),
            ("nfsd_file_close", "nfsd_file_close"),
            ("nfsd_init_request", "nfsd_init_request")
        ]
        
        for func, prog in kprobes:
            try:
                bpf.attach_kprobe(event=func, fn_name=prog)
                if args.verbose:
                    print(f"已附加kprobe: {func} -> {prog}")
            except Exception as e:
                print(f"附加kprobe失败 {func}: {str(e)}")
    
    # 设置事件回调
    bpf["events"].open_ring_buffer(handle_event)
    
    print("NFS安全监控系统已启动")
    print("按Ctrl-C退出")
    
    # 主循环
    try:
        while True:
            bpf.ring_buffer_consume()
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n正在清理...")
        bpf.cleanup()

if __name__ == "__main__":
    main()
