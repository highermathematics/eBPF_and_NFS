#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fs_context.h>
#include <linux/nfs_fs_sb.h>
#include <linux/sunrpc/svc.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/time.h>
#include <linux/fdtable.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/timekeeping.h>
#include <linux/pid_namespace.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/ip.h>

/* ================= 常量定义 ================= */
#define MAX_FILENAME_LEN 256
#define MAX_CLIENT_IP_LEN 16
#define MAX_PROCESS_NAME 16
#define MAX_USERNAME_LEN 32
#define MAX_PATH_LEN 512

#define OPERATION_OPEN 0
#define OPERATION_READ 1
#define OPERATION_WRITE 2
#define OPERATION_UNLINK 3
#define OPERATION_SETATTR 4
#define OPERATION_RENAME 5
#define OPERATION_CREATE 6
#define OPERATION_SYMLINK 7

#define BLOCK_RULE_PERMANENT 0
#define BLOCK_RULE_TEMPORARY 1

/* ================= 数据结构定义 ================= */
// ML特征数据结构
struct ml_feature {
    __u64 timestamp;
    __u64 inode;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 operation;
    __u32 access_flags;
    __u32 file_size;
    __u32 mode;
    __u64 parent_inode;
    __u64 session_id;
    char filename[MAX_FILENAME_LEN];
    char client_ip[MAX_CLIENT_IP_LEN];
    char process_name[MAX_PROCESS_NAME];
    char username[MAX_USERNAME_LEN];
    char full_path[MAX_PATH_LEN];
};

// 拦截规则
struct block_rule {
    __u64 inode;
    __u32 operation;
    __u32 flags;
    __u64 expire_time;
};

// 会话信息
struct session_info {
    __u64 start_time;
    __u32 pid;
    __u32 uid;
    char client_ip[MAX_CLIENT_IP_LEN];
    char init_process[MAX_PROCESS_NAME];
};

/* ================= eBPF Maps 定义 ================= */
// ML开关状态Map (0=OFF, 1=ON)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ml_switch SEC(".maps");

// 动态拦截规则Map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct block_rule);
    __type(value, __u8);
} block_rules SEC(".maps");

// 特征上报Ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024); // 2MB
} ml_events SEC(".maps");

// 基础事件上报Ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512KB
} base_events SEC(".maps");

// 会话Map (session_id -> session_info)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct session_info);
} sessions SEC(".maps");

// 文件路径缓存 (inode -> full_path)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, char[MAX_PATH_LEN]);
} path_cache SEC(".maps");

/* ================= 辅助函数 ================= */
static __always_inline void get_process_name(struct task_struct *task, char *buf) {
    bpf_probe_read_kernel_str(buf, MAX_PROCESS_NAME, task->comm);
}

static __always_inline void get_client_ip(struct sock *sk, char *buf) {
    struct sockaddr_in sin;
    __builtin_memset(&sin, 0, sizeof(sin));
    
    if (sk) {
        sin.sin_addr.s_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        long n = bpf_snprintf(buf, MAX_CLIENT_IP_LEN, "%pI4", &sin.sin_addr.s_addr);
        if (n < 0) {
            bpf_probe_read_kernel_str(buf, MAX_CLIENT_IP_LEN, "0.0.0.0");
        }
    } else {
        bpf_probe_read_kernel_str(buf, MAX_CLIENT_IP_LEN, "0.0.0.0");
    }
}

static __always_inline bool should_block(__u64 inode, __u32 operation) {
    struct block_rule key = {
        .inode = inode,
        .operation = operation
    };
    
    // 查找永久规则
    __u8 *block_type = bpf_map_lookup_elem(&block_rules, &key);
    if (block_type) {
        if (*block_type == BLOCK_RULE_PERMANENT) {
            return true;
        }
        
        // 检查临时规则是否过期
        if (key.expire_time > 0) {
            __u64 now = bpf_ktime_get_ns();
            if (now < key.expire_time) {
                return true;
            }
            // 过期规则自动删除
            bpf_map_delete_elem(&block_rules, &key);
        }
    }
    return false;
}

static __always_inline void get_full_path(struct dentry *dentry, char *buf) {
    // 尝试从缓存获取路径
    __u64 inode = dentry->d_inode->i_ino;
    char *cached_path = bpf_map_lookup_elem(&path_cache, &inode);
    if (cached_path) {
        bpf_probe_read_kernel_str(buf, MAX_PATH_LEN, cached_path);
        return;
    }
    
    // 动态构建路径
    struct dentry *parent;
    char tmp_path[MAX_PATH_LEN] = {0};
    char component[MAX_FILENAME_LEN];
    int depth = 0;
    
    // 从当前dentry向上遍历
    for (int i = 0; i < 16; i++) { // 防止无限循环
        if (!dentry || depth >= MAX_PATH_LEN - 1) break;
        
        // 获取当前dentry名称
        bpf_probe_read_kernel_str(component, MAX_FILENAME_LEN, dentry->d_name.name);
        int len = bpf_strnlen(component, MAX_FILENAME_LEN);
        
        // 检查是否根目录
        if (dentry == dentry->d_parent) {
            if (len > 0) {
                bpf_probe_read_user_str(buf, MAX_PATH_LEN, component);
            } else {
                bpf_probe_read_user_str(buf, MAX_PATH_LEN, "/");
            }
            break;
        }
        
        // 构建路径
        if (depth == 0) {
            bpf_probe_read_user_str(tmp_path, MAX_PATH_LEN, component);
        } else {
            char new_path[MAX_PATH_LEN];
            bpf_snprintf(new_path, MAX_PATH_LEN, "%s/%s", component, tmp_path);
            bpf_probe_read_user_str(tmp_path, MAX_PATH_LEN, new_path);
        }
        depth++;
        
        // 移动到父目录
        parent = dentry->d_parent;
        if (!parent) break;
        dentry = parent;
    }
    
    // 复制到输出缓冲区
    bpf_probe_read_kernel_str(buf, MAX_PATH_LEN, tmp_path);
    
    // 更新缓存
    char path_to_cache[MAX_PATH_LEN];
    bpf_probe_read_kernel_str(path_to_cache, MAX_PATH_LEN, buf);
    bpf_map_update_elem(&path_cache, &inode, path_to_cache, BPF_ANY);
}

static __always_inline __u64 get_session_id(struct task_struct *task) {
    // 使用进程的start_time和pid组合作为会话ID
    __u64 start_time = BPF_CORE_READ(task, start_time);
    return start_time + BPF_CORE_READ(task, pid);
}

static __always_inline void get_username(struct task_struct *task, char *buf) {
    struct cred *cred = BPF_CORE_READ(task, cred);
    kuid_t uid = BPF_CORE_READ(cred, uid);
    
    // 在实际系统中应查询用户数据库，这里简化为使用UID
    long n = bpf_snprintf(buf, MAX_USERNAME_LEN, "user_%u", uid.val);
    if (n < 0) {
        bpf_probe_read_kernel_str(buf, MAX_USERNAME_LEN, "unknown");
    }
}

/* ================= LSM 钩子实现 ================= */
SEC("lsm/file_open")
int BPF_PROG(nfs_file_open, struct file *file) {
    __u64 inode = file->f_inode->i_ino;
    __u32 operation = OPERATION_OPEN;
    
    // 基础层检查
    if (should_block(inode, operation)) {
        return -EACCES;
    }
    
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 检查ML开关状态
    __u32 key = 0;
    __u32 *ml_enabled = bpf_map_lookup_elem(&ml_switch, &key);
    if (ml_enabled && *ml_enabled) {
        // 分配特征结构
        struct ml_feature *feature = bpf_ringbuf_reserve(&ml_events, sizeof(*feature), 0);
        if (!feature) return 0;
        
        // 填充特征数据
        feature->timestamp = bpf_ktime_get_ns();
        feature->inode = inode;
        feature->pid = BPF_CORE_READ(task, pid);
        feature->uid = BPF_CORE_READ(task, cred)->uid.val;
        feature->gid = BPF_CORE_READ(task, cred)->gid.val;
        feature->operation = operation;
        feature->file_size = file->f_inode->i_size;
        feature->mode = file->f_inode->i_mode;
        feature->access_flags = file->f_flags;
        feature->parent_inode = 0;
        feature->session_id = get_session_id(task);
        
        // 获取文件名和路径
        bpf_probe_read_kernel_str(feature->filename, MAX_FILENAME_LEN, 
                   file->f_path.dentry->d_name.name);
        get_full_path(file->f_path.dentry, feature->full_path);
        
        // 获取客户端IP和进程信息
        struct socket *sock = BPF_CORE_READ(file, f_path.dentry->d_sb, s_fs_info);
        struct sock *sk = sock ? BPF_CORE_READ(sock, sk) : NULL;
        get_client_ip(sk, feature->client_ip);
        get_process_name(task, feature->process_name);
        get_username(task, feature->username);
        
        // 更新会话信息
        struct session_info *session = bpf_map_lookup_elem(&sessions, &feature->session_id);
        if (!session) {
            struct session_info new_session = {
                .start_time = feature->timestamp,
                .pid = feature->pid,
                .uid = feature->uid
            };
            bpf_probe_read_kernel_str(new_session.client_ip, MAX_CLIENT_IP_LEN, feature->client_ip);
            bpf_probe_read_kernel_str(new_session.init_process, MAX_PROCESS_NAME, feature->process_name);
            bpf_map_update_elem(&sessions, &feature->session_id, &new_session, BPF_ANY);
        }
        
        bpf_ringbuf_submit(feature, 0);
    } else {
        // ML关闭：仅上报基础事件
        struct ml_feature *base_event = bpf_ringbuf_reserve(&base_events, sizeof(struct ml_feature), 0);
        if (base_event) {
            base_event->timestamp = bpf_ktime_get_ns();
            base_event->inode = inode;
            base_event->operation = operation;
            bpf_probe_read_kernel_str(base_event->filename, MAX_FILENAME_LEN, 
                       file->f_path.dentry->d_name.name);
            bpf_ringbuf_submit(base_event, 0);
        }
    }
    
    return 0;
}

// 文件删除操作
SEC("lsm/inode_unlink")
int BPF_PROG(nfs_unlink, struct inode *dir, struct dentry *dentry) {
    __u64 inode = dentry->d_inode->i_ino;
    __u32 operation = OPERATION_UNLINK;
    
    // 基础层检查
    if (should_block(inode, operation)) {
        return -EPERM;
    }
    
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 检查ML开关状态
    __u32 key = 0;
    __u32 *ml_enabled = bpf_map_lookup_elem(&ml_switch, &key);
    if (ml_enabled && *ml_enabled) {
        // 分配特征结构
        struct ml_feature *feature = bpf_ringbuf_reserve(&ml_events, sizeof(*feature), 0);
        if (!feature) return 0;
        
        // 填充特征数据
        feature->timestamp = bpf_ktime_get_ns();
        feature->inode = inode;
        feature->pid = BPF_CORE_READ(task, pid);
        feature->uid = BPF_CORE_READ(task, cred)->uid.val;
        feature->gid = BPF_CORE_READ(task, cred)->gid.val;
        feature->operation = operation;
        feature->file_size = dentry->d_inode->i_size;
        feature->mode = dentry->d_inode->i_mode;
        feature->parent_inode = dir->i_ino;
        feature->session_id = get_session_id(task);
        
        // 获取文件名和路径
        bpf_probe_read_kernel_str(feature->filename, MAX_FILENAME_LEN, dentry->d_name.name);
        get_full_path(dentry, feature->full_path);
        
        // 获取客户端IP和进程信息
        struct socket *sock = BPF_CORE_READ(dentry->d_sb, s_fs_info);
        struct sock *sk = sock ? BPF_CORE_READ(sock, sk) : NULL;
        get_client_ip(sk, feature->client_ip);
        get_process_name(task, feature->process_name);
        get_username(task, feature->username);
        
        bpf_ringbuf_submit(feature, 0);
    } else {
        // 仅上报基础事件
        struct ml_feature *base_event = bpf_ringbuf_reserve(&base_events, sizeof(struct ml_feature), 0);
        if (base_event) {
            base_event->timestamp = bpf_ktime_get_ns();
            base_event->inode = inode;
            base_event->operation = operation;
            bpf_probe_read_kernel_str(base_event->filename, MAX_FILENAME_LEN, dentry->d_name.name);
            bpf_ringbuf_submit(base_event, 0);
        }
    }
    
    return 0;
}

// 文件属性变更
SEC("lsm/inode_setattr")
int BPF_PROG(nfs_setattr, struct dentry *dentry, struct iattr *attr) {
    __u64 inode = dentry->d_inode->i_ino;
    __u32 operation = OPERATION_SETATTR;
    
    // 基础层检查
    if (should_block(inode, operation)) {
        return -EPERM;
    }
    
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 检查ML开关状态
    __u32 key = 0;
    __u32 *ml_enabled = bpf_map_lookup_elem(&ml_switch, &key);
    if (ml_enabled && *ml_enabled) {
        // 分配特征结构
        struct ml_feature *feature = bpf_ringbuf_reserve(&ml_events, sizeof(*feature), 0);
        if (!feature) return 0;
        
        // 填充特征数据
        feature->timestamp = bpf_ktime_get_ns();
        feature->inode = inode;
        feature->pid = BPF_CORE_READ(task, pid);
        feature->uid = BPF_CORE_READ(task, cred)->uid.val;
        feature->gid = BPF_CORE_READ(task, cred)->gid.val;
        feature->operation = operation;
        feature->file_size = dentry->d_inode->i_size;
        feature->mode = attr->ia_mode;
        feature->parent_inode = 0;
        feature->session_id = get_session_id(task);
        
        // 获取文件名和路径
        bpf_probe_read_kernel_str(feature->filename, MAX_FILENAME_LEN, dentry->d_name.name);
        get_full_path(dentry, feature->full_path);
        
        // 获取客户端IP和进程信息
        struct socket *sock = BPF_CORE_READ(dentry->d_sb, s_fs_info);
        struct sock *sk = sock ? BPF_CORE_READ(sock, sk) : NULL;
        get_client_ip(sk, feature->client_ip);
        get_process_name(task, feature->process_name);
        get_username(task, feature->username);
        
        bpf_ringbuf_submit(feature, 0);
    }
    
    return 0;
}

// 文件创建操作
SEC("lsm/inode_create")
int BPF_PROG(nfs_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    __u64 inode = 0; // 新文件，inode尚未分配
    __u32 operation = OPERATION_CREATE;
    
    // 基础层检查
    if (should_block(dir->i_ino, operation)) {
        return -EPERM;
    }
    
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 检查ML开关状态
    __u32 key = 0;
    __u32 *ml_enabled = bpf_map_lookup_elem(&ml_switch, &key);
    if (ml_enabled && *ml_enabled) {
        // 分配特征结构
        struct ml_feature *feature = bpf_ringbuf_reserve(&ml_events, sizeof(*feature), 0);
        if (!feature) return 0;
        
        // 填充特征数据
        feature->timestamp = bpf_ktime_get_ns();
        feature->inode = 0;
        feature->pid = BPF_CORE_READ(task, pid);
        feature->uid = BPF_CORE_READ(task, cred)->uid.val;
        feature->gid = BPF_CORE_READ(task, cred)->gid.val;
        feature->operation = operation;
        feature->file_size = 0;
        feature->mode = mode;
        feature->parent_inode = dir->i_ino;
        feature->session_id = get_session_id(task);
        
        // 获取文件名和路径
        bpf_probe_read_kernel_str(feature->filename, MAX_FILENAME_LEN, dentry->d_name.name);
        get_full_path(dentry, feature->full_path);
        
        // 获取客户端IP和进程信息
        struct socket *sock = BPF_CORE_READ(dentry->d_sb, s_fs_info);
        struct sock *sk = sock ? BPF_CORE_READ(sock, sk) : NULL;
        get_client_ip(sk, feature->client_ip);
        get_process_name(task, feature->process_name);
        get_username(task, feature->username);
        
        bpf_ringbuf_submit(feature, 0);
    }
    
    return 0;
}

// 符号链接操作
SEC("lsm/inode_symlink")
int BPF_PROG(nfs_symlink, struct inode *dir, struct dentry *dentry, const char *oldname) {
    __u64 inode = 0; // 新文件，inode尚未分配
    __u32 operation = OPERATION_SYMLINK;
    
    // 基础层检查
    if (should_block(dir->i_ino, operation)) {
        return -EPERM;
    }
    
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 检查ML开关状态
    __u32 key = 0;
    __u32 *ml_enabled = bpf_map_lookup_elem(&ml_switch, &key);
    if (ml_enabled && *ml_enabled) {
        // 分配特征结构
        struct ml_feature *feature = bpf_ringbuf_reserve(&ml_events, sizeof(*feature), 0);
        if (!feature) return 0;
        
        // 填充特征数据
        feature->timestamp = bpf_ktime_get_ns();
        feature->inode = 0;
        feature->pid = BPF_CORE_READ(task, pid);
        feature->uid = BPF_CORE_READ(task, cred)->uid.val;
        feature->gid = BPF_CORE_READ(task, cred)->gid.val;
        feature->operation = operation;
        feature->file_size = 0;
        feature->mode = S_IFLNK; // 符号链接
        feature->parent_inode = dir->i_ino;
        feature->session_id = get_session_id(task);
        
        // 获取文件名和路径
        bpf_probe_read_kernel_str(feature->filename, MAX_FILENAME_LEN, dentry->d_name.name);
        get_full_path(dentry, feature->full_path);
        
        // 获取目标链接
        bpf_probe_read_kernel_str(feature->username, MAX_USERNAME_LEN, oldname);
        
        // 获取客户端IP和进程信息
        struct socket *sock = BPF_CORE_READ(dentry->d_sb, s_fs_info);
        struct sock *sk = sock ? BPF_CORE_READ(sock, sk) : NULL;
        get_client_ip(sk, feature->client_ip);
        get_process_name(task, feature->process_name);
        get_username(task, feature->username);
        
        bpf_ringbuf_submit(feature, 0);
    }
    
    return 0;
}

// 文件重命名操作
SEC("lsm/inode_rename")
int BPF_PROG(nfs_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry) {
    __u64 inode = old_dentry->d_inode->i_ino;
    __u32 operation = OPERATION_RENAME;
    
    // 基础层检查
    if (should_block(inode, operation)) {
        return -EPERM;
    }
    
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 检查ML开关状态
    __u32 key = 0;
    __u32 *ml_enabled = bpf_map_lookup_elem(&ml_switch, &key);
    if (ml_enabled && *ml_enabled) {
        // 分配特征结构
        struct ml_feature *feature = bpf_ringbuf_reserve(&ml_events, sizeof(*feature), 0);
        if (!feature) return 0;
        
        // 填充特征数据
        feature->timestamp = bpf_ktime_get_ns();
        feature->inode = inode;
        feature->pid = BPF_CORE_READ(task, pid);
        feature->uid = BPF_CORE_READ(task, cred)->uid.val;
        feature->gid = BPF_CORE_READ(task, cred)->gid.val;
        feature->operation = operation;
        feature->file_size = old_dentry->d_inode->i_size;
        feature->mode = old_dentry->d_inode->i_mode;
        feature->parent_inode = old_dir->i_ino;
        feature->session_id = get_session_id(task);
        
        // 获取文件名和路径
        bpf_probe_read_kernel_str(feature->filename, MAX_FILENAME_LEN, old_dentry->d_name.name);
        get_full_path(old_dentry, feature->full_path);
        
        // 存储新路径在username字段中
        char new_path[MAX_PATH_LEN];
        get_full_path(new_dentry, new_path);
        bpf_probe_read_kernel_str(feature->username, MAX_USERNAME_LEN, new_path);
        
        // 获取客户端IP和进程信息
        struct socket *sock = BPF_CORE_READ(old_dentry->d_sb, s_fs_info);
        struct sock *sk = sock ? BPF_CORE_READ(sock, sk) : NULL;
        get_client_ip(sk, feature->client_ip);
        get_process_name(task, feature->process_name);
        get_username(task, feature->username); // 覆盖新路径，仅用于演示
        
        bpf_ringbuf_submit(feature, 0);
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";
