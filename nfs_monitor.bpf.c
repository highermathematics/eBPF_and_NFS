#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/nfs_fs.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_EVENTS 10240
#define MAX_XATTR_NAME_LEN 64
#define MAX_XATTR_VALUE_LEN 256
#define NFS_SUPER_MAGIC 0x6969

// 事件类型定义
enum event_type {
    EVENT_FILE_OPEN = 1,
    EVENT_FILE_READ = 2,
    EVENT_FILE_WRITE = 3,
    EVENT_FILE_DELETE = 4,
    EVENT_PERMISSION_DENIED = 5,
    EVENT_INODE_PERMISSION = 6,
    EVENT_FILE_PERMISSION = 7,
    EVENT_SETATTR = 8,
    EVENT_XATTR_SET = 9,
    EVENT_XATTR_GET = 10,
    EVENT_LINK_CREATE = 11,
    EVENT_RENAME = 12,
    EVENT_MKDIR = 13,
    EVENT_RMDIR = 14,
    EVENT_CREATE = 15,
    EVENT_MOUNT = 16,
    EVENT_REMOUNT = 17,
    EVENT_STATFS = 18,
    EVENT_MMAP = 19,
    EVENT_MPROTECT = 20,
    EVENT_EXEC_CHECK = 21,
    EVENT_CRED_CHANGE = 22
};

// 权限掩码定义
#define MAY_EXEC 0x00000001
#define MAY_WRITE 0x00000002
#define MAY_READ 0x00000004
#define MAY_APPEND 0x00000008
#define MAY_ACCESS 0x00000010
#define MAY_OPEN 0x00000020
#define MAY_CHDIR 0x00000040

// NFS访问事件结构
struct nfs_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u64 timestamp;
    char filename[MAX_FILENAME_LEN];
    __u32 file_size;
    __u32 access_mode;
    __u32 permission_mask;
    __u32 client_ip;
    __u16 client_port;
    __u32 inode_number;
    __u16 file_mode;
    __u32 parent_inode;
    char xattr_name[MAX_XATTR_NAME_LEN];
    char target_path[MAX_FILENAME_LEN];
    __u32 mount_flags;
    __u32 security_flags;
};

// 安全策略配置
struct security_policy {
    __u32 enable_access_control;
    __u32 enable_xattr_protection;
    __u32 enable_exec_control;
    __u32 enable_mount_control;
    __u32 strict_mode;
    __u32 log_level;
};

// ML开关状态
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} ml_switch_map SEC(".maps");

// 安全策略配置MAP
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct security_policy);
} security_policy_map SEC(".maps");

// 事件环形缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_EVENTS * sizeof(struct nfs_event));
} events SEC(".maps");

// 拦截规则MAP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // client_ip
    __type(value, __u32); // 0=允许, 1=拒绝
} intercept_rules SEC(".maps");

// 文件访问白名单
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);  // inode_number
    __type(value, __u32); // 访问权限掩码
} file_whitelist SEC(".maps");

// 用户权限映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // uid
    __type(value, __u32); // 权限级别
} user_permissions SEC(".maps");

// 敏感扩展属性列表
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[MAX_XATTR_NAME_LEN]);
    __type(value, __u32); // 保护级别
} sensitive_xattrs SEC(".maps");

// 统计信息MAP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // client_ip
    __type(value, __u64); // 访问次数
} access_stats SEC(".maps");

// 违规统计MAP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // client_ip
    __type(value, __u64); // 违规次数
} violation_stats SEC(".maps");

// 辅助函数：检查是否为NFS文件系统
static __always_inline bool is_nfs_filesystem(struct super_block *sb)
{
    if (!sb)
        return false;
    
    __u32 magic = BPF_CORE_READ(sb, s_magic);
    return magic == NFS_SUPER_MAGIC;
}

// 辅助函数：获取客户端IP地址
static __always_inline __u32 get_client_ip(void)
{
    // 实际实现需要从网络栈或NFS上下文中获取
    // 这里简化处理，实际需要根据NFS服务器实现
    return 0x7f000001; // 127.0.0.1 for testing
}

// 辅助函数：检查拦截规则
static __always_inline bool check_intercept_rule(__u32 client_ip)
{
    __u32 *rule = bpf_map_lookup_elem(&intercept_rules, &client_ip);
    return rule && *rule == 1;
}

// 辅助函数：获取安全策略
static __always_inline struct security_policy* get_security_policy(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&security_policy_map, &key);
}

// 辅助函数：记录事件
static __always_inline void record_event(struct nfs_event *event)
{
    struct nfs_event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;
    
    __builtin_memcpy(e, event, sizeof(*e));
    bpf_ringbuf_submit(e, 0);
}

// 辅助函数：更新统计信息
static __always_inline void update_stats(__u32 client_ip, bool is_violation)
{
    __u64 *count;
    
    // 更新访问统计
    count = bpf_map_lookup_elem(&access_stats, &client_ip);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&access_stats, &client_ip, &init_count, BPF_ANY);
    }
    
    // 更新违规统计
    if (is_violation) {
        count = bpf_map_lookup_elem(&violation_stats, &client_ip);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 init_count = 1;
            bpf_map_update_elem(&violation_stats, &client_ip, &init_count, BPF_ANY);
        }
    }
}

// 辅助函数：检查用户权限
static __always_inline bool check_user_permission(__u32 uid, __u32 required_level)
{
    __u32 *user_level = bpf_map_lookup_elem(&user_permissions, &uid);
    if (!user_level)
        return false;
    
    return *user_level >= required_level;
}

// LSM钩子：inode权限检查
SEC("lsm/inode_permission")
int BPF_PROG(nfs_inode_permission, struct inode *inode, int mask)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    __u32 inode_num;
    __u32 *whitelist_mask;
    
    if (!inode || !inode->i_sb)
        return 0;
    
    // 检查是否为NFS文件系统
    if (!is_nfs_filesystem(inode->i_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    // 检查拦截规则
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 检查文件白名单
    inode_num = BPF_CORE_READ(inode, i_ino);
    whitelist_mask = bpf_map_lookup_elem(&file_whitelist, &inode_num);
    if (whitelist_mask && (mask & *whitelist_mask) != mask) {
        // 请求的权限超出白名单允许范围
        event.event_type = EVENT_PERMISSION_DENIED;
        event.inode_number = inode_num;
        event.permission_mask = mask;
        event.client_ip = client_ip;
        event.timestamp = bpf_ktime_get_ns();
        record_event(&event);
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录正常访问
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    event.event_type = EVENT_INODE_PERMISSION;
    event.timestamp = bpf_ktime_get_ns();
    event.inode_number = inode_num;
    event.permission_mask = mask;
    event.client_ip = client_ip;
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：文件权限检查
SEC("lsm/file_permission")
int BPF_PROG(nfs_file_permission, struct file *file, int mask)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!file || !file->f_inode)
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        event.event_type = EVENT_PERMISSION_DENIED;
        event.client_ip = client_ip;
        event.timestamp = bpf_ktime_get_ns();
        record_event(&event);
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录文件权限检查
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_FILE_PERMISSION;
    event.timestamp = bpf_ktime_get_ns();
    event.permission_mask = mask;
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(file->f_inode, i_ino);
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：文件打开
SEC("lsm/file_open")
int BPF_PROG(nfs_file_open, struct file *file)
{
    struct nfs_event event = {};
    struct dentry *dentry;
    const char *filename;
    __u32 client_ip;
    
    if (!file || !file->f_path.dentry)
        return 0;
    
    dentry = file->f_path.dentry;
    if (!dentry || !dentry->d_sb || !is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 填充事件信息
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    event.event_type = EVENT_FILE_OPEN;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.access_mode = file->f_mode;
    event.inode_number = BPF_CORE_READ(file->f_inode, i_ino);
    
    filename = BPF_CORE_READ(dentry, d_name.name);
    if (filename) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, filename);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：设置inode属性
SEC("lsm/inode_setattr")
int BPF_PROG(nfs_inode_setattr, struct dentry *dentry, struct iattr *attr)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    const char *filename;
    
    if (!dentry || !dentry->d_inode)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    // 检查是否有权限修改属性
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (policy->strict_mode && !check_user_permission(uid, 2)) {
        update_stats(client_ip, true);
        return -EPERM;
    }
    
    // 记录属性修改事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = uid;
    event.gid = bpf_get_current_uid_gid() >> 32;
    event.event_type = EVENT_SETATTR;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(dentry->d_inode, i_ino);
    
    filename = BPF_CORE_READ(dentry, d_name.name);
    if (filename) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, filename);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：设置扩展属性
SEC("lsm/inode_setxattr")
int BPF_PROG(nfs_inode_setxattr, struct dentry *dentry, const char *name,
             const void *value, size_t size, int flags)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    __u32 *protection_level;
    
    if (!dentry || !name)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_xattr_protection)
        return 0;
    
    client_ip = get_client_ip();
    
    // 检查是否为敏感扩展属性
    char xattr_name[MAX_XATTR_NAME_LEN] = {};
    bpf_probe_read_kernel_str(xattr_name, MAX_XATTR_NAME_LEN, name);
    
    protection_level = bpf_map_lookup_elem(&sensitive_xattrs, &xattr_name);
    if (protection_level && *protection_level > 0) {
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        if (!check_user_permission(uid, *protection_level)) {
            update_stats(client_ip, true);
            return -EPERM;
        }
    }
    
    // 记录扩展属性设置事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_XATTR_SET;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(dentry->d_inode, i_ino);
    
    __builtin_memcpy(event.xattr_name, xattr_name, MAX_XATTR_NAME_LEN);
    
    const char *filename = BPF_CORE_READ(dentry, d_name.name);
    if (filename) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, filename);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：获取扩展属性
SEC("lsm/inode_getxattr")
int BPF_PROG(nfs_inode_getxattr, struct dentry *dentry, const char *name)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!dentry || !name)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_xattr_protection)
        return 0;
    
    client_ip = get_client_ip();
    
    // 记录扩展属性获取事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_XATTR_GET;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(dentry->d_inode, i_ino);
    
    bpf_probe_read_kernel_str(event.xattr_name, MAX_XATTR_NAME_LEN, name);
    
    const char *filename = BPF_CORE_READ(dentry, d_name.name);
    if (filename) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, filename);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：创建硬链接
SEC("lsm/path_link")
int BPF_PROG(nfs_path_link, struct dentry *old_dentry, struct path *new_dir,
             struct dentry *new_dentry)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!old_dentry || !new_dentry)
        return 0;
    
    if (!is_nfs_filesystem(old_dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录硬链接创建事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_LINK_CREATE;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(old_dentry->d_inode, i_ino);
    
    const char *old_name = BPF_CORE_READ(old_dentry, d_name.name);
    if (old_name) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, old_name);
    }
    
    const char *new_name = BPF_CORE_READ(new_dentry, d_name.name);
    if (new_name) {
        bpf_probe_read_kernel_str(event.target_path, MAX_FILENAME_LEN, new_name);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：重命名/移动
SEC("lsm/path_rename")
int BPF_PROG(nfs_path_rename, struct path *old_dir, struct dentry *old_dentry,
             struct path *new_dir, struct dentry *new_dentry)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!old_dentry || !new_dentry)
        return 0;
    
    if (!is_nfs_filesystem(old_dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录重命名事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_RENAME;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(old_dentry->d_inode, i_ino);
    
    const char *old_name = BPF_CORE_READ(old_dentry, d_name.name);
    if (old_name) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, old_name);
    }
    
    const char *new_name = BPF_CORE_READ(new_dentry, d_name.name);
    if (new_name) {
        bpf_probe_read_kernel_str(event.target_path, MAX_FILENAME_LEN, new_name);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：创建目录
SEC("lsm/path_mkdir")
int BPF_PROG(nfs_path_mkdir, struct path *dir, struct dentry *dentry, umode_t mode)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!dentry)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录目录创建事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_MKDIR;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.file_mode = mode;
    
    const char *dirname = BPF_CORE_READ(dentry, d_name.name);
    if (dirname) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, dirname);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：删除目录
SEC("lsm/path_rmdir")
int BPF_PROG(nfs_path_rmdir, struct path *dir, struct dentry *dentry)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!dentry)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录目录删除事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_RMDIR;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(dentry->d_inode, i_ino);
    
    const char *dirname = BPF_CORE_READ(dentry, d_name.name);
    if (dirname) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, dirname);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：删除文件
SEC("lsm/inode_unlink")
int BPF_PROG(nfs_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!dentry)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录文件删除事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    event.event_type = EVENT_FILE_DELETE;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(dentry->d_inode, i_ino);
    
    const char *filename = BPF_CORE_READ(dentry, d_name.name);
    if (filename) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, filename);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：创建文件
SEC("lsm/inode_create")
int BPF_PROG(nfs_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!dentry)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_access_control)
        return 0;
    
    client_ip = get_client_ip();
    
    if (check_intercept_rule(client_ip)) {
        update_stats(client_ip, true);
        return -EACCES;
    }
    
    // 记录文件创建事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_CREATE;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.file_mode = mode;
    
    const char *filename = BPF_CORE_READ(dentry, d_name.name);
    if (filename) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, filename);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：挂载文件系统
SEC("lsm/sb_mount")
int BPF_PROG(nfs_sb_mount, const char *dev_name, struct path *path,
             const char *type, unsigned long flags, void *data)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_mount_control)
        return 0;
    
    client_ip = get_client_ip();
    
    // 检查挂载权限
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (policy->strict_mode && !check_user_permission(uid, 3)) {
        update_stats(client_ip, true);
        return -EPERM;
    }
    
    // 记录挂载事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = uid;
    event.event_type = EVENT_MOUNT;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.mount_flags = flags;
    
    if (dev_name) {
        bpf_probe_read_kernel_str(event.filename, MAX_FILENAME_LEN, dev_name);
    }
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：重新挂载文件系统
SEC("lsm/sb_remount")
int BPF_PROG(nfs_sb_remount, struct super_block *sb, void *data)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_mount_control)
        return 0;
    
    client_ip = get_client_ip();
    
    // 检查重新挂载权限
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (policy->strict_mode && !check_user_permission(uid, 3)) {
        update_stats(client_ip, true);
        return -EPERM;
    }
    
    // 记录重新挂载事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = uid;
    event.event_type = EVENT_REMOUNT;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：获取文件系统统计信息
SEC("lsm/sb_statfs")
int BPF_PROG(nfs_sb_statfs, struct dentry *dentry)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!dentry)
        return 0;
    
    if (!is_nfs_filesystem(dentry->d_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || policy->log_level < 2)
        return 0;
    
    client_ip = get_client_ip();
    
    // 记录统计信息查询事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_STATFS;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：内存映射文件
SEC("lsm/mmap_file")
int BPF_PROG(nfs_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!file || !file->f_inode)
        return 0;
    
    if (!is_nfs_filesystem(file->f_inode->i_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_exec_control)
        return 0;
    
    client_ip = get_client_ip();
    
    // 检查可执行映射权限
    if ((prot & PROT_EXEC) && policy->strict_mode) {
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        if (!check_user_permission(uid, 2)) {
            update_stats(client_ip, true);
            return -EPERM;
        }
    }
    
    // 记录内存映射事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_MMAP;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(file->f_inode, i_ino);
    event.security_flags = prot;
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

// LSM钩子：内存保护修改
SEC("lsm/file_mprotect")
int BPF_PROG(nfs_file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot)
{
    struct nfs_event event = {};
    struct security_policy *policy;
    __u32 client_ip;
    
    if (!vma || !vma->vm_file || !vma->vm_file->f_inode)
        return 0;
    
    if (!is_nfs_filesystem(vma->vm_file->f_inode->i_sb))
        return 0;
    
    policy = get_security_policy();
    if (!policy || !policy->enable_exec_control)
        return 0;
    
    client_ip = get_client_ip();
    
    // 检查执行权限修改
    if ((prot & PROT_EXEC) && !(reqprot & PROT_EXEC)) {
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        if (policy->strict_mode && !check_user_permission(uid, 2)) {
            update_stats(client_ip, true);
            return -EPERM;
        }
    }
    
    // 记录内存保护修改事件
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = EVENT_MPROTECT;
    event.timestamp = bpf_ktime_get_ns();
    event.client_ip = client_ip;
    event.inode_number = BPF_CORE_READ(vma->vm_file->f_inode, i_ino);
    event.security_flags = prot;
    
    record_event(&event);
    update_stats(client_ip, false);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";