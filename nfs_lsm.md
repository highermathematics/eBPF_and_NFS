以下是分步骤实现混合分层方案的详细指南，包含可直接执行的代码片段和验证方法：

---

### 一、环境准备（Ubuntu 22.04示例）

#### 1. 安装依赖
```bash
# 内核开发环境
sudo apt install -y build-essential linux-headers-$(uname -r) clang llvm libelf-dev

# BCC工具链
sudo apt install -y bpfcc-tools libbpfcc-dev python3-bpfcc

# 机器学习组件
pip install tritonclient[grpc] scikit-learn pandas
```

#### 2. 配置内核选项
```bash
# 检查NFS相关tracepoint
sudo grep -r NFS /sys/kernel/debug/tracing/available_events

# 确认LSM支持
sudo cat /boot/config-$(uname -r) | grep -E "LSM|NFSD"
```

---

### 二、基础LSM层实现

#### 1. 创建eBPF程序文件 `nfs_sec.c`
```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8);
} ml_switch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32); // client IP
    __type(value, u64); // last block time
} block_list SEC(".maps");

SEC("lsm/nfsd_dispatch")
int BPF_PROG(nfsd_security, struct svc_rqst *rqstp) {
    u32 client_ip = rqstp->rq_xprt->xpt_remotelen;
    u8 *ml_enabled = bpf_map_lookup_elem(&ml_switch, &(u32){0});
    
    // 基础防护：IP黑名单
    if (bpf_map_lookup_elem(&block_list, &client_ip)) {
        return -EPERM;
    }
    
    // 如果启用ML则传递元数据
    if (ml_enabled && *ml_enabled) {
        struct event {
            u32 client_ip;
            u64 timestamp;
            u16 operation;
        };
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->client_ip = client_ip;
            e->timestamp = bpf_ktime_get_ns();
            e->operation = rqstp->rq_proc;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
```

#### 2. 编译加载eBPF程序
```bash
# 编译
clang -O2 -target bpf -c nfs_sec.c -o nfs_sec.o

# 加载到内核
sudo bpftool prog load nfs_sec.o /sys/fs/bpf/nfs_sec
sudo bpftool prog attach /sys/fs/bpf/nfs_sec lsm -f nfsd_dispatch
```

---

### 三、动态控制模块实现

#### 1. 创建用户态控制脚本 `ctrl.py`
```python
from bcc import BPF
import ctypes

class NFSController:
    def __init__(self):
        self.bpf = BPF(src_file="nfs_sec.c")
        self.ml_switch = self.bpf["ml_switch"]
        self.block_list = self.bpf["block_list"]
    
    def set_ml_mode(self, enable: bool):
        key = ctypes.c_uint32(0)
        val = ctypes.c_uint8(1 if enable else 0)
        self.ml_switch[ctypes.pointer(key)] = ctypes.pointer(val)
    
    def block_client(self, ip: str):
        ip_int = int.from_bytes(socket.inet_aton(ip), byteorder='big')
        key = ctypes.c_uint32(ip_int)
        val = ctypes.c_uint64(time.time_ns())
        self.block_list[ctypes.pointer(key)] = ctypes.pointer(val)

# 使用示例
if __name__ == "__main__":
    ctrl = NFSController()
    ctrl.set_ml_mode(True)  # 启用ML模式
    ctrl.block_client("192.168.1.100")  # 封禁IP
```

#### 2. 测试基础功能
```bash
# 查看加载的程序
sudo bpftool prog list

# 测试IP封禁
python3 ctrl.py block 192.168.1.100
nmap -p 2049 192.168.1.100 # 应显示端口关闭
```

---

### 四、机器学习集成实现

#### 1. 创建特征处理服务 `ml_service.py`
```python
from bcc import BPF
import numpy as np
from sklearn.ensemble import IsolationForest

class MLService:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01)
        self.bpf = BPF(src_file="nfs_sec.c")
        self.ringbuf = self.bpf.get_table("events")
        self.ringbuf.open_ring_buffer(self._process_event)
    
    def _process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        features = self._extract_features(event)
        prediction = self.model.predict([features])[0]
        
        if prediction == -1:
            print(f"Anomaly detected from {event.client_ip}")
            self._update_block_list(event.client_ip)
    
    def _extract_features(self, event):
        return [
            event.operation,        # 操作类型
            event.timestamp % 86400, # 时间周期特征
            # 可添加更多特征
        ]
    
    def _update_block_list(self, ip):
        # 与控制器联动
        ctrl = NFSController()
        ctrl.block_client(ip)

if __name__ == "__main__":
    ml = MLService()
    while True:
        ml.ringbuf.ring_buffer_consume()
```

#### 2. 训练初始模型
```python
# 生成模拟数据
X_train = np.random.rand(1000, 3) * [10, 86400, 1]
ml.model.fit(X_train)
```

---

### 五、系统联调测试

#### 1. 启动服务
```bash
# 终端1：启动ML服务
sudo python3 ml_service.py

# 终端2：运行控制台
sudo python3 ctrl.py set_ml 1
```

#### 2. 生成测试流量
```bash
# 正常访问
for i in {1..100}; do
    curl nfs://server/path/to/file
done

# 模拟攻击（高频访问）
while true; do
    curl nfs://server/secret_file
done
```

#### 3. 验证防御效果
```bash
# 查看被阻断IP
sudo bpftool map dump name block_list

# 监控ringbuffer事件
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

### 六、高级功能扩展

#### 1. 动态策略加载
```c
// 在eBPF程序中添加
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u32);
} policies SEC(".maps");

SEC("lsm/nfsd_dispatch")
int handle_request(...) {
    u32 key = 0;
    bpf_tail_call(ctx, &policies, key);
    return 0;
}

SEC("lsm/policy1")
int policy1(...) {
    // 自定义检测逻辑
}
```

#### 2. 性能优化编译
```bash
# 使用BTF和CO-RE编译
clang -target bpf -O2 -g -Wall -c -D__TARGET_ARCH_$(ARCH) \
      -I/usr/include/$(shell uname -m)-linux-gnu \
      -mcpu=v3 -mattr=+alu32 \
      -o nfs_sec.o nfs_sec.c
```

---

通过以上步骤，您可以获得：
1. 基础LSM层防护能力（IP黑名单）
2. 可动态启停的ML检测层
3. 用户态可视化控制接口
4. 实时威胁阻断能力

关键验证点：
- `bpftool prog show` 确认程序加载状态
- `dmesg | grep BPF` 查看内核日志
- `bcc工具观察nfsd函数调用频率`
