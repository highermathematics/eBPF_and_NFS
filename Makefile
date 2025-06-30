# NFS eBPF监控系统 Makefile
# 支持Ubuntu 22.04.2 LTS

# 编译器和工具
CC = clang
LLC = llc
OPT = opt
LLVM_DIS = llvm-dis
LLVM_OBJCOPY = llvm-objcopy

# 编译标志
CFLAGS = -O2 -g -Wall -Wextra
BPF_CFLAGS = -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu
LDFLAGS = -lbpf -lelf -lz

# 内核头文件路径
KERNEL_HEADERS = /usr/src/linux-headers-$(shell uname -r)
LINUXINCLUDE = -I$(KERNEL_HEADERS)/arch/x86/include \
               -I$(KERNEL_HEADERS)/arch/x86/include/generated \
               -I$(KERNEL_HEADERS)/include \
               -I$(KERNEL_HEADERS)/arch/x86/include/uapi \
               -I$(KERNEL_HEADERS)/arch/x86/include/generated/uapi \
               -I$(KERNEL_HEADERS)/include/uapi \
               -I$(KERNEL_HEADERS)/include/generated/uapi

# 源文件
XDP_SOURCES = xdp_nfs_kern.c tc_nfs_kern.c xdp_reply.c
USER_SOURCES = user.c nfs_ebpf_safe.c
LSM_SOURCES = nfs_monitor.bpf.c
PYTHON_SOURCES = ml_service.py nfs_monitor_loader.py train_models.py evaluate_models.py

# 目标文件
XDP_OBJECTS = $(XDP_SOURCES:.c=.o)
USER_OBJECTS = $(USER_SOURCES:.c=.o)
LSM_OBJECTS = $(LSM_SOURCES:.c=.o)

# 可执行文件
USER_PROGRAMS = nfs_ebpf_loader user_tool

.PHONY: all clean install deps check train-models test-models

all: $(XDP_OBJECTS) $(LSM_OBJECTS) $(USER_PROGRAMS)
	@echo "构建完成！"

# 编译eBPF内核程序
%.o: %.c
	@echo "编译eBPF程序: $<"
	$(CC) $(BPF_CFLAGS) $(LINUXINCLUDE) -c $< -o $@

# 编译用户态程序
nfs_ebpf_loader: nfs_ebpf_safe.c ebpfmap.c
	@echo "编译用户态加载器: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

user_tool: user.c
	@echo "编译用户态工具: $@"
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# 安装依赖
deps:
	@echo "安装项目依赖..."
	./scripts/install_deps.sh

# 环境检查
check:
	@echo "检查运行环境..."
	./scripts/check_env.sh

# 训练ML模型
train-models:
	@echo "训练机器学习模型..."
	@if [ -f "venv/bin/activate" ]; then \
		source venv/bin/activate && python3 train_models.py; \
	else \
		python3 train_models.py; \
	fi

# 测试ML模型
test-models:
	@echo "测试机器学习模型..."
	@if [ -f "venv/bin/activate" ]; then \
		source venv/bin/activate && python3 evaluate_models.py; \
	else \
		python3 evaluate_models.py; \
	fi

# 安装程序
install: all
	@echo "安装程序到系统..."
	sudo mkdir -p /usr/local/lib/bpf/
	sudo cp $(XDP_OBJECTS) $(LSM_OBJECTS) /usr/local/lib/bpf/
	sudo cp $(USER_PROGRAMS) /usr/local/bin/
	sudo cp $(PYTHON_SOURCES) /usr/local/bin/
	sudo chmod +x /usr/local/bin/nfs_ebpf_loader
	sudo chmod +x /usr/local/bin/user_tool
	sudo chmod +x /usr/local/bin/ml_service.py
	sudo chmod +x /usr/local/bin/nfs_monitor_loader.py
	sudo chmod +x /usr/local/bin/train_models.py
	sudo chmod +x /usr/local/bin/evaluate_models.py

# 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -f *.o $(USER_PROGRAMS)
	rm -f *.ll *.s
	rm -rf __pycache__/
	rm -f *.pyc

# 运行测试
test: all
	@echo "运行项目测试..."
	./scripts/run_tests.sh

# 启动服务
start: all
	@echo "启动NFS eBPF监控服务..."
	sudo ./start.sh

# 停止服务
stop:
	@echo "停止NFS eBPF监控服务..."
	sudo ./stop.sh

# 完整部署（包含模型训练）
deploy: deps all train-models
	@echo "完整部署NFS eBPF监控系统..."
	@echo "部署完成！可以运行 'make start' 启动系统"