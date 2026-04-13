# Frida + eBPF 混合架构设计文档
## TLS 密钥提取 + 五元组关联

---

## 一、纯 eBPF 失败原因分析

### 1.1 Chrome 代码段布局异常（根本原因）

标准 PIE 二进制的代码段权限是 `r-xp`（只读+可执行），  
但 Chrome 的 `/proc/PID/maps` 显示：

```
r--p 00000000   数据段
r-xp 02b46000   代码段1
rwxp 04882000   ← HKDF (0x048837E0) 和 ssl_log_secret (0x04883520) 均在此
r-xp 04883000   代码段2
rwxp 0a22c000   ← PRF (0x0A22D4B0) 在此
r-xp 0a22d000   代码段3
```

`rwxp`（可读写执行）页是 Chrome 在运行时做**代码热补丁**（code patching）的区域。
Google 用这个机制实现 PGO（Profile-Guided Optimization）的运行时特化，
以及 BoringSSL 的 FIPS 自检机制（会修改函数序言）。

**影响：**

| 工具 | 表现 | 原因 |
|------|------|------|
| bpftrace | "No probes to attach" | 显式拒绝 rwxp 页 |
| perf probe | "WARNING: perf not found" | OEM 内核无匹配 perf 包 |
| tracefs uprobe | 0 事件 | rwxp 页的 uprobe 在部分内核版本不触发 |
| libbpf uprobe | 附加成功但 0 事件 | uretprobe 失效（见下） |

### 1.2 uretprobe 在 LTO 优化函数上失效

内核 uretprobe 的实现原理：  
在函数入口把返回地址替换为 trampoline，函数执行完毕后跳转到 trampoline 触发事件。

Chrome 开启了 `-flto -fprofile-use`（LTO + PGO），编译器会：
- 将小函数内联（inlining）——函数入口不存在
- 将尾调用优化为 `jmp`（tail call）——没有 `ret` 指令，uretprobe trampoline 永远不被触发

HKDF 是 BoringSSL 的核心热点函数，被 LTO 深度优化，uretprobe 完全失效。

### 1.3 文件偏移计算的多层混淆

Frida 用的是**模块相对偏移**（相对于模块加载基址），  
eBPF uprobe 用的是**文件偏移**（ELF 文件内的字节位置）。

计算步骤容易出错：
```
Ghidra VA（Ghidra 基址 0x100000）
  → ELF VirtAddr（= Ghidra VA - 0x100000）
  → 文件偏移（= ELF VirtAddr - segment_VirtAddr + segment_FileOffset）
```

Chrome 的分段结构让这个计算更复杂：同一个函数可能跨越多个段边界。

### 1.4 结论

纯 eBPF 路径在当前 Chrome 版本遇到三重障碍的叠加：
1. rwxp 页的 uprobe 支持不完整（工具链限制）
2. LTO 优化导致 uretprobe 完全失效
3. 偏移计算难以独立验证（perf/OEM内核不匹配）

**等待 BoringSecretHunter 拿到 ssl_log_secret 特征码后**，可以尝试：
- 用特征码在运行时内存中扫描实际地址（绕过偏移计算问题）
- 配合内核补丁使 rwxp 页支持 uprobe

---

## 二、Frida + eBPF 混合架构

### 2.1 核心思路

**分工原则：**
- **Frida** 做应用层感知：读 ssl_ptr → 提取密钥 + 读 fd
- **eBPF** 做网络层感知：hook syscall tracepoint → 维护 fd→五元组 映射
- **共享媒介**：BPF Pinned Map（固定到文件系统，两侧均可访问）

```
┌─────────────────────────────────────────────────────────────┐
│                    Chrome NetworkService                     │
│                                                              │
│  TLS握手 → HKDF/ssl_log_secret → [Frida Hook]              │
│                                      ↓                       │
│                              ssl_ptr → fd (0x240→0x03c)     │
│                                      ↓                       │
│                              查询 BPF Pinned Map             │
│                                      ↓                       │
│  TCP连接建立 → connect(fd) → [eBPF tracepoint]             │
│                                      ↓                       │
│                              fd → 五元组 → BPF Map          │
└─────────────────────────────────────────────────────────────┘

         ┌──────────────┐      ┌──────────────────────────┐
         │  Frida       │      │  eBPF daemon             │
         │  (Python)    │ ←──→ │  (fd_tracker.bpf.c)     │
         │              │  BPF │                          │
         │  密钥捕获    │  Map │  connect/accept tracepoint│
         │  fd读取      │      │  fd→tuple 维护           │
         │  五元组查询  │      │                          │
         └──────────────┘      └──────────────────────────┘
                ↓
         ┌──────────────┐
         │  输出文件    │
         │  # 五元组    │
         │  LABEL cr key│
         └──────────────┘
```

### 2.2 为什么 eBPF Tracepoint 可以工作

**syscall tracepoint 不依赖 uprobe**，不受 rwxp 限制，不受 LTO 影响：

```c
// 挂载点：内核提供的稳定接口
SEC("tracepoint/syscalls/sys_exit_connect")  // connect() 返回时
SEC("tracepoint/syscalls/sys_enter_accept4") // accept4() 进入时
```

这些是内核静态 tracepoint，内核编译时固化，100% 可靠。

### 2.3 共享媒介：BPF Pinned Map

```
/sys/fs/bpf/tls_fd_map   ← eBPF 写入 fd→五元组
                          ← Frida 的 Python 通过 ctypes+libbpf 读取
```

Pinned Map 跨进程共享，eBPF daemon 和 Frida Python 同时访问，
fd 作为公共 key，实现关联。

---

## 三、实现文件说明

```
hybrid_arch/
├── fd_tracker.bpf.c      eBPF：hook connect/accept，维护 fd→tuple map
├── fd_tracker.c          用户态 loader：加载 BPF，pin map，后台运行
├── fd_tracker.h          共享数据结构
├── Makefile              编译脚本
└── watchdog_v9.py        Frida watchdog：密钥捕获 + 查询 BPF Map
```

### 执行顺序

```bash
# 步骤1：编译 eBPF 组件
cd hybrid_arch && make

# 步骤2：启动 fd_tracker（后台运行，维护 fd→tuple map）
sudo ./fd_tracker &

# 步骤3：启动 Chrome + Frida watchdog
sudo python3 watchdog_v9.py

# 步骤4：访问 HTTPS 站点

# 步骤5：验证
diff <(sort /tmp/chrome_tls_v9.log | grep -v '^#') \
     <(grep -E '^(CLIENT|SERVER|EXPORTER)' /tmp/chrome_sslkeys_env.log | sort)
```

---

## 四、后续纯 eBPF 突破路径

等 BoringSecretHunter 输出结果后：

### 4.1 用特征码定位运行时地址

```python
# BoringSecretHunter 输出字节特征，在运行时内存扫描
pattern = bytes.fromhex("3F 23 03 D5 FF C3 01 D1 ...")  # 示例
# 在 /proc/PID/mem 扫描 rwxp 段，找到实际运行时地址
# 直接用运行时地址 - 模块基址 = 真实文件偏移
```

### 4.2 验证 uprobe 在 rwxp 的内核支持

```bash
# 内核 6.17 可能已修复 rwxp uprobe 问题
# 测试方法：直接写 uprobe_events 并检查 trace
echo "p:test /opt/google/chrome/chrome:0x4882520" | \
    sudo tee /sys/kernel/debug/tracing/uprobe_events
# 若成功注册（无报错），说明内核支持
```

### 4.3 ssl_log_secret 单 uprobe（无需 uretprobe）

一旦偏移确认正确，ssl_log_secret 的 uprobe 不需要 uretprobe，
secret 在 onEnter 时已就绪，纯 uprobe 即可完成全部工作。
