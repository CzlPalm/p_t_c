# P4：eBPF uprobe 密钥捕获 + 五元组关联 — 执行规划方案

**起始日期**: 2026-03-31
**前置条件**: P3 ✅ 已通过（watchdog_attach_v4.py 验证，96% 捕获率）
**预计周期**: 2–3 周
**目标**: 使用纯 eBPF 替代 Frida 实现 TLS 密钥提取，并在内核态关联五元组

---

## 一、架构决策：纯 eBPF（推荐）

### 1.1 为什么 eBPF 可以完全替代 Frida

P3 验证的 HKDF Hook 核心操作在 eBPF 中全部可实现：

| 操作 | Frida | eBPF | 复杂度 |
|------|-------|------|--------|
| 读寄存器 RDI/RSI/RCX/R8 | `args[N]` | `PT_REGS_PARM1~5(ctx)` | 低 |
| 读 label 字符串 (≤20B) | `readUtf8String()` | `bpf_probe_read_user()` + 手动比较 | 中 |
| 三级指针解引用读 CR | `readPointer().add()...` | 三次 `bpf_probe_read_user()` 链式 | 中 |
| 读密钥 (32/48B) | `readByteArray()` | `bpf_probe_read_user()` | 低 |
| 读密钥长度 (EVP_MD+4) | `readU8()` | `bpf_probe_read_user()` | 低 |

栈用量估算：`cr[32] + secret[48] + label[20] + 指针变量×6 + event结构 ≈ 200 字节`，远低于 512 字节限制。

### 1.2 纯 eBPF 的优势

| 维度 | Frida (P3) | eBPF (P4) |
|------|-----------|----------|
| 注入方式 | ptrace 注入目标进程 | perf_event，不注入 |
| CFI 影响 | 可能被拦截 | 无影响（只观察） |
| 权限 | root + ptrace | root + CAP_BPF |
| 性能开销 | 较高（JS 引擎） | 极低（JIT 编译） |
| 五元组能力 | 需轮询 /proc/net/tcp | 内核态原生 tracepoint |
| 稳定性 | Frida 版本依赖 | 内核原生，无额外依赖 |
| 多进程 | 需逐个 attach | 一个程序覆盖所有 chrome 进程 |

### 1.3 整体数据流

```
Chrome 进程                    内核 eBPF                     用户空间
┌─────────────┐
│ HKDF 被调用  │──uprobe──→ 保存 {ssl_ptr, out_ptr, label} 到 pending_map[tid]
│ HKDF 返回    │──uretprobe→ 从 pending_map 取上下文
│              │              ├─ 读 secret (out_ptr, kl 字节)
│              │              ├─ 读 client_random (三级解引用)
│              │              ├─ 读 fd (ssl_ptr → rbio → fd)
│              │              ├─ 查 fd_tuple_map[fd] 得五元组
│              │              └─ 写 ring_buffer → {nss_label, cr, secret, tuple}
│              │                                        │
│ connect()    │──kprobe───→ fd_tuple_map[fd] = {sIP,sP,dIP,dP,proto}
└─────────────┘                                         ↓
                                                  tls_capture daemon
                                                  ├─ poll ring_buffer
                                                  ├─ 格式化 NSS Key Log
                                                  └─ 写入文件 + 五元组注释
```

---

## 二、前置准备工作（P4.0）

### 2.1 环境搭建

**任务 T4.0.1**：安装 eBPF 开发环境（1d）

```bash
# 确认内核版本（需 5.8+，推荐 5.15+）
uname -r

# 安装工具链
sudo apt install -y \
  libbpf-dev bpftool linux-headers-$(uname -r) \
  clang llvm libelf-dev \
  python3-pip

# 安装 Python BPF 绑定
pip3 install bcc --break-system-packages
# 或用 libbpf + ctypes（更轻量）

# 验证 eBPF 可用
sudo bpftool prog list
```

**任务 T4.0.2**：确认 uprobe 基本功能（0.5d）

```bash
# 验证对 Chrome 的 uprobe 挂载能力
sudo bpftrace -e '
  uprobe:/opt/google/chrome/chrome:0x048837E0 {
    printf("HKDF called by pid=%d tid=%d\n", pid, tid);
  }
' -p $(pgrep -f "type=utility.*NetworkService")
```

如果有输出，说明 uprobe 可以正常挂载到 Chrome 的 HKDF RVA。

### 2.2 定位五元组所需的结构体偏移量

**任务 T4.0.3**：在 Ghidra 中定位 ssl_st → rbio → fd 路径（1–2d）

这是 P4 的关键前置依赖。需要找到两个偏移量：

**偏移量 A：ssl_st 中 rbio 字段的偏移**

BoringSSL 源码中 `ssl_st` 结构体的 `rbio` 字段位置。搜索策略：

```
方法1：在 Ghidra 中搜索字符串 "rbio"（可能被优化掉）
方法2：搜索 BIO_new_socket 的 XREF → 找到 SSL_set_fd → 观察写入 ssl_st 的偏移
方法3：在 Frida HKDF Hook 中用探针扫描 ssl_st 寻找 fd 值
方法4：对照 BoringSSL 源码 include/openssl/ssl.h 编译带符号版本，用 pahole 提取
```

**推荐方法（最快）**：用 P3 已有的 Frida 脚本加探针：

```javascript
// 在 HKDF onEnter 中执行，扫描 ssl_ptr 前 0x100 字节寻找像 fd 的值
// fd 通常是小正整数（3~100）
Interceptor.attach(mod.base.add(ptr('0x048837E0')), {
    onEnter(args) {
        const ssl = args[0];
        send({t:'probe_fd', data: hex(ssl.readByteArray(256))});
        // 同时在另一终端执行 lsof -p <chrome_pid> | grep "TCP" 获取已知 fd
    }
});
```

对比 `lsof` 输出的 fd 值和内存 dump，找到 fd 在 ssl_st 中的偏移。

**偏移量 B：BIO 结构体中 fd 字段的偏移**

如果 rbio 是指针，还需要在 BIO 结构体中找 fd。BoringSSL 的 BIO 结构简单，fd 通常在 `BIO->num` 字段（偏移约 +0x28~+0x30）。同样用探针验证。

**预期输出格式**：
```json
{
  "ssl_st_rbio_offset": "0x??",
  "bio_fd_offset": "0x??",
  "fd_read_path": "*(*(ssl_ptr + 0x??) + 0x??)"
}
```

**任务 T4.0.4**：定位 ssl_log_secret 函数（可选，解决 4% 漏捕）（1d）

P3 遗留问题：Session Ticket/PSK 复用导致 4% 漏捕。BoringSSL 的 `ssl_log_secret()` 函数在所有密钥写入 keylog 时被调用，包括 PSK 复用场景。

搜索策略：
```
在 Ghidra 中搜索字符串 "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
→ 这个 NSS 格式标签在 ssl_log_secret 内部被使用
→ 其 XREF 应指向 FUN_04983520 (已知的 boringssl_tls13_keylog_write)
→ 分析其调用者，找到 ssl_log_secret 入口
```

Hook `ssl_log_secret` 可以直接获取已格式化的 NSS keylog 行，无需手动拼装。

---

## 三、核心开发任务

### 阶段 T4.1：eBPF 密钥提取程序（1 周）

#### T4.1.1：定义数据结构（0.5d）

```c
// tls_capture.h

#define MAX_SECRET_LEN 48
#define CR_LEN 32
#define LABEL_LEN 20

// uprobe → uretprobe 传递上下文
struct pending_entry {
    __u64 ssl_ptr;
    __u64 out_ptr;
    __u64 evp_md_ptr;   // args[5] = R9 = EVP_MD*
    char  label[LABEL_LEN];
    __u32 label_len;
};

// 五元组
struct five_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;     // 6=TCP, 17=UDP(QUIC)
};

// Ring buffer 事件
struct tls_key_event {
    __u32 pid;
    __u32 tid;
    __u8  label_type;   // 0=c_hs, 1=s_hs, 2=c_ap, 3=s_ap, 4=exp, 5=early, 6=prf
    __u8  key_len;
    __u8  client_random[CR_LEN];
    __u8  secret[MAX_SECRET_LEN];
    struct five_tuple tuple;
    __u8  has_tuple;    // 0=无五元组, 1=有
};
```

#### T4.1.2：HKDF uprobe/uretprobe（2d）

```c
// tls_capture.bpf.c

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);    // tid
    __type(value, struct pending_entry);
} pending_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);    // ssl_ptr
    __type(value, __u32);  // fd
} ssl_fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);    // fd (作为 u64 方便对齐)
    __type(value, struct five_tuple);
} fd_tuple_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Label → NSS 标签类型映射（在 BPF 中用字节比较）
static __always_inline int match_label(const char *label, int len) {
    if (len == 12) {
        // "c hs traffic" / "s hs traffic" / "c ap traffic" / "s ap traffic"
        if (label[0] == 'c' && label[2] == 'h') return 0;  // c_hs
        if (label[0] == 's' && label[2] == 'h') return 1;  // s_hs
        if (label[0] == 'c' && label[2] == 'a') return 2;  // c_ap
        if (label[0] == 's' && label[2] == 'a') return 3;  // s_ap
    }
    if (len == 10) {
        if (label[0] == 'e') return 4;  // exp master
        // res master → 不输出 keylog，跳过
    }
    if (len == 11 && label[0] == 'c') return 5;  // c e traffic
    return -1;  // 不关心的标签
}

// 密钥长度偏移表（与 P3 JSON 一致）
static const __u16 key_len_offsets[] = {
    [0] = 0xb2,   // c hs traffic
    [1] = 0xe3,   // s hs traffic
    [2] = 0x114,  // c ap traffic
    [3] = 0x145,  // s ap traffic
    [4] = 0,      // exp master → 特殊处理
    [5] = 0x81,   // c e traffic
};

SEC("uprobe//opt/google/chrome/chrome:0x048837E0")
int BPF_KPROBE(hkdf_enter,
    __u64 ssl_ptr,    // RDI = args[0]
    __u64 out_ptr,    // RSI = args[1]
    __u64 hkdf_ctx,   // RDX = args[2]
    __u64 label_ptr,  // RCX = args[3]
    __u64 label_len,  // R8  = args[4]
    __u64 evp_md)     // R9  = args[5]
{
    if (label_len == 0 || label_len > LABEL_LEN) return 0;

    struct pending_entry entry = {};
    entry.ssl_ptr = ssl_ptr;
    entry.out_ptr = out_ptr;
    entry.evp_md_ptr = evp_md;
    entry.label_len = (__u32)label_len;

    bpf_probe_read_user(entry.label, label_len & 0x1F, (void *)label_ptr);

    // 过滤：只保存我们关心的标签
    if (match_label(entry.label, entry.label_len) < 0) return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_map, &tid, &entry, BPF_ANY);
    return 0;
}

SEC("uretprobe//opt/google/chrome/chrome:0x048837E0")
int BPF_KRETPROBE(hkdf_exit)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct pending_entry *entry = bpf_map_lookup_elem(&pending_map, &tid);
    if (!entry) return 0;

    int ltype = match_label(entry->label, entry->label_len);
    if (ltype < 0) goto cleanup;

    // ── 读取密钥长度 ──
    __u8 kl = 32;
    if (ltype == 4) {
        // exp master: 二级解引用 *(*(ssl_ptr) + 0x30) + 0x1b2
        __u64 s3 = 0, sub = 0;
        bpf_probe_read_user(&s3, 8, (void *)entry->ssl_ptr);
        bpf_probe_read_user(&sub, 8, (void *)(s3 + 0x30));
        bpf_probe_read_user(&kl, 1, (void *)(sub + 0x1b2));
    } else if (ltype <= 5) {
        __u16 off = key_len_offsets[ltype];
        if (off > 0)
            bpf_probe_read_user(&kl, 1, (void *)(entry->ssl_ptr + off));
    }
    if (kl == 0 || kl > MAX_SECRET_LEN) kl = 32;

    // ── 构建事件 ──
    struct tls_key_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) goto cleanup;

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->tid = (__u32)tid;
    evt->label_type = (__u8)ltype;
    evt->key_len = kl;

    // 读 secret
    bpf_probe_read_user(evt->secret, kl & 0x3F, (void *)entry->out_ptr);

    // 读 client_random（三级解引用，P3 验证路径）
    __u64 s3 = 0, sub = 0;
    bpf_probe_read_user(&s3, 8, (void *)entry->ssl_ptr);
    bpf_probe_read_user(&sub, 8, (void *)(s3 + 0x30));
    bpf_probe_read_user(evt->client_random, CR_LEN, (void *)(sub + 0x30));

    // ── 五元组关联 ──
    // 方案A：从 ssl_st 读 fd（需要 T4.0.3 确认偏移量）
    // __u64 rbio = 0;
    // __u32 fd = 0;
    // bpf_probe_read_user(&rbio, 8, (void *)(entry->ssl_ptr + SSL_RBIO_OFFSET));
    // bpf_probe_read_user(&fd, 4, (void *)(rbio + BIO_FD_OFFSET));
    //
    // struct five_tuple *tuple = bpf_map_lookup_elem(&fd_tuple_map, &(__u64)fd);
    // if (tuple) {
    //     evt->tuple = *tuple;
    //     evt->has_tuple = 1;
    // }

    evt->has_tuple = 0;  // 初始版本先不关联，等 T4.0.3 完成后启用

    bpf_ringbuf_submit(evt, 0);

cleanup:
    bpf_map_delete_elem(&pending_map, &tid);
    return 0;
}
```

#### T4.1.3：PRF uprobe（TLS 1.2）（1d）

```c
SEC("uprobe//opt/google/chrome/chrome:0x0A22D4B0")
int BPF_KPROBE(prf_enter,
    __u64 ssl_ptr,   // RDI
    __u64 out_ptr,   // RSI = master_secret 输出
    __u64 out_len)   // RDX = 固定 0x30
{
    struct pending_entry entry = {};
    entry.ssl_ptr = ssl_ptr;
    entry.out_ptr = out_ptr;
    entry.label_len = 0;  // PRF 不需要 label 过滤
    __builtin_memcpy(entry.label, "prf", 3);

    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_map, &tid, &entry, BPF_ANY);
    return 0;
}

SEC("uretprobe//opt/google/chrome/chrome:0x0A22D4B0")
int BPF_KRETPROBE(prf_exit)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct pending_entry *entry = bpf_map_lookup_elem(&pending_map, &tid);
    if (!entry || entry->label[0] != 'p') return 0;

    struct tls_key_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) goto cleanup;

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->label_type = 6;  // PRF = CLIENT_RANDOM
    evt->key_len = 48;

    bpf_probe_read_user(evt->secret, 48, (void *)entry->out_ptr);

    // client_random 路径同 HKDF
    __u64 s3 = 0, sub = 0;
    bpf_probe_read_user(&s3, 8, (void *)entry->ssl_ptr);
    bpf_probe_read_user(&sub, 8, (void *)(s3 + 0x30));
    bpf_probe_read_user(evt->client_random, CR_LEN, (void *)(sub + 0x30));

    evt->has_tuple = 0;
    bpf_ringbuf_submit(evt, 0);

cleanup:
    bpf_map_delete_elem(&pending_map, &tid);
    return 0;
}
```

#### T4.1.4：用户空间 daemon（1d）

```python
#!/usr/bin/env python3
# tls_capture_daemon.py

import ctypes, os, struct
from bcc import BPF  # 或 libbpf 绑定

NSS_LABELS = {
    0: 'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
    1: 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
    2: 'CLIENT_TRAFFIC_SECRET_0',
    3: 'SERVER_TRAFFIC_SECRET_0',
    4: 'EXPORTER_SECRET',
    5: 'CLIENT_EARLY_TRAFFIC_SECRET',
    6: 'CLIENT_RANDOM',
}

def handle_event(ctx, data, size):
    # 解析 ring buffer 事件
    event = ctypes.cast(data, ctypes.POINTER(TLSKeyEvent)).contents
    label = NSS_LABELS.get(event.label_type, '?')
    cr_hex = bytes(event.client_random).hex()
    secret_hex = bytes(event.secret[:event.key_len]).hex()

    line = f"{label} {cr_hex} {secret_hex}"

    # 五元组注释（如果有）
    if event.has_tuple:
        t = event.tuple
        src = f"{ip_str(t.src_ip)}:{t.src_port}"
        dst = f"{ip_str(t.dst_ip)}:{t.dst_port}"
        line = f"# five_tuple=tcp:{src}->{dst}\n{line}"

    print(line)
    with open(OUTPUT_FILE, 'a') as f:
        f.write(line + '\n')

# 加载 BPF 程序，注册回调，进入 poll 循环
```

### 阶段 T4.2：五元组关联（1 周）

#### T4.2.1：TCP 连接追踪 tracepoint（1d）

```c
// 追踪 Chrome 进程的所有 TCP 连接建立
SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // 只关心 TCP_SYN_SENT → TCP_ESTABLISHED 转换
    if (ctx->newstate != 1 /* TCP_ESTABLISHED */) return 0;

    // 过滤进程：只跟踪 chrome
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    // 可通过 pid_filter_map 过滤

    struct five_tuple tuple = {};
    tuple.src_ip   = ctx->saddr[0];  // IPv4
    tuple.dst_ip   = ctx->daddr[0];
    tuple.src_port = ctx->sport;
    tuple.dst_port = ctx->dport;
    tuple.protocol = 6;  // TCP

    __u64 fd_key = /* 需要从 sock 获取 fd */;
    // 注意：tracepoint 直接拿不到 fd，需要另外 Hook

    return 0;
}
```

#### T4.2.2：connect() 系统调用追踪（1d）

更可靠的方式是 Hook `connect()` 系统调用，直接获取 fd 和目标地址：

```c
SEC("kprobe/__sys_connect")
int trace_connect(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    // 检查是否是 chrome 进程（pid_filter_map）

    int fd = PT_REGS_PARM1(ctx);
    struct sockaddr_in *addr = (void *)PT_REGS_PARM2(ctx);

    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), addr);

    if (sa.sin_family != AF_INET) return 0;  // 只处理 IPv4

    struct five_tuple tuple = {};
    tuple.dst_ip   = sa.sin_addr.s_addr;
    tuple.dst_port = __builtin_bswap16(sa.sin_port);
    tuple.protocol = 6;

    // src_ip 和 src_port 在 connect 返回后才确定
    // 需要在 kretprobe 中用 getsockname 逻辑获取
    // 或在 HKDF hook 时通过 getpeername 延迟获取

    __u64 fd_key = fd;
    bpf_map_update_elem(&fd_tuple_map, &fd_key, &tuple, BPF_ANY);
    return 0;
}
```

#### T4.2.3：ssl_ptr → fd 路径探测与验证（1–2d）

**此任务依赖 T4.0.3 的结果。**

一旦确认 rbio 偏移，在 HKDF uretprobe 中启用五元组关联：

```c
// 假设 T4.0.3 确认 rbio_offset = 0x??, bio_fd_offset = 0x??
#define SSL_RBIO_OFFSET  0x??  // 待确认
#define BIO_FD_OFFSET    0x??  // 待确认

// 在 uretprobe 中：
__u64 rbio = 0;
bpf_probe_read_user(&rbio, 8, (void *)(entry->ssl_ptr + SSL_RBIO_OFFSET));
if (rbio) {
    __u32 fd = 0;
    bpf_probe_read_user(&fd, 4, (void *)(rbio + BIO_FD_OFFSET));
    __u64 fd_key = fd;
    struct five_tuple *tuple = bpf_map_lookup_elem(&fd_tuple_map, &fd_key);
    if (tuple) {
        evt->tuple = *tuple;
        evt->has_tuple = 1;
    }
}
```

#### T4.2.4：备选方案 — 时序关联（0.5d）

如果 fd 路径无法打通（ssl_st 偏移不稳定），用时序关联作为 fallback：

```python
# 用户空间 daemon 中
# HKDF 事件带时间戳，connect 事件也带时间戳
# 对同一 pid/tid，取 HKDF 之前最近的 connect 事件作为匹配
# 窗口 < 500ms

def correlate_by_time(key_event, connect_events):
    candidates = [c for c in connect_events
                  if c.pid == key_event.pid
                  and (key_event.ts - c.ts) < 500_000_000  # 500ms in ns
                  and (key_event.ts - c.ts) > 0]
    return max(candidates, key=lambda c: c.ts) if candidates else None
```

### 阶段 T4.3：集成测试与验证（0.5 周）

#### T4.3.1：密钥提取验证（与 P3 对标）（1d）

```bash
# 与 P3 相同的验证方式
SSLKEYLOGFILE=/tmp/ebpf_env.log chrome --no-sandbox &
sudo ./tls_capture_daemon -o /tmp/ebpf_capture.log -p $(pgrep chrome)

# 访问站点后对比
diff <(sort /tmp/ebpf_capture.log | grep -v "^#") \
     <(grep -E "^(CLIENT|SERVER|EXPORTER)" /tmp/ebpf_env.log | sort)

# 标准：与 P3 捕获率持平（≥ 96%）
```

#### T4.3.2：五元组验证（1d）

```bash
# 同时抓包
sudo tcpdump -i any -w /tmp/test.pcap 'tcp port 443'

# 检查五元组注释与实际流量包的对应关系
# 从 capture.log 中提取五元组
grep "^# five_tuple" /tmp/ebpf_capture.log | sort -u

# 从 pcap 中提取实际连接
tshark -r /tmp/test.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -Y "tls.handshake.type==1" | sort -u

# 交叉比对
```

#### T4.3.3：Wireshark 端到端验证（0.5d）

用 eBPF 捕获的密钥文件解密 pcap，确认明文可见。

---

## 四、任务时间线

```
周1: T4.0.1~T4.0.4 (环境 + 偏移量探测) + T4.1.1~T4.1.2 (HKDF uprobe)
周2: T4.1.3~T4.1.4 (PRF + daemon) + T4.2.1~T4.2.3 (五元组)
周3: T4.2.4 (fallback) + T4.3.1~T4.3.3 (测试验证)
```

| 任务 | 描述 | 类型 | 工时 | 依赖 |
|------|------|------|------|------|
| T4.0.1 | eBPF 开发环境安装 | 环境 | 1d | — |
| T4.0.2 | uprobe 基本验证 | 验证 | 0.5d | T4.0.1 |
| T4.0.3 | ssl_st→rbio→fd 偏移量探测 | 逆向 | 1–2d | Ghidra + Frida |
| T4.0.4 | ssl_log_secret 定位（可选） | 逆向 | 1d | Ghidra |
| T4.1.1 | 数据结构定义 | 开发 | 0.5d | — |
| T4.1.2 | HKDF uprobe/uretprobe | 开发 | 2d | T4.0.2 |
| T4.1.3 | PRF uprobe | 开发 | 1d | T4.1.2 |
| T4.1.4 | 用户空间 daemon | 开发 | 1d | T4.1.2 |
| T4.2.1 | TCP tracepoint | 开发 | 1d | T4.0.1 |
| T4.2.2 | connect() kprobe | 开发 | 1d | T4.2.1 |
| T4.2.3 | ssl_ptr→fd 集成 | 开发 | 1–2d | T4.0.3 + T4.1.2 |
| T4.2.4 | 时序关联 fallback | 开发 | 0.5d | T4.1.4 |
| T4.3.1 | 密钥提取验证 | 测试 | 1d | T4.1.4 |
| T4.3.2 | 五元组验证 | 测试 | 1d | T4.2.3 |
| T4.3.3 | Wireshark 端到端 | 验证 | 0.5d | T4.3.1 |

---

## 五、风险与对策

| 风险 | 影响 | 概率 | 对策 |
|------|------|------|------|
| 内核版本 < 5.8，uprobe 功能受限 | 无法使用 BPF_KPROBE 宏 | 低 | 升级内核或降级使用 raw tracepoint |
| ssl_st 中 rbio 偏移无法确认 | 五元组关联失败 | 中 | 使用时序关联 fallback |
| eBPF 验证器拒绝复杂指针链 | 程序加载失败 | 中 | 拆分为更小的辅助函数 + `__always_inline` |
| Chrome 开启 ASLR 导致 RVA 变化 | uprobe 挂载地址错误 | 低 | uprobe 自动处理 ASLR（基于文件偏移） |
| uretprobe 栈帧恢复问题 | 极少数崩溃 | 低 | 使用 fentry/fexit 替代（需 BTF） |

### 关于 ASLR 的重要说明

eBPF uprobe **不受 ASLR 影响**。uprobe 的挂载点是**文件内偏移**（等同于 RVA），内核在加载时自动映射到进程虚拟地址。这与 Frida 的 `Module.base + offset` 原理相同但更底层。P1/P2 确认的 RVA 可以直接使用。

---

## 六、关键交付物

| 交付物 | 描述 |
|--------|------|
| `tls_capture.bpf.c` | eBPF 程序源码（uprobe + tracepoint） |
| `tls_capture.h` | 共享数据结构定义 |
| `tls_capture_daemon.py` | 用户空间 daemon |
| `Makefile` | 编译脚本（clang/llvm） |
| P4 验证报告 | 捕获率对标 P3 + 五元组准确率 |
| ssl_st 偏移量文档 | rbio/fd 偏移量及验证过程 |

---

## 七、P3→P4 过渡检查清单

在正式开始 P4 编码前，请确认以下事项：

- [ ] 记录当前 Chrome 精确版本号（`google-chrome --version`）
- [ ] 确认内核版本 ≥ 5.8（`uname -r`）
- [ ] 安装 libbpf-dev、clang、llvm
- [ ] 用 `bpftrace` 验证 uprobe 对 Chrome 可用
- [ ] **最重要**：运行 fd 探针（T4.0.3），确认 ssl_st→rbio→fd 路径

---

## 八、数据库 Schema 更新建议

P4 完成后，P1 定义的数据库 Schema 需要新增以下字段：

```sql
ALTER TABLE fingerprint_db ADD COLUMN ssl_rbio_offset INTEGER;      -- ssl_st 中 rbio 字段偏移
ALTER TABLE fingerprint_db ADD COLUMN bio_fd_offset INTEGER;        -- BIO 中 fd 字段偏移
ALTER TABLE fingerprint_db ADD COLUMN evp_md_size_offset INTEGER;   -- EVP_MD 中 md_size 偏移（+4）
ALTER TABLE fingerprint_db ADD COLUMN client_random_path TEXT;      -- CR 读取路径描述
ALTER TABLE fingerprint_db ADD COLUMN keylog_func_rva INTEGER;      -- ssl_log_secret RVA（可选）
```
