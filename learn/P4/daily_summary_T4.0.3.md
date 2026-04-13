# T4.0.3 实验小结
**日期：** 2026-03-31  
**目标：** 在 Chrome 143（BoringSSL）中定位 `ssl_st → rbio → fd` 完整指针链，  
为 P6 阶段"TLS 密钥 + 五元组自动关联"奠定结构体偏移基础。

---

## 一、背景与目标

TLS 密钥日志（SSLKEYLOGFILE / Frida HKDF hook）能捕获会话密钥，但密钥条目只包含
`client_random`，不直接告诉我们"这条密钥属于哪条 TCP 连接"。要实现自动化解密，
必须把密钥和五元组（src_ip:port → dst_ip:port）关联起来。

BoringSSL 的 `ssl_st` 结构体内部保存了 BIO 对象指针（`rbio`/`wbio`），
BIO 对象的 `num` 字段存储的正是底层 TCP socket 的 fd。
拿到 fd 后，通过 `/proc/{pid}/fd` → socket inode → `/proc/net/tcp` 即可查到五元组。

**因此，核心任务是找到两个编译期常量偏移：**

```
offset_A：ssl_ptr + A → BIO*（rbio 指针在 ssl_st 中的位置）
offset_B：BIO*    + B → fd  （fd 在 bio_st 中的位置，即 bio_st.num）
```

---

## 二、实验环境

| 项目 | 值 |
|------|----|
| 系统 | Ubuntu 24.04 LTS，内核 6.17.0-1012-oem，x86-64 |
| Chrome | 143.0.7499.169（官方预编译，stripped PIE） |
| BoringSSL commit | `992dfa0b56f98b8decaf82cd8df44aa714675d99` |
| 注入框架 | Frida 16.x，spawn 模式 |
| 辅助工具 | bpftrace、bpftool（源码编译）、objdump、readelf |

---

## 三、实验过程与方法

### 阶段 0：工具链准备

**问题：** `apt install bpftool` 报"无可安装候选"，原因是 bpftool 是虚包，
需要匹配内核版本的 tools 包，但 OEM 内核 6.17 没有对应的预编译包。

**解决：** 从 `github.com/libbpf/bpftool` 源码编译安装，解决缺少 `libssl-dev` 的
依赖后顺利编译。最终通过软链接将编译产物暴露到 PATH。

**原理：** bpftool 是 eBPF 程序管理工具，后续用于验证 uprobe 挂载能力，
与 BoringSSL 版本无关，只要内核支持 eBPF 即可使用。

---

### 阶段 1：验证 Chrome uprobe 挂载能力

**问题：** 直接用静态分析地址（`0x048837E0`）挂载 uprobe 报错：
`ERROR: Could not resolve address`

**根本原因：** Chrome 是 PIE（Position Independent Executable，位置无关可执行文件）。
静态分析工具给出的是文件内虚拟地址，而 uprobe 需要的是文件偏移（file offset）。

**解决方法：**  
1. 通过 `readelf -l chrome` 读取代码段（R E）的文件偏移（`0x2b46000`）和虚拟地址（`0x2b47000`），两者差值为 `0x1000`（1页）；  
2. 文件偏移 = 静态地址 - VirtAddr + 文件偏移 = `0x48837e0 - 0x2b47000 + 0x2b46000 = 0x48737e0`；  
3. 用 `bpftrace -l 'uprobe:/opt/google/chrome/chrome:*'` 验证挂载能力，
   成功列出 `ChromeMain`、`_Znwm` 等导出符号，证明 uprobe 框架可用。

**原理：** PIE 二进制加载时基址随机（ASLR），内核 uprobe 以文件偏移为锚点，
在运行时自动加上实际基址，因此必须使用文件偏移而非虚拟地址。

---

### 阶段 2：定位 HKDF 函数并验证 Frida Hook

**为什么选 HKDF 作为 hook 点：**  
TLS 1.3 使用 HKDF（HMAC-based Key Derivation Function）派生所有会话密钥
（握手密钥、流量密钥、exporter 密钥）。在 BoringSSL 中，每次派生操作都会调用
同一个内部函数，且调用约定固定：
- `RDI = ssl_ptr`（ssl 连接对象）
- `RSI = output_buf`（派生结果写入地址）
- `RDX/RCX/R8` = 标签参数

在这个 hook 点能同时拿到 `ssl_ptr`（用于后续结构体扫描）和密钥原材料，
是最经济的拦截位置。

**Frida spawn 模式的必要性：**  
Chrome 的 NetworkService 进程负责所有 TLS 连接。如果等进程启动后再 attach，
已建立的连接的握手密钥会被漏掉（时序差）。Spawn 模式在第一条指令执行前注入，
保证零漏捕。

**PRF hook（TLS 1.2）：** 同理 hook `ssl3_prf` 函数入口，在 `onLeave` 时
读取 master_secret，输出 `CLIENT_RANDOM` 行。

---

### 阶段 3：fd 偏移动态探测（v6.x 系列）

**为什么不用静态分析（Ghidra）：**  
Chrome 二进制是 stripped 的，没有符号表，`ssl_st` 的字段名全部被优化掉。
在 Ghidra 中搜索 "rbio" 字符串无结果（字符串常量在 stripped 二进制中不保留成员名）。
BIO_new_socket 的 XREF 路径存在但需要大量人工分析交叉引用链，耗时数天。

**核心思路（动态探测）：**  
已知 fd 是合法的小正整数（来自 `/proc/{pid}/fd`），在 HKDF hook 触发时，
`ssl_ptr` 指向的内存区域中必然有某个偏移存储了当前连接的 fd 值。
用已知 fd 集合反向扫描内存，找到匹配的偏移，即为目标。

**稳定性双重验证（v6.2 改进）：**  
早期版本（v6.0/v6.1）只统计命中次数，导致偶发碰撞（不相关字段恰好等于某个 fd 值）
被误确认。v6.2 引入两个独立条件：
- **连接内稳定**：同一 `ssl_ptr` 的多次 HKDF 调用中，该偏移读出的值唯一不变；
- **跨连接变化**：不同 `ssl_ptr` 之间该偏移的值不同（证明是动态字段，而非常量）。

只有同时满足两个条件的偏移才被确认，大幅消除噪声。

**扫描范围：** 同时扫描三层（ssl 直接层、s3 层、sub 层），覆盖 BoringSSL
多层结构体嵌套中 fd 可能出现的所有位置。

---

### 阶段 4：BIO 指针链探测（v7.0/v7.1）——T4.0.3 核心

**为什么需要指针链而非直接偏移：**  
阶段 3 确认的是"ssl_ptr + 0x238 处存在一个等于 fd 的 int32 值"，但这可能是
某个缓存字段（BoringSSL 在某些版本会在 ssl_st 直接缓存 fd）。
任务 T4.0.3 要求的是完整的语义路径：`ssl → rbio（BIO*）→ num（fd）`，
这是唯一在 BoringSSL 所有版本中语义稳定的访问路径。

**探测方法（两层指针扫描）：**  
1. 遍历 `ssl_ptr` 前 `0x500` 字节，每 8 字节视为一个潜在指针（候选 `offset_A`）；  
2. 对合法用户态地址范围（`0x100000 ~ 0x7fffffffffff`）内的每个候选指针，
   读取其指向区域前 `0x100` 字节，逐 4 字节查找已知 fd 值（候选 `offset_B`）；  
3. **wbio 交叉验证**：BoringSSL 中 rbio 和 wbio 紧邻存储（相差 8 字节），
   对同一 TCP socket 通常指向同一个 BIO 对象。
   若 `ssl_ptr + A + 8` 处也是指向同一 BIO 或合理地址的指针，则 `wbio_check = true`，
   大幅提升结果可信度。

**v7.0 → v7.1 的关键修复：**  
v7.0 使用 Python→JS post 通知机制（Python 确认 fd 后通过 `script.post()` 告知 JS），
存在异步时序问题——通知到达时当前 HKDF 调用已结束，需等下次触发。
v7.1 改为 **JS 自维护候选 fd 集合**：每次 `scanFdLayers` 时将发现的小正整数直接
加入集合，每隔 5 次 HKDF 自动尝试探测，完全不依赖外部通知，消除时序依赖。

---

## 四、最终结果

```json
{
  "chrome_version": "143.0.7499.169",
  "boringssl_commit": "992dfa0b56f98b8decaf82cd8df44aa714675d99",
  "platform": "Linux x86-64",
  "hkdf_hook_offset": "0x048837E0",
  "prf_hook_offset":  "0x0A22D4B0",

  "ssl_st_rbio_offset": "0x240",
  "bio_fd_offset":      "0x03c",
  "fd_read_path":       "*(*(ssl_ptr + 0x240) + 0x03c)",
  "wbio_check":         true,

  "五元组查询路径": "fd → /proc/{pid}/fd → socket inode → /proc/net/tcp → (src_ip:port, dst_ip:port)"
}
```

**结构体布局验证（与 BoringSSL 源码对应）：**

```
ssl_st（ssl_ptr）
  + 0x240  →  rbio*（BIO 指针）
  + 0x248  →  wbio*（与 rbio 指向同一 BIO 对象，TCP 全双工复用）

bio_st（BIO*）
  + 0x03c  →  num（int32，socket fd）
```

`bio_st.num` 对应 BoringSSL 源码 `ssl_lib.cc` 中 `SSL_get_rfd()` 的实现：
`BIO_find_type(SSL_get_rbio(ssl), BIO_TYPE_DESCRIPTOR)` 后读取的正是这个字段。

---

## 五、偏移的适用范围

| 条件 | 结论 |
|------|------|
| 同版本同平台（Linux x86-64, Chrome 143.0.7499.169） | **完全通用**，偏移是编译期常量 |
| Chrome 版本升级 | 需重新探测（BoringSSL commit 可能变化） |
| Windows / macOS | 不适用（ABI 差异） |
| ARM64 平台 | 不适用（结构体对齐不同） |
| Chromium 自编译 | 不保证 |

---

## 六、P6 自动化集成建议

1. **缓存策略**：以 `{chrome_version, platform}` 为 key 存储偏移，
   启动时查缓存，命中直接使用，未命中走动态探测流程（约需访问 3 个 HTTPS 站点）。

2. **密钥+五元组关联**：在 HKDF/PRF `onLeave` 发出密钥时，同步读取 fd：
   ```javascript
   const rbio = ssl.add(0x240).readPointer();
   const fd   = rbio.add(0x03c).readS32();
   send({t: 'key_with_fd', fd: fd, nss_line: nss_line});
   ```
   Python 侧用 fd 查 `/proc/net/tcp` 获取五元组，与密钥行合并输出。

3. **代理穿透**：当前环境所有连接目标为本地代理 `127.0.0.1:7897`，
   真实远端 IP 需另行 hook CONNECT 请求或读取代理日志。

---

## 七、工具链产出

| 文件 | 说明 |
|------|------|
| `watchdog_attach_v7.py` | T4.0.3 主脚本，含 BIO 链探测 |
| `/tmp/fd_offset_discovery.json` | fd 直接偏移确认结果 |
| `/tmp/bio_chain_result.json` | T4.0.3 最终结果（rbio/num 偏移） |

