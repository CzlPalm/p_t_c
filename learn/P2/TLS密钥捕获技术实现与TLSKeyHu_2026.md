# TLS密钥捕获技术实现与TLSKeyHunter baseline分析

**Me**

背景：我想通过TLSKeyHunter这篇论文作为baseline来实现针对于浏览器的TLS密钥捕获技术，最后能得到与五元组进行关联的TLS密钥数据 1、请你详细阅读该md文档，该文档是我之前正在进行的工作记录，务必了解之前进度和我的目的以及项目方向 2、pdf文件是TLSKeyHunter这篇论文，请仔细阅读分析了解该技术，明白我把它作为baseline的意义，同时你也可以查看github仓库了解项目 3、docx文档是你给我的规划方案，现在正在进行p1，现在完成了PRF函数的工作，详细参看聊天记录，正在进行TLS1.3的工作，但是还差一些补充，你若是确定当前情况我就将补充和其他你需要的文件给你，让你更加了解。
当你了解以上情况之后我会汇报当前进度和工作，请你帮我解决难题

**Claude**

文档已全面阅读完毕。现在我对整个项目的进展非常清晰了。

让我总结一下当前状态，然后请你告诉我具体卡在哪里：

**已完成的工作（P1阶段）：**

TLS 1.2 PRF 部分已完整分析：
- `FUN_0a32d4b0` → `boringssl_tls1_prf`（master secret派生，**主要Hook点**）
- `FUN_0a32d130` → key expansion路径（次要Hook点）
- `FUN_0a2c5180` → 底层P_hash（仅记录，不需Hook）
- imageBase确认为`0x00100000`，RVA计算已明确
- 结构体偏移：client_random在`*(ssl_ptr+0x30)+0x10`，32字节

TLS 1.3 HKDF 部分已完成静态分析：
- `FUN_049837e0` → `boringssl_tls13_derive_secret`（**唯一核心Hook点**）
- RVA: `0x48837E0`，指纹106字节已提取
- 内存偏移：`c ap traffic`→`ssl_ptr+0xe4`，`s ap traffic`→`ssl_ptr+0x115`，exporter→`*(ssl_ptr+0x30)+0x182`等

**当前卡点：**

你说"还差一些补充"，正在进行TLS 1.3工作。我判断可能缺少的是：

1. `c hs traffic` / `s hs traffic`（握手流量密钥）的XREF是否也走`FUN_049837e0`尚未最终确认
2. `client_random`在TLS 1.3场景下的获取路径（BoringSSL通过session结构体传递，偏移量需确认）
3. 可能还没开始写Frida Hook脚本

请把当前的具体情况和卡住的问题告诉我，我来帮你解决。

**Me**

这是之前得到的对TLS1.3工作的补充，以及进入P2阶段与TLSKeyHunter得出结果进行的对比；最终我在进行p3阶段验证密钥是否正确时发现：我使用watchdog_attach.py捕获的密钥没有一个能够解密流量包（wireshark验证），也没有与环境变量SSLKEYLOG相同的密钥。1、请你对这些文件重新分析，到底是什么原因导致密钥错误？
2、假如手动分析错误，是否可以通过修改TLSKeyHunter源码来自动获取全部hook点？这是P8阶段，如果p3错误可能导致后续阶段无法进行

**Claude**

好，所有材料已经完整阅读。现在我可以精准定位问题所在。

---

## 问题诊断：密钥提取失败的根本原因

仔细分析 `watchdog_attach.py` 的 Hook 脚本，发现**至少三个严重错误**：

### 错误一（最致命）：HKDF 参数索引完全错误

Hook 脚本里写的：
```javascript
this.ssl = a[0];   // RDI → param_9 ???
this.out = a[1];   // RSI → param_10 ???
this.ll  = a[4].toInt32();  // R8 → label_len ???
this.lbl = a[3].readUtf8String(this.ll);  // RCX → label ???
```

但从你的 Ghidra 分析和汇编反编译已经明确：`FUN_049837e0` 的签名有 **8个XMM寄存器参数（param_1~param_8）排在前面**，整数寄存器参数从 `param_9` 开始：

```
param_1~param_8:  XMM0~XMM7（浮点/SIMD寄存器，Frida a[0]~a[7]对应这些！）
param_9  (RDI):   ssl_ptr        → Frida 里是 a[8]
param_10 (RSI):   output_buf     → a[9]  ★ 密钥输出
param_11 (RDX):   HKDF ctx       → a[10]
param_12 (RCX):   label 字符串   → a[11]
param_13 (R8):    label 长度     → a[12]
param_14 (R9):    hash 算法      → a[13]
```

**Frida 的 `args[]` 只追踪整数寄存器（RDI, RSI, RDX, RCX, R8, R9）**，XMM 寄存器参数不占用 `args[]` 的索引。所以正确的映射是：

```javascript
// 错误的（当前代码）:
this.ssl = a[0];  // 实际读到的是 XMM0 对应的整数寄存器值，完全错误
this.out = a[1];
this.lbl = a[3].readUtf8String();
this.ll  = a[4].toInt32();

// 正确的应该是:
this.ssl = args[0];  // RDI = ssl_ptr (param_9, 第一个整数寄存器参数)
this.out = args[1];  // RSI = output_buf (param_10)
// RDX = args[2] = HKDF ctx
this.lbl = args[3];  // RCX = label ptr (param_12)
this.ll  = args[4].toInt32();  // R8 = label len (param_13)
```

等等——仔细对照汇编序言：

```asm
4C 89 45 88  → MOV [RBP-0x78], R8   ← param_13(label_len) 保存自 R8
49 89 CC     → MOV R12, RCX         ← R12 = label 指针 (param_12) 自 RCX
49 89 D7     → MOV R15, RDX         ← R15 = HKDF ctx (param_11) 自 RDX
48 89 F3     → MOV RBX, RSI         ← RBX = ★ output buf (param_10) 自 RSI
49 89 FE     → MOV R14, RDI         ← R14 = ssl_ptr (param_9) 自 RDI
```

所以 Frida args[] 对应关系（Frida 只追踪整数寄存器，按 RDI/RSI/RDX/RCX/R8/R9 顺序）：

```
args[0] = RDI = ssl_ptr
args[1] = RSI = output_buf  ← 密钥写入地址
args[2] = RDX = HKDF ctx
args[3] = RCX = label 字符串指针
args[4] = R8  = label 长度
args[5] = R9  = hash 算法
```

**当前代码的 a[0]~a[4] 映射恰好是对的！**但问题出在别处——

### 错误二（致命）：`client_random` 读取路径错误

脚本中：
```javascript
function readCR(ssl) {
    return ssl.readPointer().add(0x30).readPointer().add(0x10).readByteArray(32);
}
```

你的 JSON 分析文档里写的路径是：
```
client_random: *(*(RDI) + 0x30) + 0x10  → 32 字节
```

但注意 JSON 里的注释：
```json
"ssl_st": {
    "s3_ptr_offset": "0x00 (ssl_ptr[0] = *ssl_ptr)",
    "note": "ssl_ptr 本身即 ssl_st*，第一个字段是 SSL3_STATE* s3"
}
```

所以路径是：`ssl_ptr → 解引用得到 SSL3_STATE* → +0x30 → 解引用 → +0x10`。脚本的 `ssl.readPointer().add(0x30).readPointer().add(0x10)` 是三次操作，但实际应该是：

```
*ssl_ptr          → s3 指针
*(s3 + 0x30)      → 某个子结构指针  
+0x10             → client_random
```

脚本写法是 `ssl.readPointer()` 得到 s3，`.add(0x30)` 得到地址 s3+0x30，`.readPointer()` 再解引用，`.add(0x10)` 再加偏移。这条路径实际上是四层解引用，**多了一层**。

### 错误三（致命）：HKDF 的 `ssl_ptr` 参数来源不同

这是最根本的问题。`FUN_049837e0` 的 `RDI`（args[0]）**不是 ssl_ptr**！

回看补充.md 中的函数签名：

```
FUN_04983470（调用者）:
    param_9 (RDI) → long *（这是 ssl_st*）
    
调用 FUN_049837e0 时:
    LEA RCX,[s_c_hs_traffic_025ccec0]  ← label
    CALL 0x049837e0
```

但 `FUN_049837e0` 被调用时 RDI 传的是什么？从调用处的代码 `FUN_049836b0` 可以看到：

```c
FUN_049837e0(..., param_9,          // RDI = ssl_ptr
             (long)param_9 + 0xe4, // RSI = output_buf
             (long)plVar1,          // RDX = ssl_ptr + 0x39*8 (hash ctx)
             "c ap traffic", 0xc,
             in_R9);
```

`args[0]` 确实是 ssl_ptr，但 **ssl_ptr 在 HKDF 函数里是直接作为指针使用，不需要额外解引用来取 s3**。`readCR` 函数的路径要重新确认。

---

## 修正后的完整 Hook 脚本

```python
HOOK_JS = r"""
'use strict';

const NSS_LABEL = {
    'c e traffic':  'CLIENT_EARLY_TRAFFIC_SECRET',
    'c hs traffic': 'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
    's hs traffic': 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
    'c ap traffic': 'CLIENT_TRAFFIC_SECRET_0',
    's ap traffic': 'SERVER_TRAFFIC_SECRET_0',
    'exp master':   'EXPORTER_SECRET',
};

// 密钥长度字节在 ssl_ptr 上的偏移（从 JSON 分析文档）
const KEY_LEN_OFFSET = {
    'c e traffic':  0x81,
    'c hs traffic': 0xb2,
    's hs traffic': 0xe3,
    'c ap traffic': 0x114,
    's ap traffic': 0x145,
};

function hex(buf) {
    if (!buf) return null;
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

function readClientRandom_tls13(ssl_ptr) {
    // ssl_ptr → *ssl_ptr = s3_ptr → s3_ptr + 0x30 = &handshake_random
    // client_random 在 s3_ptr + 0x30 的结构体偏移 0x10
    try {
        const s3 = ssl_ptr.readPointer();          // *ssl_ptr
        const cr_ptr = s3.add(0x30).readPointer(); // *(s3 + 0x30)
        return cr_ptr.add(0x10).readByteArray(32); // client_random
    } catch(_) {
        return null;
    }
}

function readClientRandom_tls12(ssl_ptr) {
    // 与 TLS 1.3 路径相同
    return readClientRandom_tls13(ssl_ptr);
}

function emit(line) { send({t: 'key', v: line}); }
function dbg(msg)   { send({t: 'dbg', v: '[pid=' + Process.id + '] ' + msg}); }

// ── 找 chrome 模块 ──
const mod = (function() {
    for (const n of ['chrome', 'libchrome.so']) {
        try { return Process.getModuleByName(n); } catch(_) {}
    }
    return Process.enumerateModules()
        .filter(m => m.size > 50 * 1024 * 1024)
        .sort((a, b) => b.size - a.size)[0] || null;
})();

if (!mod) {
    dbg('chrome 模块未找到');
    send({t: 'no_module'});
} else {
    dbg('模块: ' + mod.name + ' base=' + mod.base +
        ' size=' + (mod.size / 1024 / 1024 | 0) + 'MB');

    let prf_ok = false, hkdf_ok = false;

    // ── TLS 1.2 PRF Hook ──
    // RVA: 0x0A22D4B0 (imageBase=0x00100000 时)
    try {
        const prf_addr = mod.base.add(ptr('0x0A22D4B0'));
        Interceptor.attach(prf_addr, {
            onEnter(args) {
                // args[0]=RDI=ssl_ptr, args[1]=RSI=output_buf(master_secret)
                this.ssl_ptr = args[0];
                this.out_ptr = args[1];
                dbg('PRF onEnter ssl=' + this.ssl_ptr + ' out=' + this.out_ptr);
            },
            onLeave(_retval) {
                try {
                    const ms = this.out_ptr.readByteArray(48);
                    const cr = readClientRandom_tls12(this.ssl_ptr);
                    if (ms && cr) {
                        const line = 'CLIENT_RANDOM ' + hex(cr) + ' ' + hex(ms);
                        emit(line);
                        dbg('PRF: ' + line.substring(0, 60) + '...');
                    } else {
                        dbg('PRF: ms=' + (ms?'ok':'null') + ' cr=' + (cr?'ok':'null'));
                    }
                } catch(e) { dbg('PRF onLeave err: ' + e); }
            }
        });
        prf_ok = true;
        dbg('PRF hook OK @ ' + mod.base.add(ptr('0x0A22D4B0')));
    } catch(e) { dbg('PRF hook FAIL: ' + e); }

    // ── TLS 1.3 HKDF Derive-Secret Hook ──
    // RVA: 0x048837E0
    try {
        const hkdf_addr = mod.base.add(ptr('0x048837E0'));
        Interceptor.attach(hkdf_addr, {
            onEnter(args) {
                // args[0]=RDI=ssl_ptr
                // args[1]=RSI=output_buf  ← 密钥写入此处
                // args[2]=RDX=HKDF ctx
                // args[3]=RCX=label ptr
                // args[4]=R8=label len
                this.ssl_ptr = args[0];
                this.out_ptr = args[1];
                const ll = args[4].toInt32();
                
                try {
                    if (ll > 0 && ll <= 20) {
                        this.label = args[3].readUtf8String(ll);
                    } else {
                        this.label = null;
                    }
                } catch(_) { this.label = null; }

                if (this.label) {
                    dbg('HKDF onEnter label="' + this.label + '" ssl=' + this.ssl_ptr);
                }
            },
            onLeave(_retval) {
                try {
                    if (!this.label) return;
                    const nss = NSS_LABEL[this.label];
                    if (!nss) return;  // 跳过 res master、derived 等

                    // 读取密钥长度
                    let key_len = 32; // 默认
                    const len_off = KEY_LEN_OFFSET[this.label];
                    if (len_off) {
                        try {
                            key_len = this.ssl_ptr.add(len_off).readU8();
                            if (key_len === 0 || key_len > 64) key_len = 32;
                        } catch(_) { key_len = 32; }
                    }

                    // 读取派生的密钥（从 output_buf 读）
                    const secret = this.out_ptr.readByteArray(key_len);
                    
                    // 读取 client_random
                    const cr = readClientRandom_tls13(this.ssl_ptr);
                    
                    if (secret && cr) {
                        const line = nss + ' ' + hex(cr) + ' ' + hex(secret);
                        emit(line);
                        dbg('HKDF: ' + nss + ' len=' + key_len);
                    } else {
                        dbg('HKDF miss: secret=' + (secret?'ok':'null') +
                            ' cr=' + (cr?'ok':'null') +
                            ' label=' + this.label);
                    }
                } catch(e) { dbg('HKDF onLeave err: ' + e); }
            }
        });
        hkdf_ok = true;
        dbg('HKDF hook OK @ ' + mod.base.add(ptr('0x048837E0')));
    } catch(e) { dbg('HKDF hook FAIL: ' + e); }

    send({t: 'ready', prf: prf_ok, hkdf: hkdf_ok});
}
"""
```

但在直接使用修正脚本之前，**我强烈建议先做一个探针验证**，确认 client_random 读取路径是否正确，因为这是最容易出错的地方：---

## 总结分析

### 问题一：密钥提取失败的根本原因

仔细对比原始脚本和你的 Ghidra 分析，发现**原脚本存在参数混淆问题**：

原脚本的 HKDF Hook 里：
```javascript
onEnter(a) {
    this.ssl = a[0];    // 看起来对...
    this.out = a[1];    // 看起来对...
    this.ll  = a[4].toInt32();   // label len
    this.lbl = a[3].readUtf8String(this.ll);  // label
}
```

这部分参数索引其实是正确的（Frida 整数寄存器顺序）。**真正的问题有两处：**

**问题 1：`readCR` 的路径可能是错的**。你的分析文档里 client_random 路径写的是 `*(*(RDI) + 0x30) + 0x10`，但原脚本实现是 `ssl.readPointer().add(0x30).readPointer().add(0x10)`，展开是四步操作，而实际路径可能是三步（`*ssl_ptr = s3`，`*(s3 + 0x30) = handshake 结构体地址`，`+0x10 = client_random`）。这条路径需要探针脚本实测验证。

**问题 2：`this.out` 在 `onLeave` 中可能已被覆盖**。这是 Frida 的一个已知陷阱——`args` 数组在 `onLeave` 时不可靠，必须在 `onEnter` 时用 `this.xxx = args[n]` 显式保存。原脚本在 `onLeave` 里用了 `this.out.readByteArray(kl)` 而不是在 `onEnter` 保存值，如果 `this.out` 在某些情况下读到了垃圾值，密钥就会完全错误。

### 操作步骤

**第一步（必须）：先运行探针脚本确认 client_random 路径**

```bash
# 先启动 Chrome
SSLKEYLOGFILE=/tmp/env.log /opt/google/chrome/chrome \
  --no-sandbox --user-data-dir=/tmp/cr_test &

# 找到 NetworkService PID
pgrep -f NetworkService

# 附加探针（不是 watchdog，是 probe）
frida -p <PID> -l probe_ssl_structure.js
```

在 Chrome 里访问任意 HTTPS 网站，探针会打印 `c hs traffic` 调用时的所有候选值，对比 `/tmp/env.log` 里第一条 `CLIENT_HANDSHAKE_TRAFFIC_SECRET` 前面的 client_random，确认哪条路径 [A]/[B]/[C] 匹配。

**第二步：确认路径后运行修正版**

修正版 `watchdog_attach_v2.py` 保留了 `readCR` 路径 A，如果探针显示路径不对，告诉我正确偏移我来更新脚本。

### 问题二：TLSKeyHunter 源码修改（用于 P8 阶段）

TLSKeyHunter 对 PRF 失败的根本原因已在 `比对.md` 中分析清楚：**`.rodata` 字节模式回退路径只在 HKDF 识别中存在，PRF 没有**。对于 P8 阶段，修改方案是可行的，但先把 P3 跑通更重要——等你把探针结果发过来，我们确认 client_random 路径后，P3 就可以验证通过，然后再讨论 TLSKeyHunter 的 PRF 回退路径修改。

**Me**

该文档是运行第一步的结果，请你继续分析检查

**Claude**

 日志分析得非常清晰，现在可以完全确认 client_random 的正确路径。

## 关键发现：client_random 就在 ssl_ptr 直接偏移处

对比三次探测：

**Probe #1** (`c hs traffic`)，路径A的 client_random:
```
5bebe76610a1c4c84bc08b0e7a3015bbc22b8cbaa5e52ee4f73377a88e5fca62
```

**RAW 内存 ssl_ptr+0x20:**
```
+0x020: 21 00 9d bb 24 04 d7 25 99 87 67 aa 60 55 46 c0
+0x030: d7 44 d5 28 d1 43 c5 1d f2 6e 82 a8 5e f1 9e c9
```

路径A的结果 `5bebe766...` 与 RAW 里的数据不匹配，说明**路径A是错的**。

但注意 **Probe #2** (`c ap traffic`)，RAW ssl_ptr+0x20:
```
+0x020: 54 70 62 80 c7 55 3c 33 61 e5 a8 ed 9a c2 3e f3
+0x030: 6a 0b cf 95 22 f2 f7 14 25 16 cd 96 6f e3 1b 01
```

路径B里 `ssl+0x20` = `54706280c7553c33...`，`ssl+0x30` = `6a0bcf9522f2f714...`——这两段合起来正好是 32 字节，而且看起来像随机密钥材料。

**真正的 client_random 需要和 SSLKEYLOGFILE 对比**。现在先看路径A的 client_random：`5bebe76610a1c4c84bc08b0e7a3015bbc22b8cbaa5e52ee4f73377a88e5fca62` — 这个是两次都出现的同一个 ssl_ptr `0x2a74000fc608` 产生的值，需要与环境变量日志核对。

请执行这个命令，告诉我输出：

```bash
grep "5bebe76610a1c4c84bc08b0e7a3015bbc22b8cbaa5e52ee4f73377a88e5fca62" /tmp/chrome_sslkeys_env.log
```

以及：

```bash
head -20 /tmp/chrome_sslkeys_env.log
```

把这两个命令的输出发给我，我来确认路径A是否正确，还是需要换路径。同时我注意到一个重要问题需要你确认：

**`out_ptr` 的偏移验证**

Probe #1: `ssl_ptr=0x2a74000fc608`, `out_ptr=0x2a74000fc68a`
差值: `0x2a74000fc68a - 0x2a74000fc608 = 0x82`

这完全对应 `c hs traffic` 的 `output_offset = ssl_ptr + 0x82`！

Probe #2: `ssl_ptr=0x2a74000fc608`, `out_ptr=0x2a74000fc6ec`
差值: `0x2a74000fc6ec - 0x2a74000fc608 = 0xe4`

完美对应 `c ap traffic` 的 `output_offset = ssl_ptr + 0xe4`！

这说明**密钥输出缓冲区偏移完全正确**，args[1] 读取的 out_ptr 无误。问题只出在 client_random 路径上，把那两个 grep 结果发过来就能最终确认。

**Me**

(fritap-env) palm@palm-Dell-Pro-Tower-QCT1250:~/桌面$ grep "5bebe76610a1c4c84bc08b0e7a3015bbc22b8cbaa5e52ee4f73377a88e5fca62" /tmp/chrome_sslkeys_env.log
没有结果返回，我在log文件里搜索也没有匹配项，
(fritap-env) palm@palm-Dell-Pro-Tower-QCT1250:~/桌面$ head -20 /tmp/chrome_sslkeys_env.log
CLIENT_HANDSHAKE_TRAFFIC_SECRET 53b27b358768020ba791fbdff35f561f0e4d780aa7cfd92fc2c7c2e3df3fc184 219e147ad9e4ae23f3700ee24cc181f13a579fb8c182c65fecad6716839316d1
SERVER_HANDSHAKE_TRAFFIC_SECRET 53b27b358768020ba791fbdff35f561f0e4d780aa7cfd92fc2c7c2e3df3fc184 d93bac6d166cf61f4d6e13e0b93661e8ca105b3ff5a52a08d26b78ea40155749
CLIENT_TRAFFIC_SECRET_0 53b27b358768020ba791fbdff35f561f0e4d780aa7cfd92fc2c7c2e3df3fc184 503477c3941ba412360fa5eeb096cf21bc5206dd8a3f1fec2029819cd1bd3244
SERVER_TRAFFIC_SECRET_0 53b27b358768020ba791fbdff35f561f0e4d780aa7cfd92fc2c7c2e3df3fc184 9a72392e67298a91afb0097b5ef493043354fe67de551b259b0d58525362df36
EXPORTER_SECRET 53b27b358768020ba791fbdff35f561f0e4d780aa7cfd92fc2c7c2e3df3fc184 864508fdcf0d9090d14ee4dce76d1d72cd6a8b23050a1a0c025b3d581b059d65
CLIENT_HANDSHAKE_TRAFFIC_SECRET b7dcb551f4b6ab20312eb46430c09307af07c7fa5be45908224736bdeec2b77d d473e9e71e90275ec1e0d3c1c28b5ea271ca98040703205b974b0fca203ccd66
SERVER_HANDSHAKE_TRAFFIC_SECRET b7dcb551f4b6ab20312eb46430c09307af07c7fa5be45908224736bdeec2b77d 1e620da2f9612f54c3406aa85084a47f635409652ab01fe9cb5c593e62654d0c
CLIENT_TRAFFIC_SECRET_0 b7dcb551f4b6ab20312eb46430c09307af07c7fa5be45908224736bdeec2b77d c0994932314b59210e1fd11dd9e850ec1c2e2ac07292a3b94a59e8f77cff3485
SERVER_TRAFFIC_SECRET_0 b7dcb551f4b6ab20312eb46430c09307af07c7fa5be45908224736bdeec2b77d b0ae488a7d74991609dd60b91937a29c2e94908eb861752588da8ad98d821c1c
EXPORTER_SECRET b7dcb551f4b6ab20312eb46430c09307af07c7fa5be45908224736bdeec2b77d f27ec358d2769b5fce3940620db3a247a7c41df1945c775e80f7bde6dd09bf7c
CLIENT_HANDSHAKE_TRAFFIC_SECRET e80108e35b7f778b3d682406398c187de99c53da1275a66fe2191c90f5e75af6 f8312655ee883d1090625aeddb2b530ef2f0c9b30320447427417bf1fc1ec2ebffb14f25fe4de96d0961781debd074ff
SERVER_HANDSHAKE_TRAFFIC_SECRET e80108e35b7f778b3d682406398c187de99c53da1275a66fe2191c90f5e75af6 8cad0704d94256cd3fb77d122ba7fe17beaa01952e72dc06b68442656719d50758fe7ac40df4920f7d5d039e63b6487a
CLIENT_TRAFFIC_SECRET_0 e80108e35b7f778b3d682406398c187de99c53da1275a66fe2191c90f5e75af6 8f0a7fbbc941ade15c9e2d8100ca6509a916dcb012a2fb74af52629b8c1f4f78cdd7b9f6e382df396787b4c8c21fca06
SERVER_TRAFFIC_SECRET_0 e80108e35b7f778b3d682406398c187de99c53da1275a66fe2191c90f5e75af6 3916069a76a404c728c173db0a653e76c0ce5c08092cc23e901b63ba19336f8d5e2aae06ada52b7d7b209e3fe4464237
EXPORTER_SECRET e80108e35b7f778b3d682406398c187de99c53da1275a66fe2191c90f5e75af6 d4e84a5515daeecb636f502fb9f3d2a6968b0d500215bbb908bfceccb1419bfce26f346a187607a5601ccdfdebe68018
CLIENT_HANDSHAKE_TRAFFIC_SECRET 4cc6b6c1d6421cbbe8e78f076d486be14e8a54fe7d145fbc31f1968d7155d3d2 8586a4d7a6ede6b9037a84370fbb7cee90f3a2138bc0176b5c680e972b84941a
SERVER_HANDSHAKE_TRAFFIC_SECRET 4cc6b6c1d6421cbbe8e78f076d486be14e8a54fe7d145fbc31f1968d7155d3d2 f77f2956e0b7b9918892ab3b817b6a7e756d3ea90b51bef82e4a0855ccbca316
CLIENT_HANDSHAKE_TRAFFIC_SECRET e1860e65274000646c20d6656bbd042b1fdb64754813a4054df7496f63c04635 aa27b7d019fc9a8463f7a2c6692944344aafe02ad14de5c8f42788cc7bf48d93
SERVER_HANDSHAKE_TRAFFIC_SECRET e1860e65274000646c20d6656bbd042b1fdb64754813a4054df7496f63c04635 e95488a8022d0d9f429828cdfa4dad2b7be66a5b7830cdaa0a8b481a2410c042
CLIENT_TRAFFIC_SECRET_0 4cc6b6c1d6421cbbe8e78f076d486be14e8a54fe7d145fbc31f1968d7155d3d2 83544b5da6f4152f33dcfc8fb90d6a4e750d54ab8cf329280fe6ab649c2adc46

**Claude**

 这个日志信息非常关键。现在可以完全确认问题所在了。

## 核心发现：client_random 读取路径 A 是错的

路径A返回的 `5bebe766...` 在 SSLKEYLOGFILE 里**完全找不到**，说明这不是真正的 client_random。

## 真正的 client_random 在哪里

对比日志里的 SSLKEYLOGFILE 第一条：
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 53b27b358768020ba791fbdff35f561f0e4d780aa7cfd92fc2c7c2e3df3fc184 ...
```

现在对照 Probe #1 的 RAW 内存（ssl_ptr 前 0x40 字节）：
```
+0x000: c8 98 0a 00 74 2a 00 00 88 37 08 00 74 2a 00 00
+0x010: 02 00 00 00 04 00 00 00 02 00 00 00 03 03 04 03
+0x020: 21 00 9d bb 24 04 d7 25 99 87 67 aa 60 55 46 c0
+0x030: d7 44 d5 28 d1 43 c5 1d f2 6e 82 a8 5e f1 9e c9
```

ssl_ptr+0x20 到 +0x3F 连起来是：
```
21009dbb2404d725998767aa605546c0d744d528d143c51df26e82a85ef19ec9
```

这个值在 SSLKEYLOGFILE 也没有直接命中。说明**Probe #1 对应的 TLS 连接不在日志的前20行**里，环境变量日志和 Frida 附加时机不同步（Frida 附加时 Chrome 已经跑了一批连接）。

需要先执行一个**精确的交叉验证**：在运行探针之前，先做一个重要的分析。

## 当前日志揭示了另一个关键问题

仔细看 SSLKEYLOGFILE 的格式：

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 53b27b35... 219e147a...   ← 密钥32字节
CLIENT_HANDSHAKE_TRAFFIC_SECRET e80108e3... f8312655ee883d1090625aed...ff  ← 密钥48字节！
```

**第11-15行的密钥是48字节（96个十六进制字符）！** 这说明这几个连接用的是 SHA-384（TLS_AES_256_GCM_SHA384），密钥长度是48字节而不是32字节。你的脚本里写死 `key_len=32` 作为默认值，对 SHA-384 连接完全是错的。

密钥长度偏移表里的 `*(byte*)(ssl_ptr + 0xb2)` 就是用来解决这个问题的——如果读出来是0（密钥还没写入前），或者读到的是错误值，就会截断密钥。

---

## 操作步骤（按顺序执行）

**第一步：清空日志 + 重启 Chrome**
```bash
# 关闭 Chrome
pkill chrome

# 清空日志（关键！确保时序对应）
> /tmp/chrome_sslkeys_env.log

# 重新启动
SSLKEYLOGFILE=/tmp/chrome_sslkeys_env.log \
  /opt/google/chrome/chrome \
  --no-sandbox \
  --user-data-dir=/tmp/chrome_p3_test \
  --disable-extensions &
```

**第二步：等 Chrome 完全启动（大约5-10秒），然后附加探针**
```bash
# 找 PID
pgrep -a chrome | grep NetworkService

# 附加新探针
frida -p <PID> -l probe_crosscheck.js
```

**第三步：访问一个新站点，然后立刻**
```bash
# 对比：拿探针输出的 SECRET-32B 去日志里搜
grep "<SECRET-32B的值>" /tmp/chrome_sslkeys_env.log
```

这次探针会打印 `*(ssl+0x8)` 结构体的完整前 256 字节，从里面一定能找到 client_random。把输出发给我，我来精确定位。

**Me**

这是获取的部分日志文件

**Claude**

 现在答案完全清晰了。逐个比对：

## 精确定位：client_random 在哪里

**连接 #2** 的密钥 `9dd31e4d...` 在 SSLKEYLOGFILE 里对应：
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET f96aeb8d34b965122c050291b4a16adb98d8b4b0561b12981c1fcbe98f93fec7 9dd31e4d...
```
真正的 client_random = `f96aeb8d34b965122c050291b4a16adb98d8b4b0561b12981c1fcbe98f93fec7`

现在对照连接 #2 的探针输出找这个值：
```
[A3] *ssl→*(+0x30)→+0x20: f7706e1fa52c7cf3bcf307dd594a9ffef96aeb8d34b965122c050291b4a16adb
```

**`f96aeb8d...` 出现在 A3 结果的后半段（偏移+0x10处）！**

验证连接 #3，密钥 `6817a3f4...` 对应 client_random = `3227f72b736e21803a1c5cd981d24a4c...`

对照连接 #3 探针：
```
[A3] *ssl→*(+0x30)→+0x20: c6a3d52dc99898273b668c4de111faef3227f72b736e21803a1c5cd981d24a4c
```

**`3227f72b...` 同样出现在 A3 结果的后半段！**

验证连接 #4，密钥 `bcf0425e...` 对应 client_random = `c162056e59baea79f4f18db12b3c3d94...`

对照连接 #4：
```
[A3] *ssl→*(+0x30)→+0x20: 152795e1c8249fe5cd720929f7ee5e4bc162056e59baea79f4f18db12b3c3d94
```

**`c162056e...` 出现在 A3 结果的后半段！三次全部一致，100% 确认。**

## 正确路径

```
client_random = *(*(*(ssl_ptr) + 0x30) + 0x30)  →  读 32 字节
```

即：
- `s3 = *ssl_ptr`（解引用一次）
- `sub = *(s3 + 0x30)`（再解引用）
- `cr = sub + 0x30`（不再解引用，直接读32字节）

之前路径A2 `+0x10` 差了 `0x20`，正确偏移是 `+0x30`。

现在立刻生成修正好的最终 Hook 脚本：## 问题已完全确认，一句话总结

**原脚本的 `readCR` 偏移写错了：`+0x10` 应为 `+0x30`。**

正确路径（三个连接100%交叉验证）：
```
client_random = *(*(*(ssl_ptr) + 0x30) + 0x30)  → 32字节
```

v3 脚本的核心修改只有这一行：
```javascript
// 错误（v1/v2）:
return sub.add(0x10).readByteArray(32);

// 正确（v3）:
return sub.add(0x30).readByteArray(32);
```

## 运行验证

```bash
# 清空日志 + 重启 Chrome
> /tmp/chrome_sslkeys_env.log
pkill chrome
SSLKEYLOGFILE=/tmp/chrome_sslkeys_env.log \
  /opt/google/chrome/chrome --no-sandbox \
  --user-data-dir=/tmp/chrome_p3_test --disable-extensions &

# 运行 v3
python3 watchdog_attach_v3.py
```

访问几个 HTTPS 站点后 Ctrl+C，脚本会自动输出验证命令：
```bash
diff <(sort /tmp/chrome_sslkeys_frida_v3.log) \
     <(grep -E "^(CLIENT|SERVER)" /tmp/chrome_sslkeys_env.log | sort)
```

如果 diff 无输出，P3 验证完成，可以正式进入 P4（eBPF uprobe + 五元组关联）。
