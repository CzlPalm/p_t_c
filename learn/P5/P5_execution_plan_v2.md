# P5：单浏览器（Chrome）完整自动化工作流 — 执行规划方案 v2

**起始日期**: 2026-04-08  
**前置条件**: P4 ✅（718/718 五元组 100% 命中，Wireshark 解密验证通过）  
**预计周期**: 1.5–2 周  
**目标**: 将 watchdog_v13.py + fd_tracker 整合为单命令 CLI 工具，配置化 RVA，为多版本/多浏览器扩展奠基

---

## 一、P4 成果基线

| 指标 | 结果 |
|------|------|
| 密钥捕获 | 718 条 (HKDF=701, PRF=17) |
| 五元组命中 | 718/718 = 100% |
| 关联方式 | 时序=159, 缓存=559, fd精确=0 |
| Wireshark 解密 | ✅ HTTP/HTTP2 明文可见 |
| fd 精确关联 | ❌ 不可用 (HKDF args[0] ≠ ssl_st*) |
| ssl_log_secret | 已定位 (RVA 0x04883520, BoringSecretHunter 输出) |
| 纯 eBPF 路径 | ❌ 失败 (rwxp页 + LTO优化 → uprobe/uretprobe 不触发) |
| Chrome 版本 | 143.0.7499.169 (Linux x86_64) |

---

## 二、P5 产出物定义

```
tls_capture/
├── tls_capture.py                  ← 单入口 CLI
├── ebpf/
│   ├── fd_tracker.bpf.c
│   ├── fd_tracker.c
│   ├── fd_tracker.h
│   ├── Makefile
│   └── fd_tracker                  ← 预编译二进制
├── hooks/
│   ├── chrome_hooks.js             ← Frida Hook 脚本 (RVA 参数化)
│   └── chrome_143.0.7499.169_linux_x86_64.json  ← 版本配置模板
├── lib/
│   ├── correlator.py               ← 时序关联引擎
│   ├── net_lookup.py               ← /proc/net/tcp 源地址反查
│   ├── version_detect.py           ← Chrome 版本检测 + 配置加载
│   └── output_writer.py            ← 输出格式化
├── tests/
│   └── test_e2e.sh                 ← 端到端自动测试
├── ARCHITECTURE.md                 ← 架构设计文档 (复用 P4 产出)
├── README.md
└── requirements.txt
```

---

## 三、关键设计决策

### 3.1 关于 fd 精确关联

**结论：P5 搁置，使用时序关联。**

P4 实验证明 HKDF 函数的 args[0] 是 HKDF 内部上下文对象而非 ssl_st*，因此 `ssl_st + 0x240 → rbio → 0x03c → fd` 路径在 HKDF Hook 中不可用。要实现 fd 精确关联需要 Hook HKDF 的调用者（如 FUN_049836b0），这会引入版本脆弱性。

时序关联在 P4 中已证明 100% 命中率（718/718），作为 P5 的默认策略完全可靠。后续如果需要提升到 fd 精确，可以通过 Hook ssl_log_secret（其 args[0] 可能是真正的 ssl_st*）来实现。

### 3.2 关于 ssl_log_secret 集成

**结论：P5 中作为可选增强。**

BoringSecretHunter 已输出 ssl_log_secret 的 RVA (0x04883520) 和字节指纹。P5 将其纳入配置文件但标记为 optional——CLI 工具检测到配置中有此字段时自动启用，没有则退化为当前行为。这为 P6 多浏览器扩展保留灵活性（Firefox/NSS 没有此函数）。

### 3.3 关于 BoringSecretHunter 集成

**结论：P5 不集成自动分析流程，仅使用其输出。**

BoringSecretHunter 需要 Docker + Ghidra 环境，运行一次 Chrome 分析需要约 20 小时。P5 的版本配置文件由人工运行 BoringSecretHunter 后填入结果。自动化分析流水线留给 P8。

---

## 四、任务详细规划

### Week 1：核心重构

#### T5.1：项目结构重构 (1d)

从 watchdog_v13.py 拆分为模块化结构：

| watchdog_v13 代码段 | 目标模块 |
|---|---|
| `connect_events` + `find_connect_by_*` + `parse_fd_tracker_output` | `lib/correlator.py` |
| `lookup_src` | `lib/net_lookup.py` |
| `HOOK_JS` 字符串 | `hooks/chrome_hooks.js` |
| RVA 硬编码值 | `hooks/*.json` |
| `on_message` + `attach_pid` + `cleanup` | `tls_capture.py` |

验收：各模块可独立 import，`python3 -c "from lib.correlator import Correlator"` 无报错。

#### T5.2：Hook 脚本参数化 (1d)

将 chrome_hooks.js 中所有硬编码 RVA 替换为配置变量：

```javascript
// 改前：
Interceptor.attach(mod.base.add(ptr('0x0A22D4B0')), { ... });
// 改后：
Interceptor.attach(mod.base.add(ptr(CFG.hook_points.prf.rva)), { ... });
```

Python 侧在 `create_script()` 前用 `template.replace('%HOOK_CONFIG%', json.dumps(config))` 注入配置。

同样参数化的项包括：client_random 路径中的偏移量、key_len_offsets、label_map。

验收：修改 JSON 中的 RVA 值后重新运行，Hook 点地址随之变化。

#### T5.3：版本检测 + 配置加载 (1d)

```python
# lib/version_detect.py 核心逻辑
def detect_chrome_version(binary_path):
    # 1. google-chrome --version
    # 2. strings binary | grep 版本号模式
    # 3. Last Version 文件
    # 4. /proc/PID/cmdline 中的 --product-version

def load_config(version, config_dir='hooks/'):
    # 1. 精确匹配: chrome_143.0.7499.169_linux_x86_64.json
    # 2. 大版本匹配: chrome_143.0_linux_x86_64.json
    # 3. 未找到 → 报错并提示运行 BoringSecretHunter
```

验收：`detect_chrome_version()` 输出 `143.0.7499.169`，`load_config()` 加载对应 JSON。

#### T5.4：输出格式规范化 (0.5d)

```python
# lib/output_writer.py
class OutputWriter:
    def write_key(self, label, cr_hex, secret_hex, tuple_info=None)
    def export_wireshark(self, path)   # 去掉 # 注释行
    def write_summary(self)             # 退出时统计
```

五元组注释格式：`# five_tuple=tcp:192.168.1.5:54321->142.250.80.46:443 pid=12345`

Wireshark 导出文件不含任何 `#` 行，可直接导入。

#### T5.5：CLI 主入口 (1d)

```bash
# 核心用法
sudo python3 tls_capture.py --auto                    # 自动检测+spawn
sudo python3 tls_capture.py --pid 12345               # attach 指定进程
sudo python3 tls_capture.py --auto --no-tuple          # 仅密钥，不启动 eBPF
sudo python3 tls_capture.py --auto -o keys.log --wireshark-export ws.log
```

CLI 内部自动管理 fd_tracker 子进程生命周期，Ctrl+C 时清理。

---

### Week 2：测试 + 文档 + 打磨

#### T5.6：进程生命周期管理 (0.5d)

| 场景 | 处理 |
|---|---|
| Chrome 崩溃 | on_detach 回调 → 日志提示 → 等待重启 |
| fd_tracker 异常退出 | 检测退出码 → 重启或降级为无五元组 |
| Ctrl+C | 信号处理 → detach + 终止子进程 + 输出统计 |
| 未知 Chrome 版本 | 明确报错 + 提示运行分析工具 |

#### T5.7：端到端测试 (1d)

test_e2e.sh 自动化验证流程：
1. 清理环境
2. 启动 Chrome (SSLKEYLOGFILE)
3. 启动 tls_capture.py (30s 超时)
4. diff 验证：无 `<` 行 (零误报)
5. 五元组命中率 ≥ 95%
6. Wireshark 导出文件无注释行
7. 输出 PASS/FAIL

#### T5.8：README + ARCHITECTURE 文档 (0.5d)

覆盖：安装依赖、编译 eBPF、运行方式、输出格式说明、已知限制、新版本适配指南。

---

## 五、任务时间线

```
Week 1:
  Mon: T5.1 (项目结构重构)
  Tue: T5.2 (Hook 脚本参数化)
  Wed: T5.3 (版本检测 + 配置加载)
  Thu: T5.4 (输出格式) + T5.5 (CLI 主入口)
  Fri: T5.5 续 + T5.6 (生命周期管理)

Week 2:
  Mon-Tue: T5.7 (E2E 测试 + Bug 修复)
  Wed: T5.8 (文档)
  Thu-Fri: Buffer / P6 准备
```

---

## 六、验收标准

| # | 标准 | 验证方式 |
|---|------|---------|
| 1 | 单命令启动 | `sudo tls_capture.py --auto` 完成全部工作 |
| 2 | 版本自动检测 | 终端输出 `Chrome 143.0.7499.169` |
| 3 | 配置驱动 | 修改 JSON 中 RVA 后 Hook 地址随之变化 |
| 4 | 密钥正确 | diff 无 `<` 行 |
| 5 | 五元组 ≥ 95% | 退出统计 |
| 6 | Wireshark 兼容 | `--wireshark-export` 文件可直接导入解密 |
| 7 | fd_tracker 自动管理 | 无需单独启动，Ctrl+C 无孤儿进程 |
| 8 | 未知版本明确报错 | 删除 JSON 条目后提示 "版本未支持" |
| 9 | E2E 测试通过 | `test_e2e.sh` 输出 "全部通过" |

---

## 七、版本配置模板说明

P5 产出的 `chrome_143.0.7499.169_linux_x86_64.json` 是项目的第一条完整数据库记录，包含：

- **hook_points**: PRF / HKDF / key_expansion / ssl_log_secret 的 RVA 和字节指纹
- **client_random**: 三级解引用路径及偏移量
- **tls13_key_len_offsets**: 各 label 对应的密钥长度字节偏移
- **struct_offsets**: ssl_st / bio_st 结构体偏移（含 fd 精确关联的已知限制）
- **five_tuple_strategy**: 时序关联配置

后续新增版本只需运行 TLSKeyHunter + BoringSecretHunter → 填入新 JSON → 工具自动适配。

---

## 八、P4 遗留问题处理

| 遗留 | P5 处理 | 理由 |
|------|---------|------|
| fd 精确关联 | **搁置** | 时序 100% 命中，HKDF args[0]≠ssl_st* |
| ssl_log_secret | **配置中标记 optional** | RVA 已有，待集成；非通用函数 |
| Session Ticket 漏捕 (~4%) | **记录到 README** | 需 ssl_log_secret，P6 处理 |
| attach 时序窗口 | **支持 spawn 模式** | CLI --auto 默认 spawn |
| QUIC/UDP | **记录到 README** | 建议 --disable-quic |
| TLS 1.2 覆盖不足 | **记录到 README** | 现代站点 99% TLS 1.3 |

---

## 九、与 P6 衔接

| P5 组件 | P6 扩展方式 |
|---------|-----------|
| `hooks/*.json` | 新增 Firefox / Edge 版本条目 |
| `chrome_hooks.js` | 新增 `firefox_hooks.js` (NSS 库 Hook) |
| `version_detect.py` | 增加 `detect_firefox_version()` |
| `tls_capture.py --auto` | 自动识别浏览器类型 → 加载对应 Hook |
| `fd_tracker.bpf.c` | 无需修改 (按 port 443 过滤，浏览器无关) |
| `correlator.py` | 无需修改 (时序关联与浏览器无关) |
