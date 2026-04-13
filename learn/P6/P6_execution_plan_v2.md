# P6 执行规划方案（修订版）

**阶段**: P6 — ssl_log_secret 集成 + Chrome 多版本指纹数据库构建  
**起始日期**: 2026-04-11  
**预计周期**: 3-4 周  
**前置条件**: P5 ✅（单浏览器自动化工具完成，419/419 五元组命中）

---

## 一、P6 在整个项目中的定位

### 原始九阶段规划 vs 实际执行对照

| 原计划 | 实际执行 | 说明 |
|--------|---------|------|
| P1 逆向分析 | ✅ P1 完成 | PRF/HKDF/key_expansion 全量 Hook 点 |
| P2 TLSKeyHunter 验证 | ✅ P2 完成 | HKDF 一致，PRF 失败（已知限制）|
| P3 Frida 密钥捕获 | ✅ P3 完成 | client_random +0x30 修正，96% 捕获率 |
| P4 eBPF + 五元组 | ✅ P4 完成 | 混合架构，时序关联 100% |
| P5 自动化工作流 | ✅ P5 完成 | 模块化 CLI，配置驱动 |
| **P6 多浏览器适配** | **→ 推迟到 P8** | 先做 Chrome 深度覆盖 |
| **P7 版本爬取** | **→ 合并到 P6** | 与数据库构建一起做 |
| **P8 自动化分析+数据库** | **→ 合并到 P6** | P6 = 原 P7 + P8 |
| P9 GUI | 保持 | 最后做 |

### P6 的核心定位

P6 = **从"单版本可用"到"多版本可复制"的跨越**

这是整个项目从工程工具变为**可发表研究成果**的关键阶段。论文/项目的核心贡献不是"能抓一个版本的密钥"（friTap 已经能做到），而是"通过指纹数据库实现版本无关的自动化密钥捕获+五元组关联"。

---

## 二、P6 三个阶段（串行执行，非并行）

```
Phase 1 (Week 1):     ssl_log_secret 集成 → 消除已知漏捕
Phase 2 (Week 2):     多版本二进制采集 → 建立样本池
Phase 3 (Week 3-4):   批量分析 + 数据库构建 → 产出评估数据
```

为什么串行而非并行：每个阶段的输出是下一个阶段的输入。

---

## 三、Phase 1：ssl_log_secret 集成（Week 1）

### 目标
消除 P5 遗留的 79 条 TLS 1.2 漏捕，验证 ssl_log_secret 的参数布局。

### T6.1：ssl_log_secret 参数探针验证（1d）

编写轻量探针脚本，attach 到 Chrome，在 ssl_log_secret 触发时打印 args[0]~args[3]：

```javascript
// probe_ssl_log_secret.js
Interceptor.attach(mod.base.add(ptr('0x04883520')), {
    onEnter(args) {
        // 预期: args[0]=ssl_st*, args[1]=label, args[2]=secret, args[3]=secret_len
        const ssl = args[0];
        let label = '?', secret_len = 0;
        try { label = args[1].readUtf8String(); } catch(_) {}
        try { secret_len = args[3].toInt32(); } catch(_) {}
        
        // 验证 args[0] 是否是真正的 ssl_st*
        let fd = -1;
        try {
            const rbio = ssl.add(0x240).readPointer();
            fd = rbio.isNull() ? -1 : rbio.add(0x03c).readS32();
        } catch(_) {}
        
        console.log(`[ssl_log_secret] label="${label}" len=${secret_len} fd=${fd}`);
    }
});
```

**验收**：确认参数顺序，确认 args[0] 能读到有效 fd（> 0）。

### T6.2：ssl_log_secret Hook 集成到 chrome_hooks.js（1d）

在 chrome_hooks.js 中增加第四个 Hook 点：
- 读取 label + secret + client_random
- 用现有 `_emitted` 集合去重（label|client_random 作为 key）
- 如果 args[0] 确实是 ssl_st*，同时读取 fd

### T6.3：覆盖率验证（0.5d）

运行完整测试，与 SSLKEYLOGFILE 对比：
- P5 基线：419/498 = 84%
- P6 目标：接近 498/498 = 100%
- 重点关注：79 条 CLIENT_RANDOM 是否被补足

### T6.4：更新 JSON 模板（0.5d）

在 chrome_143.0.7499.169_linux_x86_64.json 中：
- ssl_log_secret 状态从 "located_not_integrated" 改为 "integrated_verified"
- 新增 ssl_log_secret 的参数布局字段
- 如果 fd 精确关联恢复，更新 five_tuple_strategy

**Phase 1 验收**：diff 对比 CLIENT_RANDOM 漏捕数 < 5（从 79 降到接近 0）。

---

## 四、Phase 2：Chrome 多版本二进制采集（Week 2）

### T6.5：Chrome 历史版本来源调研（1d）

确定 Linux Chrome 稳定版历史二进制的获取途径：

| 来源 | 覆盖范围 | 可靠性 |
|------|---------|--------|
| Google Chrome for Testing API | 近期版本（~6个月） | 高 |
| chromiumdash.appspot.com | 版本号索引 | 高 |
| apt.google.com 仓库快照 | 当前+近几个版本 | 高 |
| 第三方归档（slimjet/nicedoc） | 历史版本 | 中 |
| Internet Archive / web.archive.org | 部分历史 | 低 |

**产出**：版本来源说明文档 + 首批可下载版本清单（目标 8-15 个版本）。

### T6.6：版本采集脚本（1.5d）

```python
# tools/chrome_downloader.py
# 输入：版本列表文件
# 输出：artifacts/chrome/{version}/chrome + metadata.json
```

每个版本保存：二进制文件、SHA256、下载 URL、平台架构、获取时间。

**优先覆盖版本范围**（建议）：

```
# 近期稳定版（每个大版本选最新补丁）
135.x, 136.x, 137.x, 138.x, 139.x, 140.x, 141.x, 142.x, 143.x (当前)
# 如果来源允许，再补几个老版本
130.x, 125.x, 120.x
```

### T6.7：手动分析 2-3 个版本建立信心（1.5d）

在构建自动化流水线之前，先手动跑通 2-3 个不同版本：
- 对每个版本运行 TLSKeyHunter Docker + BoringSecretHunter Docker
- 手动检查 HKDF 指纹是否变化、RVA 偏移量变化幅度
- 记录 TLSKeyHunter PRF 识别是否继续失败

**这一步的意义**：验证"同大版本指纹复用"假设，为自动化流水线设计提供依据。

**Phase 2 验收**：本地有 8+ 个版本的二进制 + 2-3 个版本的手动分析结果。

---

## 五、Phase 3：批量分析 + 数据库构建（Week 3-4）

### T6.8：批处理流水线实现（2d）

```bash
# tools/batch_analyze.sh
# 对 artifacts/chrome/ 下的每个版本：
# 1. 运行 TLSKeyHunter Docker → 提取 HKDF 指纹/RVA
# 2. 运行 BoringSecretHunter Docker → 提取 ssl_log_secret 指纹/RVA
# 3. 合并结果 → 生成 hooks/chrome_{version}_linux_x86_64.json
```

注意事项：
- Ghidra headless 分析 Chrome 需要 ~20 小时/版本，需要排队或并行
- 中间产物缓存：已分析过的版本跳过
- PRF RVA 需要从 HKDF 结果 + 手动补充（TLSKeyHunter PRF 识别对 Chrome 失败）

### T6.9：PRF 识别补充方案（1d）

TLSKeyHunter 对 Chrome 的 PRF 识别失败（子串问题），需要补充方案：

**方案 A**：修改 TLSKeyHunter 源码，增加 .rodata 字节模式回退（参考 HKDF 识别路径）
**方案 B**：编写独立的 Ghidra 脚本，直接搜索 "master secret" 字符串的 XREF
**方案 C**：利用已知版本的 PRF 指纹做跨版本内存扫描

建议先尝试方案 B（最轻量），失败再做方案 A。

### T6.10：指纹稳定性评估（1d）

这是**论文/项目的核心评估数据**：

对所有已分析版本，生成对比表：

| 版本 | HKDF RVA | HKDF 指纹前32B | PRF RVA | ssl_log_secret RVA | 指纹变化？ |
|------|---------|---------------|---------|-------------------|-----------|
| 135.0.xxx | 0x04721E0 | 55 48 89 E5... | 0x09F2D4B0 | 0x04721520 | 基准 |
| 136.0.xxx | 0x04731E0 | 55 48 89 E5... | 0x09F3D4B0 | 0x04731520 | RVA变，指纹同 |
| 143.0.xxx | 0x048837E0 | 55 48 89 E5... | 0x0A22D4B0 | 0x04883520 | RVA变，指纹同 |

这张表能回答关键问题：
- 指纹在多少个版本间稳定？（论文的"指纹复用率"指标）
- RVA 变化幅度多大？（回退扫描的搜索范围依据）
- 哪些版本需要单独记录？

### T6.11：数据库产出 + 工具集成验证（1d）

- 所有版本 JSON 放入 `hooks/` 目录
- 修改 version_detect.py 支持从多个 JSON 中匹配
- 在 2-3 个不同版本的 Chrome 上实际运行 tls_capture.py，验证密钥捕获成功

**Phase 3 验收**：
- hooks/ 目录下有 8+ 个版本的 JSON 记录
- 指纹稳定性评估表完成
- 至少 2 个非当前版本的 Chrome 上验证通过

---

## 六、P6 验收标准汇总

| # | 标准 | 验证方式 |
|---|------|---------|
| 1 | ssl_log_secret 集成，TLS 1.2 漏捕 < 5 条 | diff 对比 |
| 2 | 本地有 8+ 个 Chrome 版本二进制 | ls artifacts/ |
| 3 | 每个版本有对应的 JSON 记录 | ls hooks/ |
| 4 | 至少 2 个非当前版本验证通过 | 运行 + diff |
| 5 | 指纹稳定性评估表完成 | 文档 |
| 6 | 批量分析流水线可重复执行 | 脚本运行 |

---

## 七、P6 之后的全局路线图

```
P6 (当前)     Chrome 深度覆盖：ssl_log_secret + 多版本数据库
    ↓
P7            版本回退：指纹内存扫描 + 未知版本自动适配
    ↓
P8            多浏览器扩展：Firefox (NSS) + Edge (BoringSSL 共享)
    ↓
P9            交付：GUI / 论文撰写 / 开源发布
```

### 论文/项目的核心贡献点（P6 需要为此铺垫）

1. **方法论贡献**：基于 TLS 标签字符串定位密钥派生函数的自动化框架（TLSKeyHunter baseline + 我们的扩展）
2. **工程贡献**：Frida+eBPF 混合架构实现密钥捕获+五元组关联（纯 eBPF 失败的原因分析也是贡献）
3. **数据贡献**：首个覆盖 Chrome N 个版本的 TLS 密钥派生函数指纹数据库
4. **评估贡献**：指纹跨版本稳定性分析 + 捕获率/关联率的量化评估

**P6 的指纹稳定性评估表（T6.10）直接对应贡献点 3 和 4**，这是论文最有价值的数据之一。

---

## 八、风险与应对

| 风险 | 影响 | 应对 |
|------|------|------|
| Chrome 历史版本获取困难 | 样本池不够大 | 先做能拿到的，apt 仓库 + Chrome for Testing |
| TLSKeyHunter/BSH 分析太慢 | 流水线耗时长 | 并行跑 Docker，分层缓存 |
| PRF 自动识别对所有版本都失败 | JSON 中 PRF 字段需手动补 | 用指纹扫描替代（已知版本的指纹搜新版本）|
| ssl_log_secret 参数布局在不同版本变化 | 集成不通用 | 用 BoringSecretHunter 逐版本确认 |
| 指纹在大版本间不稳定 | 回退扫描范围大 | 记录变化点，建立版本断裂表 |
