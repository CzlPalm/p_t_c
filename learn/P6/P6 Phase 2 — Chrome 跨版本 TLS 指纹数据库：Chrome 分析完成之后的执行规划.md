## Context

**为什么做**： P6 Phase 1 已完成单版本 Chrome 143 的完整 TLS 密钥捕获链路（覆盖率 98.3%，已归档 10+ 条结构性 limitation）。Phase 2 的目标是把"Chrome 143 单点可用"扩展为"多版本 Chrome 自动适配"的指纹/RVA 数据库，即：给定任意 Chrome 二进制，能够在 10 分钟内产出可直接加载的 `hooks/chrome_<ver>_linux_x86_64.json`，让 Frida hook 层零改动运行。

**现在卡在哪**：

- TSHunter (`run_chrome_analysis.sh`) 对 Chrome 143 的 PRF 识别因 `"master secret"` 是 `"extended master secret"` 子串而失败；TSHunter Phase 2 已通过 `.rodata` 字节扫描 + 3 级策略修复，正在实际跑 Chrome 143 验证。
- 跑完后需要一个清晰的"合并 → 批量 → 回归"流水线。原 P6 计划里标注为 missing 的 3 个工具 (`merge_analysis.py` / `fingerprint_scan.py` / `FindPRF.java`)，经分析只需要前 2 个，`FindPRF.java` 被 TSHunter Phase 2 覆盖可删除。
- 人工字段（`tls13_key_len_offsets`、`struct_offsets`、`tls13_label_map`、`client_random.path`）在跨版本时是否还稳定、是否必须自动化，需要明确结论。

**预期结果**：

1. TSHunter 输出 `143_auto.json`，与 `hooks/chrome_143.0.7499.169_linux_x86_64.json` 的 4 个 RVA 完全一致。
2. 存在 `tools/merge_analysis.py` + `tools/fingerprint_scan.py` 两个工具，前者把 TSHunter 自动字段与 baseline 人工字段合并成完整 JSON，后者在无 Ghidra 的版本上用字节指纹从 baseline 迁移 RVA。
3. 跑完 3~5 个 Chrome 版本后 `hooks/chrome_*.json` 入库 git，`version_detect.py` 能自动选中。
4. `tls_capture.py` 对至少 3 个历史版本能产出与 `SSLKEYLOGFILE` ≥95% 一致的 keylog。

---

## 关键认知（基于 Phase 1 代码审阅）

1. **只有 4 个字段是真正 runtime-critical**（`chrome_hooks.js` 运行时真实读取）：
    - `hook_points.{prf,hkdf,key_expansion,ssl_log_secret}.rva`
    - `tls13_label_map`（TLS 1.3 RFC 固定，5 个标签，跨版本静态）
    - `tls13_key_len_offsets`（6 个相对偏移，位于 HKDF caller 的立即数里）
    - `struct_offsets.{ssl_st_rbio, bio_st_num}`（SSL 结构体 rbio + BIO 结构体 fd 字段）
2. **看起来是人工字段、实际上是文档字段**（`chrome_hooks.js` 从未从 JSON 读取）：
    - `client_random.path`：JS 的 `readCR()` / `readCRSslLog()` 把 `*(*(ssl)+0x30)+0x30` 和 `*(ssl+0x30)+0x30` 硬编码了；JSON 里的路径只是给人看的。
    - `hook_points.*.params`：纯描述，运行时靠 `args[0]`/`args[1]` 顺序。
3. **TSHunter 产出 4 项自动字段后还差什么**：
    - 缺 `tls13_key_len_offsets` / `struct_offsets` → 用户决定**手工从 143 baseline 一次性提取 + 运行期自检兜底**（不扩 TSHunter）。
    - 缺 `tls13_label_map` → 直接从 baseline 复制常量，跨版本不变。
    - 缺 `client_random.path` → 文档字段，保持 baseline 值即可。
4. **`FindPRF.java` 不需要写**：TSHunter Phase 2 的 `.rodata` 字节扫描 + `isStandaloneString()` + 3 级策略已经覆盖 PRF 子串问题。

---

## 实施步骤

### Phase A：验证 TSHunter Chrome 143 结果（阻塞后续）

1. 等 `run_chrome_analysis.sh` 跑完，拿到 `143_auto.json`（或 TSHunter 约定的输出路径）。
2. 对比 `hooks/chrome_143.0.7499.169_linux_x86_64.json` 的 4 个 RVA：
    - `prf.rva` / `hkdf.rva` / `key_expansion.rva` / `ssl_log_secret.rva`
    - 确认 TSHunter 是否已经减掉 `imageBase = 0x00100000`；如果没有就在 merge 工具里统一转换。
3. 4 条 fingerprint 用 Python 做一次 `.text` 字节比对，确认每条 fingerprint 仅命中对应函数起始字节序列 1 次。
4. **Go/No-Go 门控**：4 个 RVA 都一致才进入 Phase B；否则回到 TSHunter 调整策略。

### Phase B：实现 `tools/merge_analysis.py`（TSHunter 自动字段 + baseline 人工字段 → 完整 JSON）

文件：`/home/user/p_t_c/tools/merge_analysis.py`

输入：

- `--auto` TSHunter 输出 JSON（含 `meta` + `hook_points.{type}.{rva,fingerprint}`）
- `--baseline hooks/chrome_143.0.7499.169_linux_x86_64.json`（提供人工字段）
- `--version`、`--chrome-binary` 元信息

输出：`hooks/chrome_<version>_linux_x86_64.json`，合并规则：

- RVA、fingerprint：取 auto 的值。
- `tls13_label_map`、`tls13_key_len_offsets`、`struct_offsets`、`client_random.path`、`hook_points.*.params`：原样拷 baseline。
- `meta.source`: `"TSHunter+baseline143"`；`meta.generated_at`: 时间戳；`meta.chrome_version` / `sha256` 从 `artifacts/chrome/<ver>/metadata.json` 读。
- 若 TSHunter RVA 含 `0x00100000` 基址，统一减掉；否则按原值写入。

校验：写入前跑一次 schema check（字段齐全、RVA 形如 `0x[0-9a-f]+`、fingerprint 是 hex 字符串）。

### Phase C：实现 `tools/fingerprint_scan.py`（无 Ghidra 场景下用字节指纹定位 RVA）

文件：`/home/user/p_t_c/tools/fingerprint_scan.py`

用途：当某个 Chrome 版本没跑 TSHunter（或 TSHunter 跑挂），用 baseline 143 的 4 条 fingerprint 在新二进制的 `.text` 段 Boyer-Moore 扫描，把命中地址作为 RVA 写回。

接口：

- `scan_binary(binary_path, fingerprints: dict[str, bytes]) -> dict[str, int]`
- CLI：`python tools/fingerprint_scan.py --binary artifacts/chrome/<ver>/chrome --baseline hooks/chrome_143.0.7499.169_linux_x86_64.json --out hooks/chrome_<ver>_linux_x86_64.json`

实现点：

- 用 `pyelftools` 取 `.text` 段 `sh_addr` + 段数据。
- 每条 fingerprint 要求**命中恰好一次**；命中 0 次 → fail，命中 >1 次 → 收紧 fingerprint 长度或 fail。
- RVA = 命中偏移 + `sh_addr - imageBase`。
- 允许与 merge 工具复用，先跑 TSHunter，若某函数未返回 fingerprint 则由 fingerprint_scan 兜底。

### Phase D：批量流水线 `tools/run_batch.sh`（串起来）

文件：`/home/user/p_t_c/tools/run_batch.sh`（新增，简单 shell）

流程：

1. `python tools/chrome_downloader.py --version <v>` → `artifacts/chrome/<v>/chrome` + `metadata.json`
2. 容器化跑 TSHunter（沿用 `integrated/scripts/run_chrome_analysis.sh`，传入二进制路径），产出 auto JSON
3. `python tools/merge_analysis.py --auto ... --baseline ... --version <v>` → `hooks/chrome_<v>_linux_x86_64.json`
4. 失败回退：跑 `python tools/fingerprint_scan.py` 直接从 baseline 迁移
5. `git add hooks/chrome_<v>_linux_x86_64.json`（入库策略由用户确认为"提交到 git"）

输入：版本列表 `configs/chrome_versions.txt`（Phase 2 步骤 1 的产物），目标 3~5 个主版本 + 差距版本。

### Phase E：运行期自检（兜底手工 struct_offsets）

文件：`/home/user/p_t_c/hooks/chrome_hooks.js`（最小改动）

在 `readCR()` / `readCRSslLog()` 成功解引用后加一行轻量检查：

- 读出的 32B `client_random` 若全 0 或明显重复模式（如 `00 00 ...` / `ff ff ...`）→ `console.warn("[self-check] client_random looks degenerate, struct_offsets may be stale")`
- 仅日志告警，不 abort，避免误杀；用作"版本跳变导致 `struct_offsets` 失配"的人肉信号。

无 baseline 字段变更，向后兼容。

### Phase F：跨版本回归验证

对至少 3 个版本（如 Chrome 130 / 137 / 143）：

1. 跑 `tls_capture.py --chrome-bin artifacts/chrome/<v>/chrome` 捕获 keylog。
2. 同步用 `SSLKEYLOGFILE=...` 直接让 Chrome 自己写出对照。
3. `diff` 行数计数，覆盖率 ≥95% 视为通过。
4. 若覆盖率骤降 → 优先检查 `tls13_key_len_offsets` / `struct_offsets` 是否需要按版本重测；结果记入 `learn/P6/T6.2_第二阶段测试文档.md` 的回归章节。

---

## 关键文件（只读 / 要改）

只读参考：

- `learn/P1/浏览器密钥捕获数据库方案可行性评估_2026-03 (1).md`（架构与数据流）
- `learn/P6/P6_execution_plan_v2.md`、`learn/P6/P6_Phase2_execution_steps.md`、`learn/P6/T6.2_第二阶段测试文档.md`
- `hooks/chrome_143.0.7499.169_linux_x86_64.json`（baseline，字段基准）
- `hooks/chrome_hooks.js`（确认 `readCR()` L86-95 / `readCRSslLog()` L101-109 硬编码路径不读 JSON）
- `lib/version_detect.py`（选版逻辑）
- `tools/chrome_downloader.py`（下载器已存在可用）
- TSHunter `integrated/scripts/TLShunterAnalyzer.java` + `run.py`（理解自动字段输出格式）

要新增：

- `tools/merge_analysis.py`（Phase B）
- `tools/fingerprint_scan.py`（Phase C）
- `tools/run_batch.sh`（Phase D，可选但推荐）
- `configs/chrome_versions.txt`（Phase D 目标版本列表）

要小改：

- `hooks/chrome_hooks.js`（Phase E，加 2~4 行自检日志）
- 批量生成的 `hooks/chrome_<ver>_linux_x86_64.json`（提交到 git）
- `learn/P6/T6.2_第二阶段测试文档.md`（Phase F 追加回归结果）

**显式不做**：

- `tools/FindPRF.java`（TSHunter Phase 2 已覆盖，不再写）
- TSHunter 扩 `tls13_key_len_offsets` / `struct_offsets` 自动提取（用户决定走手工 + 运行期自检路线）

---

## 验证方式

1. **Phase A 验证**：`diff <(jq -S . 143_auto.json) <(jq -S .hook_points hooks/chrome_143.0.7499.169_linux_x86_64.json)` 4 个 RVA 字段一致。
2. **Phase B 验证**：`python tools/merge_analysis.py --auto 143_auto.json --baseline hooks/chrome_143.0.7499.169_linux_x86_64.json --version 143.0.7499.169 --out /tmp/merged.json && diff /tmp/merged.json hooks/chrome_143.0.7499.169_linux_x86_64.json`（去掉 `meta.generated_at` 后应完全一致）。
3. **Phase C 验证**：对 143 二进制跑 `fingerprint_scan.py`，输出的 4 个 RVA 等于 baseline。
4. **Phase D/F 验证**：对每个新版本运行 `tls_capture.py`，比对 `SSLKEYLOGFILE` diff 覆盖率 ≥95%；`version_detect.py` 能选中新 JSON。
5. **运行期自检**：故意把 `struct_offsets.ssl_st_rbio` 改错一次，确认 Phase E 告警日志触发。