/**
 * probe_fd.js — ssl_ptr → rbio → fd 完整诊断探针
 *
 * 目标：确认在 HKDF 调用时，ssl_ptr 的 0x240/0x03c 路径是否能读到有效 fd
 *
 * 注入方式：
 *   PID=$(pgrep -f "NetworkService.*chrome_p3_test" | head -1)
 *   frida -p $PID -l probe_fd.js --no-pause
 *
 * 访问一个 HTTPS 站点后观察输出，Ctrl+C 退出
 *
 * 输出解读：
 *   fd_rdi=N  ← args[0]（RDI寄存器）路径读到的 fd，应为 5~4095
 *   fd_r14=N  ← R14 寄存器路径（函数序言有时把 RDI 存入 R14）
 *   rbio=0x0  ← BIO 未绑定（时序问题，HKDF 调用时连接还没建立）
 *   fd=-1     ← BIO 存在但 0x03c 偏移不对
 */

'use strict';

const mod = Process.getModuleByName('chrome');
console.log('[*] chrome base:', mod.base, 'size:', (mod.size/1024/1024|0)+'MB');

// 已知 HTTPS 连接 fd 集合（从 /proc/PID/fd 读取）
// 用于交叉验证：如果读到的 fd 在这个集合里，说明偏移正确
const KNOWN_SOCKET_FDS = new Set();
try {
    const pid = Process.id;
    const fds = new File(`/proc/${pid}/fd`, 'r');
    // frida 没有 readdir，改用 /proc/pid/net/tcp 辅助判断
} catch(_) {}

// ── 尝试读取已知 socket fd（通过 frida 的 Process.enumerateRanges 侧信道）
// 改用最简单方式：固定几个常见范围
const REASONABLE_FD_RANGE = { min: 5, max: 4095 };

let hitCount = 0;
const MAX_HITS = 30;  // 最多打印 30 次，避免刷屏

// ── Hook 1：HKDF 入口（uprobe）─────────────────────────────────────────────
// 在 onEnter 保存 RDI (ssl_ptr)，在 onLeave 读取（函数执行完后 BIO 应已就绪）
Interceptor.attach(mod.base.add(ptr('0x048837E0')), {
    onEnter(args) {
        // args[0] = RDI = ssl_ptr（System V x86-64 调用约定第1个参数）
        this.ssl_from_rdi = args[0];

        // 同时保存 R14（部分版本 Chrome HKDF 的序言会 push r14; mov r14, rdi）
        try {
            this.ssl_from_r14 = this.context.r14;
        } catch(_) {
            this.ssl_from_r14 = null;
        }
    },

    onLeave(_retval) {
        if (hitCount >= MAX_HITS) return;
        hitCount++;

        const results = [];

        // ── 方案A：从 RDI（args[0]）路径读 fd
        const ssl_rdi = this.ssl_from_rdi;
        if (ssl_rdi && !ssl_rdi.isNull()) {
            results.push(...probe_ssl(ssl_rdi, 'RDI'));
        }

        // ── 方案B：从 R14 路径读 fd（onLeave 时 R14 可能被修改，仅供参考）
        const ssl_r14 = this.ssl_from_r14;
        if (ssl_r14 && !ssl_r14.isNull() &&
            ssl_r14.toString() !== ssl_rdi.toString()) {
            results.push(...probe_ssl(ssl_r14, 'R14'));
        }

        if (results.length > 0) {
            console.log('\n[HKDF #' + hitCount + ']');
            results.forEach(r => console.log('  ' + r));
        }
    }
});

/**
 * 对给定 ssl_ptr 尝试所有已知偏移组合，返回诊断行数组
 */
function probe_ssl(ssl, source) {
    const lines = [];

    // 候选 rbio 偏移（历次测试中出现过的值）
    const RBIO_OFFSETS = [0x240, 0x248, 0x0e0, 0x0f0, 0x2a0, 0x008];

    // 候选 bio.num 偏移（历次测试中出现过的值）
    const NUM_OFFSETS  = [0x03c, 0x020, 0x028, 0x004, 0x040, 0x0c8];

    for (const rbio_off of RBIO_OFFSETS) {
        let rbio = null;
        try {
            rbio = ssl.add(rbio_off).readPointer();
        } catch(_) { continue; }

        if (rbio.isNull()) {
            lines.push(`[${source}] ssl+0x${rbio_off.toString(16).padStart(3,'0')} → rbio=NULL`);
            continue;
        }

        // 检查 rbio 地址是否合理（用户态地址范围）
        const rbio_val = rbio.compare(ptr('0x100000'));
        if (rbio_val < 0) {
            lines.push(`[${source}] ssl+0x${rbio_off.toString(16).padStart(3,'0')} → rbio=0x${rbio} (太小，非指针)`);
            continue;
        }

        // 尝试读 bio.num
        for (const num_off of NUM_OFFSETS) {
            try {
                const fd = rbio.add(num_off).readS32();
                if (fd >= REASONABLE_FD_RANGE.min &&
                    fd <= REASONABLE_FD_RANGE.max) {
                    lines.push(
                        `✓ [${source}] ssl+0x${rbio_off.toString(16).padStart(3,'0')}` +
                        ` → rbio=${rbio}` +
                        ` → +0x${num_off.toString(16).padStart(3,'0')}` +
                        ` → fd=${fd}  ← 候选!`
                    );
                }
            } catch(_) {}
        }
    }

    // 如果没有找到任何候选，打印 0x240 的诊断信息
    if (lines.length === 0) {
        try {
            const rbio_240 = ssl.add(0x240).readPointer();
            const rbio_248 = ssl.add(0x248).readPointer();
            let fd_240_03c = '?', fd_248_03c = '?';
            try { fd_240_03c = rbio_240.add(0x03c).readS32(); } catch(_) {}
            try { fd_248_03c = rbio_248.add(0x03c).readS32(); } catch(_) {}
            lines.push(
                `[${source}] ssl=${ssl}` +
                ` rbio@0x240=${rbio_240}(fd=${fd_240_03c})` +
                ` wbio@0x248=${rbio_248}(fd=${fd_248_03c})`
            );
        } catch(e) {
            lines.push(`[${source}] ssl=${ssl} 读取失败: ${e}`);
        }
    }

    return lines;
}

// ── Hook 2：ssl_log_secret（覆盖 PSK 路径，对比 RDI 值）─────────────────
// 这个 hook 能成功触发就同时打印 fd，帮助确认两个 hook 的 ssl_ptr 是否一致
let ssl_log_count = 0;
try {
    Interceptor.attach(mod.base.add(ptr('0x04883520')), {
        onEnter(args) {
            if (ssl_log_count++ >= 5) return;
            const ssl = args[0];
            try {
                const rbio = ssl.add(0x240).readPointer();
                const fd = rbio.isNull() ? -1 : rbio.add(0x03c).readS32();
                console.log(`\n[ssl_log_secret] ssl=${ssl} rbio=${rbio} fd=${fd}`);
            } catch(e) {
                console.log(`\n[ssl_log_secret] ssl=${ssl} err=${e}`);
            }
        }
    });
    console.log('[*] ssl_log_secret hook OK @ 0x04883520');
} catch(e) {
    console.log('[!] ssl_log_secret hook 失败:', e);
}

console.log('[*] HKDF hook OK @ 0x048837E0');
console.log('[*] 请在 Chrome 访问 HTTPS 站点，观察输出...');
console.log('[*] 最多打印', MAX_HITS, '次 HKDF 事件\n');
