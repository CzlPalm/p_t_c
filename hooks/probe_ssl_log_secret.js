'use strict';
/**
 * probe_ssl_log_secret.js
 *
 * 目标：
 *   在 ssl_log_secret 触发时，优先从 args[0]（已知更接近真正 ssl_st*）的
 *   L1/L2 路径中定位 client_random，必要时再看 L3。
 *
 * 设计原则：
 *   1. 先看 L1（直接偏移）
 *   2. 再看 L2（一级解引用）
 *   3. L3 默认关闭，避免日志过大
 *   4. 过滤掉 0x00 / 0xcc 填充、低熵块，减少假阳性
 */

const CHROME_MODULE = 'chrome';
const SSL_LOG_SECRET_RVA = ptr('0x04883520');
const RBIO_OFFSET = 0x240;
const BIO_NUM_OFFSET = 0x03c;

const MAX_HITS = 10;
const ENABLE_L3 = false;

const L1_SCAN_SIZE = 0x300;
const L2_SCAN_SIZE = 0x100;
const L3_SCAN_SIZE = 0x40;

const L1_STEP = 0x10;
const L2_STEP = 0x10;

const PTR_OFFSETS_L2 = [
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
    0x240, 0x248
];
const PTR_OFFSETS_L3 = [0x00, 0x08, 0x10, 0x30, 0x240];
const SUB_OFFSETS_L3 = [0x00, 0x10, 0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60];

let hitCount = 0;

function toHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function safeUtf8(p) {
    try {
        if (!p || ptr(p).isNull()) return '?';
        return ptr(p).readUtf8String() || '?';
    } catch (_) {
        return '?';
    }
}

function isReadable(addr, size) {
    try {
        const base = ptr(addr);
        const range = Process.findRangeByAddress(base);
        if (!range) return false;
        if (range.protection.indexOf('r') === -1) return false;
        return base.add(size).compare(range.base.add(range.size)) <= 0;
    } catch (_) {
        return false;
    }
}

function safeReadPointer(addr) {
    try {
        const p = ptr(addr);
        if (!isReadable(p, Process.pointerSize)) return null;
        const v = p.readPointer();
        if (v.isNull()) return null;
        if (v.compare(ptr('0x1000')) < 0) return null;
        if (!isReadable(v, 1)) return null;
        return v;
    } catch (_) {
        return null;
    }
}

function safeReadBytes(addr, size) {
    try {
        const p = ptr(addr);
        if (!isReadable(p, size)) return null;
        const data = p.readByteArray(size);
        return data ? new Uint8Array(data) : null;
    } catch (_) {
        return null;
    }
}

function freqStats(arr) {
    const freq = new Map();
    let maxCount = 0;
    for (const b of arr) {
        const c = (freq.get(b) || 0) + 1;
        freq.set(b, c);
        if (c > maxCount) maxCount = c;
    }
    return { unique: freq.size, maxCount };
}

function looksLikeClientRandom32(arr) {
    if (!arr || arr.length !== 32) return false;

    const { unique, maxCount } = freqStats(arr);
    if (unique < 20) return false;
    if (maxCount > 4) return false;

    let ccCount = 0;
    let zeroCount = 0;
    for (const b of arr) {
        if (b === 0xcc) ccCount++;
        if (b === 0x00) zeroCount++;
    }
    if (ccCount >= 4) return false;
    if (zeroCount >= 4) return false;

    return true;
}

function readFd(ssl) {
    try {
        const rbio = ssl.add(RBIO_OFFSET).readPointer();
        if (rbio.isNull()) return -1;
        const fd = rbio.add(BIO_NUM_OFFSET).readS32();
        return (fd >= 3 && fd <= 65535) ? fd : -1;
    } catch (_) {
        return -1;
    }
}

function collectL1Candidates(ssl) {
    const out = [];
    const u8 = safeReadBytes(ssl, L1_SCAN_SIZE);
    if (!u8) return out;

    for (let off = 0; off <= L1_SCAN_SIZE - 32; off += L1_STEP) {
        const slice = u8.slice(off, off + 32);
        if (!looksLikeClientRandom32(slice)) continue;
        out.push({ off, hex32: toHex(slice) });
    }
    return out;
}

function collectL2Candidates(ssl) {
    const out = [];
    for (const pOff of PTR_OFFSETS_L2) {
        const p = safeReadPointer(ssl.add(pOff));
        if (!p) continue;

        const u8 = safeReadBytes(p, L2_SCAN_SIZE);
        if (!u8) continue;

        for (let off = 0; off <= L2_SCAN_SIZE - 32; off += L2_STEP) {
            const slice = u8.slice(off, off + 32);
            if (!looksLikeClientRandom32(slice)) continue;
            out.push({ pOff, off, hex32: toHex(slice) });
        }
    }
    return out;
}

function collectL3Candidates(ssl) {
    const out = [];
    for (const pOff of PTR_OFFSETS_L3) {
        const p1 = safeReadPointer(ssl.add(pOff));
        if (!p1) continue;

        for (const subOff of SUB_OFFSETS_L3) {
            const p2 = safeReadPointer(p1.add(subOff));
            if (!p2) continue;

            const u8 = safeReadBytes(p2, L3_SCAN_SIZE);
            if (!u8) continue;

            const head32 = u8.slice(0, 32);
            if (!looksLikeClientRandom32(head32)) continue;
            out.push({ pOff, subOff, hex32: toHex(head32) });
        }
    }
    return out;
}

function logCandidates(title, rows, formatter) {
    console.log(title);
    if (rows.length === 0) {
        console.log('  (无候选)');
        return;
    }
    for (const row of rows) {
        console.log('  ' + formatter(row));
    }
}

const mod = Process.getModuleByName(CHROME_MODULE);
const hookAddr = mod.base.add(SSL_LOG_SECRET_RVA);

Interceptor.attach(hookAddr, {
    onEnter(args) {
        if (hitCount >= MAX_HITS) return;
        hitCount += 1;

        const ssl = args[0];
        const label = safeUtf8(args[1]);
        let secretLen = -1;
        try {
            secretLen = args[3].toInt32();
        } catch (_) {}

        const fd = readFd(ssl);
        console.log(`\n=== ssl_log_secret #${hitCount} label="${label}" len=${secretLen} fd=${fd} ssl=${ssl} ===`);
        console.log('[*] 匹配顺序建议：先对照 L1，再看 L2；只有前两层都没有时才考虑 L3');

        const l1 = collectL1Candidates(ssl);
        logCandidates('[L1] ssl_st 直接偏移中的 32B 候选：', l1,
            row => `+0x${row.off.toString(16).padStart(3, '0')}: ${row.hex32}`);

        const l2 = collectL2Candidates(ssl);
        logCandidates('[L2] *(ssl+offset) 一级解引用中的 32B 候选：', l2,
            row => `*(ssl+0x${row.pOff.toString(16)})+0x${row.off.toString(16).padStart(3, '0')}: ${row.hex32}`);

        if (ENABLE_L3) {
            const l3 = collectL3Candidates(ssl);
            logCandidates('[L3] *(*(ssl+offset)+offset) 二级解引用中的 32B 候选：', l3,
                row => `*(*(ssl+0x${row.pOff.toString(16)})+0x${row.subOff.toString(16)})+0x000: ${row.hex32}`);
        } else {
            console.log('[L3] 已跳过（默认关闭，避免日志过大；仅当 L1/L2 无结果时再开启）');
        }
    }
});

console.log(`[*] probe ready: ${CHROME_MODULE}!${SSL_LOG_SECRET_RVA} => ${hookAddr}`);
console.log('[*] 建议流程：先用 SSLKEYLOGFILE 拿到一条 client_random，再优先在 L1/L2 输出中检索');
