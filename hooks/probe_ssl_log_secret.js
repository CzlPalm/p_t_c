'use strict';

/*
 * T6.1: ssl_log_secret 参数探针验证脚本
 *
 * 目标：
 * 1. 验证 ssl_log_secret 的参数顺序
 * 2. 验证 args[0] 是否可作为 ssl_st* 使用
 * 3. 验证通过 rbio -> fd 路径是否能恢复有效 fd
 *
 * 使用方式：
 *   frida -p <PID> -l hooks/probe_ssl_log_secret.js
 *
 * 当前目标版本：Chrome 143.0.7499.169
 * ssl_log_secret RVA: 0x04883520
 * 指纹: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 48 48 8B 47 68 41 B4 01 48 83 B8 40 02 00 00 00 75 12
 */

const SSL_LOG_SECRET_RVA = ptr('0x04883520');
const RBIO_OFFSET = 0x240;
const BIO_NUM_OFFSET = 0x03c;

function hex(buf) {
    if (!buf) return null;
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

function ptrHex(v) {
    try {
        return ptr(v).toString();
    } catch (_) {
        return String(v);
    }
}

function safeUtf8(p, len = -1) {
    try {
        if (!p || ptr(p).isNull()) return null;
        return len > 0 ? ptr(p).readUtf8String(len) : ptr(p).readUtf8String();
    } catch (_) {
        return null;
    }
}

function tryReadFd(ssl) {
    try {
        const rbio = ssl.add(RBIO_OFFSET).readPointer();
        if (rbio.isNull()) {
            return { rbio: 'NULL', fd: -1, err: null };
        }
        const fd = rbio.add(BIO_NUM_OFFSET).readS32();
        return { rbio: ptrHex(rbio), fd, err: null };
    } catch (e) {
        return { rbio: 'ERR', fd: -1, err: String(e) };
    }
}

function tryReadCR(ssl) {
    try {
        const s3 = ssl.readPointer();
        const sub = s3.add(0x30).readPointer();
        const cr = sub.add(0x30).readByteArray(32);
        return hex(cr);
    } catch (_) {
        return null;
    }
}

(function () {
    const mod = Process.getModuleByName('chrome');
    const target = mod.base.add(SSL_LOG_SECRET_RVA);

    console.log('[*] chrome base = ' + mod.base);
    console.log('[*] ssl_log_secret = ' + target);
    console.log('[*] RBIO_OFFSET = 0x' + RBIO_OFFSET.toString(16) + ', BIO_NUM_OFFSET = 0x' + BIO_NUM_OFFSET.toString(16));

    Interceptor.attach(target, {
        onEnter(args) {
            const ssl = args[0];
            const label = safeUtf8(args[1]);
            let secretLen = -1;
            let secretHex = null;
            try {
                secretLen = args[3].toInt32();
            } catch (_) {}
            try {
                if (secretLen > 0 && secretLen <= 128) {
                    secretHex = hex(args[2].readByteArray(secretLen));
                }
            } catch (_) {}

            const fdInfo = tryReadFd(ssl);
            const crHex = tryReadCR(ssl);

            console.log('[ssl_log_secret]');
            console.log('  a0 ssl        = ' + ptrHex(args[0]));
            console.log('  a1 label_ptr  = ' + ptrHex(args[1]));
            console.log('  a2 secret_ptr = ' + ptrHex(args[2]));
            console.log('  a3 secret_len = ' + ptrHex(args[3]) + ' (' + secretLen + ')');
            console.log('  label         = ' + JSON.stringify(label));
            console.log('  rbio          = ' + fdInfo.rbio);
            console.log('  fd            = ' + fdInfo.fd);
            if (fdInfo.err) console.log('  fd_err        = ' + fdInfo.err);
            console.log('  client_random = ' + (crHex || 'null'));
            console.log('  secret        = ' + (secretHex || 'null'));
        }
    });
})();

