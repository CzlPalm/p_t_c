#!/usr/bin/env python3
"""
watchdog_attach_v4.py
─────────────────────────────────────────────────────────────
使用 Frida spawn 模式：在 Chrome 第一条指令执行前注入，
确保零时序差，不漏任何 TLS 连接。

修复记录：
  v4.1 - exp master 长度截断修复（二级解引用路径）
  v4.1 - NetworkService 过滤增加 user-data-dir 验证，排除无关 Chrome 实例

用法：
    sudo python3 watchdog_attach_v4.py
"""

import frida, sys, os, time, signal, threading

OUTPUT_FILE  = '/tmp/chrome_sslkeys_frida_v4.log'
CHROME_BIN   = '/opt/google/chrome/chrome'
USER_DATA    = '/tmp/chrome_p3_test'
ENV_LOG      = '/tmp/chrome_sslkeys_env.log'

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

// 密钥长度字节在 ssl_ptr 上的偏移（直接偏移，适用于除 exp master 外的所有标签）
const KEY_LEN_OFFSET = {
    'c e traffic':  0x81,
    'c hs traffic': 0xb2,
    's hs traffic': 0xe3,
    'c ap traffic': 0x114,
    's ap traffic': 0x145,
    // 'exp master' 不在这里，走二级解引用路径
};

function hex(buf) {
    if (!buf) return null;
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// client_random 路径（三次验证确认）：
// s3 = *ssl_ptr → sub = *(s3 + 0x30) → client_random = sub + 0x30，读 32 字节
function readCR(ssl) {
    try {
        const s3  = ssl.readPointer();
        const sub = s3.add(0x30).readPointer();
        return sub.add(0x30).readByteArray(32);
    } catch(_) { return null; }
}

function emit(line) { send({t: 'key', v: line}); }
function dbg(msg)   { send({t: 'dbg', v: '[pid=' + Process.id + '] ' + msg}); }

function waitForModule(name, cb, retry) {
    retry = retry || 0;
    try {
        const m = Process.getModuleByName(name);
        cb(m);
    } catch(_) {
        if (retry > 100) { dbg('模块等待超时: ' + name); return; }
        setTimeout(() => waitForModule(name, cb, retry + 1), 100);
    }
}

function installHooks(mod) {
    dbg('模块: ' + mod.name + ' base=' + mod.base +
        ' size=' + (mod.size / 1024 / 1024 | 0) + 'MB');

    let prf_ok = false, hkdf_ok = false;

    // ── TLS 1.2 PRF ──────────────────────────────────────────────────────────
    try {
        Interceptor.attach(mod.base.add(ptr('0x0A22D4B0')), {
            onEnter(args) {
                this.ssl = args[0];   // RDI = ssl_ptr
                this.out = args[1];   // RSI = output（master_secret 写入地址）
            },
            onLeave(_) {
                try {
                    const cr = readCR(this.ssl);
                    const ms = this.out.readByteArray(48);
                    if (cr && ms) emit('CLIENT_RANDOM ' + hex(cr) + ' ' + hex(ms));
                } catch(_) {}
            }
        });
        prf_ok = true;
        dbg('PRF hook OK @ ' + mod.base.add(ptr('0x0A22D4B0')));
    } catch(e) { dbg('PRF 失败: ' + e); }

    // ── TLS 1.3 HKDF ─────────────────────────────────────────────────────────
    try {
        Interceptor.attach(mod.base.add(ptr('0x048837E0')), {
            onEnter(args) {
                this.ssl = args[0];   // RDI = ssl_ptr
                this.out = args[1];   // RSI = output_buf（密钥写入地址）
                // RCX = label 指针，R8 = label 长度
                try {
                    const ll = args[4].toInt32();
                    this.lbl = (ll > 0 && ll <= 20)
                        ? args[3].readUtf8String(ll)
                        : null;
                } catch(_) { this.lbl = null; }
            },
            onLeave(_) {
                try {
                    if (!this.lbl) return;
                    const nss = NSS_LABEL[this.lbl];
                    if (!nss) return;

                    let kl;
                    if (this.lbl === 'exp master') {
                        // exp master 存储路径：*(*(*(ssl_ptr)) + 0x30) + 0x182
                        // 长度字节路径：       *(*(*(ssl_ptr)) + 0x30) + 0x1b2
                        // 与其他密钥不同，需要二级解引用，不能用 KEY_LEN_OFFSET 直接读
                        try {
                            const s3  = this.ssl.readPointer();
                            const sub = s3.add(0x30).readPointer();
                            kl = sub.add(0x1b2).readU8();
                            if (kl === 0 || kl > 64) kl = 48;
                        } catch(_) { kl = 48; }
                    } else {
                        // 其余标签：长度字节在 ssl_ptr 直接偏移处
                        const lo = KEY_LEN_OFFSET[this.lbl];
                        kl = lo ? this.ssl.add(lo).readU8() : 32;
                        if (kl === 0 || kl > 64) kl = 32;
                    }

                    const secret = this.out.readByteArray(kl);
                    const cr     = readCR(this.ssl);
                    if (secret && cr)
                        emit(nss + ' ' + hex(cr) + ' ' + hex(secret));
                } catch(_) {}
            }
        });
        hkdf_ok = true;
        dbg('HKDF hook OK @ ' + mod.base.add(ptr('0x048837E0')));
    } catch(e) { dbg('HKDF 失败: ' + e); }

    send({t: 'ready', prf: prf_ok, hkdf: hkdf_ok});
}

waitForModule('chrome', installHooks);
"""

# ─────────────────────────────────────────────────────────────────────────────
device   = frida.get_local_device()
sessions = {}
keycount = 0
lock     = threading.Lock()

def on_message(pid):
    def handler(message, _):
        global keycount
        if message.get('type') != 'send': return
        p = message.get('payload', {})
        t = p.get('t', '')
        if t == 'key':
            with lock:
                keycount += 1
                line = p['v']
            print(f'\033[32m[KEY #{keycount} pid={pid}]\033[0m {line}')
            with open(OUTPUT_FILE, 'a') as f:
                f.write(line + '\n')
        elif t == 'dbg':
            print(f'\033[36m[DBG pid={pid}]\033[0m {p["v"]}')
        elif t == 'ready':
            prf  = '✓' if p.get('prf')  else '✗'
            hkdf = '✓' if p.get('hkdf') else '✗'
            print(f'\033[32m[+]\033[0m pid={pid}  PRF={prf}  HKDF={hkdf}')
        elif t == 'no_module':
            print(f'\033[31m[-]\033[0m pid={pid} chrome 模块未找到')
        elif message.get('type') == 'error':
            print(f'\033[31m[ERR pid={pid}]\033[0m {message.get("stack","")}')
    return handler

def attach_pid(pid, label=''):
    try:
        sess = device.attach(pid)
        scr  = sess.create_script(HOOK_JS)
        scr.on('message', on_message(pid))
        scr.load()
        sessions[pid] = sess
        print(f'\033[32m[+]\033[0m 附加成功 pid={pid} {label}')
        return True
    except Exception as e:
        print(f'\033[31m[-]\033[0m 附加失败 pid={pid}: {e}')
        return False

# ── 工具函数 ──────────────────────────────────────────────────────────────────

def is_our_chrome_network_process(pid, user_data_dir):
    """
    判断 pid 是否是属于当前 Chrome 实例的 NetworkService 进程。
    额外验证 user-data-dir，排除系统中其他 Chrome/Electron 实例的网络进程。
    """
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            cmd = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore')
        return 'NetworkService' in cmd and user_data_dir in cmd
    except:
        return False

# ── 子进程监控线程 ────────────────────────────────────────────────────────────

def watch_child_processes(parent_pid):
    """
    持续扫描 parent_pid 的直接子进程，
    发现属于当前 Chrome 实例的 NetworkService 进程时自动附加。
    """
    known = set()
    while True:
        try:
            for entry in os.scandir('/proc'):
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                if pid in known or pid in sessions:
                    continue
                try:
                    with open(f'/proc/{pid}/status') as f:
                        ppid = None
                        for line in f:
                            if line.startswith('PPid:'):
                                ppid = int(line.split()[1])
                                break
                    if ppid != parent_pid:
                        continue

                    # 关键修复：用 user-data-dir 区分同系统的多个 Chrome 实例
                    if is_our_chrome_network_process(pid, USER_DATA):
                        known.add(pid)
                        time.sleep(0.3)   # 等进程完全启动
                        attach_pid(pid, '[NetworkService]')
                    else:
                        known.add(pid)
                except:
                    pass
        except:
            pass
        time.sleep(0.2)

# ── 清理 ──────────────────────────────────────────────────────────────────────

def cleanup(sig=None, frame=None):
    print()
    for pid, sess in sessions.items():
        try:
            sess.detach()
        except:
            pass
    print(f'[*] 共捕获 {keycount} 条密钥')
    print(f'[*] 验证命令：')
    print(f'    diff <(sort {OUTPUT_FILE}) \\')
    print(f'         <(grep -E "^(CLIENT|SERVER|EXPORTER)" {ENV_LOG} | sort)')
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

# ── 主流程 ────────────────────────────────────────────────────────────────────

print('=' * 55)
print('  Chrome TLS Watchdog v4.1')
print('  spawn 模式 | 零时序差 | 多实例隔离')
print('=' * 55)

# 清空日志
open(OUTPUT_FILE, 'w').close()
open(ENV_LOG,     'w').close()

# spawn Chrome（Frida 在第一条指令前暂停，注入后再 resume）
print(f'[*] spawn: {CHROME_BIN}')
env = os.environ.copy()
env['SSLKEYLOGFILE'] = ENV_LOG

child_pid = device.spawn(
    [CHROME_BIN,
     '--no-sandbox',
     f'--user-data-dir={USER_DATA}',
     '--disable-extensions'],
    env=env
)
print(f'[*] Chrome PID = {child_pid}')

# 注入主进程
attach_pid(child_pid, '[main]')

# 启动子进程监控线程
t = threading.Thread(target=watch_child_processes,
                     args=(child_pid,), daemon=True)
t.start()

# 恢复 Chrome 执行
device.resume(child_pid)
print(f'\033[32m[+]\033[0m Chrome 已恢复运行')
print(f'[+] 访问 HTTPS 站点后 Ctrl+C 退出\n')

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass

cleanup()
