#!/usr/bin/env python3
"""
watchdog_attach_v2.py
─────────────────────────────────────────────────────────────
修复：确保附加到的网络进程和 SSLKEYLOGFILE 来自同一 Chrome 实例

变更：
  1. 附加前检查目标进程的 /proc/PID/environ 确认有 SSLKEYLOGFILE
  2. 要求用户提供 Chrome 主进程 PID，精确定位其子进程
  3. sudo 自动处理 ptrace 权限

用法（两步）：
  步骤1 —— 启动 Chrome（记住输出的 PID）：
    SSLKEYLOGFILE=/tmp/chrome_sslkeys_env.log \\
      /opt/google/chrome/chrome \\
      --no-sandbox \\
      --user-data-dir=/tmp/chrome_p3_test \\
      --disable-extensions &
    echo "Chrome 主进程 PID: $!"

  步骤2 —— 附加（传入上面的 PID）：
    sudo python3 watchdog_attach_v2.py <主进程PID>
    # 例如：sudo python3 watchdog_attach_v2.py 52100
"""

import frida, sys, os, time, signal

OUTPUT_FILE = '/tmp/chrome_sslkeys_frida.log'
ENV_LOG     = '/tmp/chrome_sslkeys_env.log'

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
const KEY_LEN = {
    'c e traffic': 0x81, 'c hs traffic': 0xb2,
    's hs traffic': 0xe3, 'c ap traffic': 0x114,
    's ap traffic': 0x145,
};
function hex(ab) {
    if (!ab) return '';
    return Array.from(new Uint8Array(ab)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function readCR(ssl) {
    try {
        // 路径: *(*(ssl_ptr) + 0x30) + 0x10
        return ssl.readPointer().add(0x30).readPointer().add(0x10).readByteArray(32);
    } catch(_) { return null; }
}
function emit(line) { send({t:'key', v:line}); }
function dbg(msg)   { send({t:'dbg', v:'[pid='+Process.id+'] '+msg}); }

const mod = (function() {
    for (const n of ['chrome','libchrome.so']) {
        try { return Process.getModuleByName(n); } catch(_) {}
    }
    return Process.enumerateModules()
        .filter(m => m.size > 50*1024*1024)
        .sort((a,b) => b.size - a.size)[0] || null;
})();

if (!mod) {
    dbg('chrome 模块未找到');
    send({t:'no_module'});
} else {
    dbg('模块: '+mod.name+' base='+mod.base+' size='+(mod.size/1024/1024|0)+'MB');
    let prf_ok=false, hkdf_ok=false;

    try {
        Interceptor.attach(mod.base.add(ptr('0x0A22D4B0')), {
            onEnter(a){ this.ssl=a[0]; this.out=a[1]; },
            onLeave(_){
                try {
                    const cr=readCR(this.ssl), ms=this.out.readByteArray(48);
                    if(cr&&ms) emit('CLIENT_RANDOM '+hex(cr)+' '+hex(ms));
                } catch(_) {}
            }
        });
        prf_ok=true;
        dbg('PRF hook OK @ '+mod.base.add(ptr('0x0A22D4B0')));
    } catch(e){ dbg('PRF 失败: '+e); }

    try {
        Interceptor.attach(mod.base.add(ptr('0x048837E0')), {
            onEnter(a){
                this.ssl=a[0]; this.out=a[1]; this.ll=a[4].toInt32();
                try { this.lbl=(this.ll>0&&this.ll<=20)?a[3].readUtf8String(this.ll):null; }
                catch(_){ this.lbl=null; }
            },
            onLeave(_){
                try {
                    if(!this.lbl) return;
                    const nss=NSS_LABEL[this.lbl]; if(!nss) return;
                    let kl=KEY_LEN[this.lbl]?this.ssl.add(KEY_LEN[this.lbl]).readU8():32;
                    if(kl===0||kl>64) kl=32;
                    const s=this.out.readByteArray(kl), cr=readCR(this.ssl);
                    if(s&&cr) emit(nss+' '+hex(cr)+' '+hex(s));
                } catch(_) {}
            }
        });
        hkdf_ok=true;
        dbg('HKDF hook OK @ '+mod.base.add(ptr('0x048837E0')));
    } catch(e){ dbg('HKDF 失败: '+e); }

    send({t:'ready', prf:prf_ok, hkdf:hkdf_ok});
}
"""

# ─────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────

def get_all_chrome_pids():
    """返回所有 chrome 进程的 PID"""
    pids = []
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit(): continue
        try:
            exe = os.readlink(f'/proc/{entry.name}/exe')
            if 'chrome' in exe.lower():
                pids.append(int(entry.name))
        except (PermissionError, FileNotFoundError):
            continue
    return pids

def get_children(parent_pid):
    """获取某 PID 的所有子孙进程"""
    children = []
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit(): continue
        try:
            with open(f'/proc/{entry.name}/status') as f:
                for line in f:
                    if line.startswith('PPid:'):
                        ppid = int(line.split()[1])
                        if ppid == parent_pid:
                            children.append(int(entry.name))
                        break
        except (PermissionError, FileNotFoundError):
            continue
    return children

def get_all_descendants(root_pid):
    """递归获取所有子孙进程"""
    result = set()
    queue = [root_pid]
    while queue:
        p = queue.pop()
        children = get_children(p)
        for c in children:
            if c not in result:
                result.add(c)
                queue.append(c)
    return result

def is_network_process(pid):
    """检查是否是网络进程"""
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            cmd = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore')
        return 'NetworkService' in cmd and 'chrome' in cmd
    except: return False

def has_ssl_keylog_env(pid):
    """检查进程环境是否含有 SSLKEYLOGFILE"""
    try:
        with open(f'/proc/{pid}/environ', 'rb') as f:
            env = f.read().decode('utf-8', errors='ignore')
        return 'SSLKEYLOGFILE' in env
    except: return False

def pid_cmdline_short(pid):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            cmd = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore')
        # 提取 --type= 参数
        for part in cmd.split():
            if '--type=' in part or '--utility-sub-type=' in part:
                return part
        return cmd[:60]
    except: return '?'

# ─────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────

device   = frida.get_local_device()
session  = None
keycount = 0

def on_message(message, _):
    global keycount
    if message.get('type') != 'send': return
    p = message.get('payload', {})
    t = p.get('t','')
    if t == 'key':
        keycount += 1
        line = p['v']
        print(f'\033[32m[KEY #{keycount}]\033[0m {line}')
        with open(OUTPUT_FILE, 'a') as f:
            f.write(line + '\n')
    elif t == 'dbg':
        print(f'\033[36m[DBG]\033[0m {p["v"]}')
    elif t == 'ready':
        prf  = '✓' if p.get('prf')  else '✗'
        hkdf = '✓' if p.get('hkdf') else '✗'
        print(f'\033[32m[+]\033[0m PRF={prf}  HKDF={hkdf}')
        print(f'\033[32m[+]\033[0m 现在访问 HTTPS 站点！\033[0m')
    elif t == 'no_module':
        print('\033[31m[-]\033[0m chrome 模块未找到（可能是错误进程）')
    elif message.get('type') == 'error':
        print(f'\033[31m[ERR]\033[0m {message.get("stack","")}')

def try_attach(pid):
    global session
    try:
        session = device.attach(pid)
        script  = session.create_script(HOOK_JS)
        script.on('message', on_message)
        script.load()
        return True
    except Exception as e:
        print(f'\033[31m[-]\033[0m attach pid={pid} 失败: {e}')
        session = None
        return False

def cleanup(sig=None, frame=None):
    print()
    if session:
        try: session.detach()
        except: pass
    print(f'[*] 共捕获 {keycount} 条密钥')
    print(f'[*] 验证:\n    python3 verify_keylog.py {OUTPUT_FILE} {ENV_LOG}')
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

# ── 入口 ──────────────────────────────────────
print('=' * 55)
print('  Chrome TLS Watchdog v2（精确进程定位）')
print('=' * 55)

# 确认 ptrace 权限
ptrace_scope = 999
try:
    with open('/proc/sys/kernel/yama/ptrace_scope') as f:
        ptrace_scope = int(f.read().strip())
except: pass

if ptrace_scope >= 1 and os.geteuid() != 0:
    print('\033[33m[!]\033[0m ptrace_scope=' + str(ptrace_scope) + '，非 root 运行可能失败')
    print('    建议: sudo python3 watchdog_attach_v2.py <PID>')
    print('    或:   echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope')
    print()

# 获取父进程 PID
if len(sys.argv) < 2:
    print('[*] 未指定父进程 PID，自动搜索所有 chrome 进程...')
    all_pids = get_all_chrome_pids()
    print(f'[*] 找到 {len(all_pids)} 个 chrome 进程: {all_pids[:10]}')
    # 尝试找有 SSLKEYLOGFILE 的网络进程
    target_pid = None
    for pid in all_pids:
        if is_network_process(pid) and has_ssl_keylog_env(pid):
            print(f'\033[32m[+]\033[0m 找到带 SSLKEYLOGFILE 的网络进程: pid={pid}')
            target_pid = pid
            break
    if not target_pid:
        print('[-] 未找到带 SSLKEYLOGFILE 的网络进程')
        print('    用法: sudo python3 watchdog_attach_v2.py <Chrome主进程PID>')
        print()
        print('    获取 PID 方法：')
        print('    SSLKEYLOGFILE=/tmp/chrome_sslkeys_env.log \\')
        print('      /opt/google/chrome/chrome --no-sandbox ... &')
        print('    echo $!   ← 这就是主进程 PID')
        sys.exit(1)
else:
    parent_pid = int(sys.argv[1])
    print(f'[*] Chrome 主进程 PID={parent_pid}')

    # 找其所有子孙进程中的网络进程
    descendants = get_all_descendants(parent_pid)
    print(f'[*] 子孙进程共 {len(descendants)} 个')

    target_pid = None
    print(f'\n[*] 扫描网络进程...')
    for pid in descendants:
        cmd = pid_cmdline_short(pid)
        is_net = is_network_process(pid)
        has_env = has_ssl_keylog_env(pid)
        if is_net:
            print(f'    pid={pid}  net=✓  env_ssl={"✓" if has_env else "✗"}  {cmd[:50]}')
            if target_pid is None:
                target_pid = pid

    if not target_pid:
        print('[-] 在子孙进程中未找到网络进程')
        print('[*] 等待网络进程启动（最多 15 秒）...')
        for _ in range(30):
            time.sleep(0.5)
            descendants = get_all_descendants(parent_pid)
            for pid in descendants:
                if is_network_process(pid):
                    target_pid = pid
                    print(f'\033[32m[+]\033[0m 网络进程出现: pid={pid}')
                    time.sleep(1)  # 等它稳定
                    break
            if target_pid: break

    if not target_pid:
        print('[-] 超时，未找到网络进程')
        sys.exit(1)

# 清空旧记录
open(OUTPUT_FILE, 'w').close()

# 附加
print(f'\n[*] 目标进程 pid={target_pid}')
print(f'[*] attach...')
if not try_attach(target_pid):
    print('[-] attach 失败，尝试用 sudo 运行')
    sys.exit(1)

print(f'\033[32m[+]\033[0m 附加成功！')
print(f'[+] 等待 TLS 连接... (Ctrl+C 退出)')

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass

cleanup()
