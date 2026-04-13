#!/usr/bin/env python3
"""
watchdog_v13.py — 单脚本：attach 模式 + fd精确关联 + 时序fallback
用法：
  终端1: SSLKEYLOGFILE=/tmp/chrome_sslkeys_env.log /opt/google/chrome/chrome --no-sandbox --user-data-dir=/tmp/chrome_p3_test --disable-extensions &
  终端2: sudo $(which python3) watchdog_v13.py
"""

import frida,sys,os,time,signal,threading,collections,subprocess,struct,socket,re

OUTPUT_FILE='/tmp/chrome_tls_v13.log'
CHROME_BIN='/opt/google/chrome/chrome'
USER_DATA='/tmp/chrome_p3_test'
ENV_LOG='/tmp/chrome_sslkeys_env.log'
SCRIPT_DIR=os.path.dirname(os.path.abspath(__file__))
FD_TRACKER_BIN=os.path.join(SCRIPT_DIR,'fd_tracker')

connect_events=collections.defaultdict(lambda:collections.deque(maxlen=500))
conn_lock=threading.Lock()

def parse_fd_tracker_output(proc):
    try:
        for raw in proc.stderr:
            line=raw.decode('utf-8',errors='ignore').strip()
            m=re.match(r'\[connect\] pid=(\d+)(?: tid=\d+)?(?: fd=(\d+))? -> ([\d.]+):(\d+)',line)
            if not m:
                m=re.match(r'\[connect\] pid=(\d+) -> ([\d.]+):(\d+)',line)
                if m: pid,dst_ip,dst_port,fd=int(m.group(1)),m.group(2),int(m.group(3)),0
                else: continue
            else: pid,fd,dst_ip,dst_port=int(m.group(1)),int(m.group(2))if m.group(2)else 0,m.group(3),int(m.group(4))
            with conn_lock:
                connect_events[pid].append({'time':time.monotonic(),'dst_ip':dst_ip,'dst_port':dst_port,'fd':fd,'used':False})
    except: pass

def find_connect_by_fd(pid,fd):
    if fd<=0: return None
    with conn_lock:
        for p,evts in connect_events.items():
            for evt in reversed(evts):
                if evt['fd']==fd and not evt['used']:
                    evt['used']=True; return evt['dst_ip'],evt['dst_port']
    return None

def find_connect_by_time(pid):
    with conn_lock:
        evts=connect_events.get(pid)
        if not evts:
            for p,e in connect_events.items():
                if e: evts=e; break
        if not evts: return None
        for evt in reversed(evts):
            if not evt['used']:
                evt['used']=True; return evt['dst_ip'],evt['dst_port']
    return None

def lookup_src(pid,dst_ip_str,dst_port):
    try:
        parts=dst_ip_str.split('.')
        dst_hex='%02X%02X%02X%02X'%(int(parts[3]),int(parts[2]),int(parts[1]),int(parts[0]))
        dst_port_hex='%04X'%dst_port
        pids_to_try=set()
        try:
            for entry in os.scandir('/proc'):
                if entry.name.isdigit():
                    try:
                        comm=open(f'/proc/{entry.name}/comm').read().strip()
                        if 'chrome' in comm.lower() or 'Chrome' in comm: pids_to_try.add(int(entry.name))
                    except: pass
        except: pass
        pids_to_try.add(pid)
        for try_pid in pids_to_try:
            try:
                with open(f'/proc/{try_pid}/net/tcp') as f:
                    for line in f:
                        fields=line.strip().split()
                        if len(fields)<4 or fields[0]=='sl': continue
                        local,remote=fields[1],fields[2]
                        rip,rport=remote.split(':')
                        if rip.upper()==dst_hex and rport.upper()==dst_port_hex:
                            lip,lport=local.split(':')
                            b=bytes.fromhex(lip.zfill(8))
                            return f'{b[3]}.{b[2]}.{b[1]}.{b[0]}',int(lport,16)
            except: continue
    except: pass
    return None,None

HOOK_JS=r"""
'use strict';
const _emitted=new Set();
let _msCalibrated=false,_msPathType=null,_msOff1=0,_msOff2=0;
const _prfCache=new Map();
const NSS_LABEL={'c e traffic':'CLIENT_EARLY_TRAFFIC_SECRET','c hs traffic':'CLIENT_HANDSHAKE_TRAFFIC_SECRET','s hs traffic':'SERVER_HANDSHAKE_TRAFFIC_SECRET','c ap traffic':'CLIENT_TRAFFIC_SECRET_0','s ap traffic':'SERVER_TRAFFIC_SECRET_0','exp master':'EXPORTER_SECRET'};
const KEY_LEN_OFFSET={'c e traffic':0x81,'c hs traffic':0xb2,'s hs traffic':0xe3,'c ap traffic':0x114,'s ap traffic':0x145};
function hex(buf){if(!buf)return null;return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');}
function readCR(ssl){try{const s3=ssl.readPointer();const sub=s3.add(0x30).readPointer();const buf=sub.add(0x30).readByteArray(32);if(!buf)return null;const u8=new Uint8Array(buf);if(u8[0]===0&&u8[1]===0&&u8[2]===0&&u8[3]===0)return null;if(new Set(u8).size<16)return null;return buf;}catch(_){return null;}}
function readFd(ssl){try{const rbio=ssl.add(0x240).readPointer();if(rbio.isNull())return -1;const fd=rbio.add(0x03c).readS32();return(fd>=3&&fd<=65535)?fd:-1;}catch(_){return -1;}}
function emitKey(line,src,fd){const p=line.split(' ');if(p.length<3)return;const dk=p[0]+'|'+p[1];if(_emitted.has(dk))return;_emitted.add(dk);send({t:'key',v:line,src:src,pid:Process.id,fd:fd});}
function dbg(msg){send({t:'dbg',v:'[pid='+Process.id+'] '+msg});}
function calibrateMs(ssl,knownMsHex){const msBytes=[];for(let i=0;i<96;i+=2)msBytes.push(parseInt(knownMsHex.substr(i,2),16));try{const dump=new Uint8Array(ssl.readByteArray(0x1000));for(let off=0;off<=dump.length-48;off+=8){if(dump[off]!==msBytes[0]||dump[off+1]!==msBytes[1])continue;let ok=true;for(let j=2;j<48;j++){if(dump[off+j]!==msBytes[j]){ok=false;break;}}if(ok){_msPathType='direct';_msOff1=off;_msCalibrated=true;dbg('MS cal: ssl+0x'+off.toString(16));return true;}}}catch(_){}try{for(let pOff=0;pOff<0x400;pOff+=8){let p;try{p=ssl.add(pOff).readPointer();}catch(_){continue;}if(p.isNull())continue;let sub;try{sub=new Uint8Array(p.readByteArray(0x200));}catch(_){continue;}for(let off=0;off<=sub.length-48;off+=8){if(sub[off]!==msBytes[0]||sub[off+1]!==msBytes[1])continue;let ok=true;for(let j=2;j<48;j++){if(sub[off+j]!==msBytes[j]){ok=false;break;}}if(ok){_msPathType='indirect';_msOff1=pOff;_msOff2=off;_msCalibrated=true;dbg('MS cal: *(ssl+0x'+pOff.toString(16)+')+0x'+off.toString(16));return true;}}}}catch(_){}return false;}
function readMsCalibrated(ssl){try{if(_msPathType==='direct')return ssl.add(_msOff1).readByteArray(48);if(_msPathType==='indirect')return ssl.add(_msOff1).readPointer().add(_msOff2).readByteArray(48);}catch(_){}return null;}
function installHooks(mod){
    dbg('模块: '+mod.name+' base='+mod.base+' size='+(mod.size/1024/1024|0)+'MB');
    let prf_ok=false,keyexp_ok=false,hkdf_ok=false;
    try{Interceptor.attach(mod.base.add(ptr('0x0A22D4B0')),{onEnter(args){this.ssl=args[0];this.out=args[1];},onLeave(_){try{const cr=readCR(this.ssl),ms=this.out.readByteArray(48);if(!cr||!ms)return;const msHex=hex(ms);const fd=readFd(this.ssl);emitKey('CLIENT_RANDOM '+hex(cr)+' '+msHex,'prf',fd);_prfCache.set(this.ssl.toString(),msHex);}catch(_){}}});prf_ok=true;dbg('PRF hook OK');}catch(e){dbg('PRF fail: '+e);}
    try{Interceptor.attach(mod.base.add(ptr('0x0A22D130')),{onEnter(args){this.ssl=args[0];},onLeave(_){try{const cr=readCR(this.ssl);if(!cr)return;let ms=null;if(_msCalibrated){ms=readMsCalibrated(this.ssl);}else{const cached=_prfCache.get(this.ssl.toString());if(cached&&calibrateMs(this.ssl,cached))ms=readMsCalibrated(this.ssl);}if(!cr||!ms)return;const fd=readFd(this.ssl);emitKey('CLIENT_RANDOM '+hex(cr)+' '+hex(ms),'key_exp',fd);}catch(_){}}});keyexp_ok=true;dbg('key_expansion hook OK');}catch(e){dbg('key_exp fail: '+e);}
    try{Interceptor.attach(mod.base.add(ptr('0x048837E0')),{onEnter(args){this.ssl=args[0];this.out=args[1];try{const ll=args[4].toInt32();this.lbl=(ll>0&&ll<=20)?args[3].readUtf8String(ll):null;}catch(_){this.lbl=null;}},onLeave(_){try{if(!this.lbl)return;const nss=NSS_LABEL[this.lbl];if(!nss)return;let kl;if(this.lbl==='exp master'){try{const s3=this.ssl.readPointer();const sub=s3.add(0x30).readPointer();kl=sub.add(0x1b2).readU8();if(!kl||kl>64)kl=48;}catch(_){kl=48;}}else{const lo=KEY_LEN_OFFSET[this.lbl];kl=lo?this.ssl.add(lo).readU8():32;if(!kl||kl>64)kl=32;}const secret=this.out.readByteArray(kl),cr=readCR(this.ssl);if(!secret||!cr)return;const fd=readFd(this.ssl);emitKey(nss+' '+hex(cr)+' '+hex(secret),'hkdf',fd);}catch(_){}}});hkdf_ok=true;dbg('HKDF hook OK');}catch(e){dbg('HKDF fail: '+e);}
    send({t:'ready',prf:prf_ok,keyexp:keyexp_ok,hkdf:hkdf_ok});
}
(function(){try{installHooks(Process.getModuleByName('chrome'));}catch(_){let r=0;const poll=()=>{try{installHooks(Process.getModuleByName('chrome'));}catch(_){if(++r<100)setTimeout(poll,100);else dbg('timeout');}};setTimeout(poll,100);}})();
"""

keycount=0;tuple_hits=0;fd_match_hits=0;ts_match_hits=0
src_counts=collections.Counter();lock=threading.Lock();sessions={};cr_to_tuple={}
device=frida.get_local_device();fd_tracker_proc=None

def on_message(pid):
    def handler(message,_):
        global keycount,tuple_hits,fd_match_hits,ts_match_hits
        if message.get('type')!='send':return
        p=message.get('payload',{});t=p.get('t','')
        if t=='key':
            line=p['v'];src=p.get('src','?');fpid=p.get('pid',pid);fd=p.get('fd',-1)
            with lock: keycount+=1;src_counts[src]+=1;n=keycount
            parts=line.split(' ');cr_hex=parts[1]if len(parts)>=3 else''
            tup=cr_to_tuple.get(cr_hex);conn=None;match_method='cache'
            if not tup:
                if fd and fd>0: conn=find_connect_by_fd(fpid,fd)
                if conn: match_method='fd';
                else: conn=find_connect_by_time(fpid);match_method='time'if conn else None
                if conn:
                    dst_ip,dst_port=conn
                    src_ip,src_port=lookup_src(fpid,dst_ip,dst_port)
                    tup=(src_ip or'?',src_port or 0,dst_ip,dst_port)
                    cr_to_tuple[cr_hex]=tup
                    if match_method=='fd':
                        with lock:fd_match_hits+=1
                    elif match_method=='time':
                        with lock:ts_match_hits+=1
            if tup:
                with lock:tuple_hits+=1
                src_s=f'{tup[0]}:{tup[1]}'if tup[0]!='?'else'?:?'
                comment=f'# five_tuple=tcp:{src_s}->{tup[2]}:{tup[3]} pid={fpid} fd={fd}'
                print(f'\033[36m{comment}\033[0m')
                with open(OUTPUT_FILE,'a')as f:f.write(comment+'\n')
            short=(line[:80]+'...')if len(line)>80 else line
            colors={'hkdf':'\033[32m','prf':'\033[34m','key_exp':'\033[33m'}
            c=colors.get(src,'\033[0m')
            tup_s=f' ->{tup[2]}:{tup[3]}'if tup else''
            fd_s=f' fd={fd}'if fd and fd>0 else''
            print(f'{c}[KEY #{n:4d} {src:7s}{fd_s}{tup_s}]\033[0m {short}')
            with open(OUTPUT_FILE,'a')as f:f.write(line+'\n')
        elif t=='dbg':print(f'\033[36m[DBG pid={pid}]\033[0m {p["v"]}')
        elif t=='ready':
            prf='✓'if p.get('prf')else'✗';keyexp='✓'if p.get('keyexp')else'✗';hkdf='✓'if p.get('hkdf')else'✗'
            print(f'\033[32m[+]\033[0m pid={pid} PRF={prf} key_exp={keyexp} HKDF={hkdf}')
        elif message.get('type')=='error':print(f'\033[31m[ERR pid={pid}]\033[0m {message.get("stack","")}')
    return handler

def attach_pid(pid,label=''):
    try:
        sess=device.attach(pid);scr=sess.create_script(HOOK_JS);scr.on('message',on_message(pid));scr.load()
        sessions[pid]=sess;print(f'\033[32m[+]\033[0m 附加 pid={pid} {label}');return True
    except Exception as e:print(f'\033[31m[-]\033[0m 附加失败 pid={pid}: {e}');return False

def find_chrome_network_pid():
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():continue
        try:
            with open(f'/proc/{entry.name}/cmdline','rb')as f:cmd=f.read().replace(b'\x00',b' ').decode('utf-8',errors='ignore')
            if'NetworkService'in cmd and USER_DATA in cmd:return int(entry.name)
        except:continue
    return None

def cleanup(sig=None,frame=None):
    print()
    for s in sessions.values():
        try:s.detach()
        except:pass
    if fd_tracker_proc:
        fd_tracker_proc.terminate()
        try:fd_tracker_proc.wait(timeout=3)
        except:fd_tracker_proc.kill()
    total_conn=sum(len(v)for v in connect_events.values())
    print(f'[*] 密钥: {keycount} 条')
    print(f'    来源: {dict(src_counts)}')
    print(f'    五元组命中: {tuple_hits}/{keycount}')
    print(f'    关联方式: fd精确={fd_match_hits}  时序={ts_match_hits}  缓存={max(0,tuple_hits-fd_match_hits-ts_match_hits)}')
    print(f'    connect 事件: {total_conn}  唯一连接: {len(cr_to_tuple)}')
    print(f'\n[*] 密钥验证:')
    print(f'    diff <(grep -v "^#" {OUTPUT_FILE} | sort) \\')
    print(f'         <(grep -E "^(CLIENT|SERVER|EXPORTER)" {ENV_LOG} | sort)')
    sys.exit(0)

signal.signal(signal.SIGINT,cleanup)

print('='*68)
print('  Chrome TLS Watchdog v13 — attach 模式')
print('  密钥: PRF + key_expansion + HKDF')
print('  五元组: eBPF connect() + fd精确 + 时序fallback')
print('  颜色: \033[34m蓝\033[0m=PRF  \033[33m黄\033[0m=key_exp  \033[32m绿\033[0m=HKDF  \033[36m青\033[0m=五元组')
print('='*68)

if os.geteuid()!=0:
    print('\033[31m[!] 需要 root\033[0m');print(f'    sudo $(which python3) {sys.argv[0]}');sys.exit(1)
if not os.path.exists(FD_TRACKER_BIN):
    print(f'\033[31m[!] 未找到 {FD_TRACKER_BIN}\033[0m');print(f'    cd {SCRIPT_DIR} && make');sys.exit(1)

print('[*] 启动 fd_tracker ...')
fd_tracker_proc=subprocess.Popen([FD_TRACKER_BIN,'-v'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
time.sleep(1)
if fd_tracker_proc.poll()is not None:print('\033[31m[!] fd_tracker 启动失败\033[0m');sys.exit(1)
print(f'[+] fd_tracker PID={fd_tracker_proc.pid}')
threading.Thread(target=parse_fd_tracker_output,args=(fd_tracker_proc,),daemon=True).start()

try:open(OUTPUT_FILE,'w').close()
except:pass

print(f'\n[*] 查找 Chrome NetworkService (--user-data-dir={USER_DATA}) ...')
print(f'    如未启动 Chrome，请在另一终端执行:')
print(f'    SSLKEYLOGFILE={ENV_LOG} {CHROME_BIN} --no-sandbox \\')
print(f'      --user-data-dir={USER_DATA} --disable-extensions &\n')

net_pid=None
for attempt in range(60):
    net_pid=find_chrome_network_pid()
    if net_pid:break
    time.sleep(1)
    if attempt%10==9:print(f'    等待中... ({attempt+1}s)')
if not net_pid:print('\033[31m[!] 60s 超时\033[0m');cleanup()

print(f'[*] NetworkService PID={net_pid}')
attach_pid(net_pid,'[NetworkService]')
print(f'\n\033[32m[+]\033[0m 就绪！访问 HTTPS 站点，Ctrl+C 退出\n')

try:
    while True:time.sleep(1)
except KeyboardInterrupt:pass
cleanup()
