"""
lib/net_lookup.py — 通过 /proc/net/tcp 反查 TCP 连接的源地址

已知 dst_ip:dst_port → 在 /proc/{pid}/net/tcp 中查找匹配行
→ 返回 (src_ip, src_port)
"""

import os


def lookup_src(pid, dst_ip_str, dst_port):
    """根据目标 IP:端口，在 /proc/net/tcp 中反查源 IP:端口。

    Args:
        pid: Chrome 进程 PID（用于读取 /proc/{pid}/net/tcp）
        dst_ip_str: 目标 IP 字符串，如 "142.250.80.46"
        dst_port: 目标端口，如 443

    Returns:
        (src_ip, src_port) 或 (None, None)
    """
    try:
        parts = dst_ip_str.split('.')
        # /proc/net/tcp 使用小端序十六进制
        dst_hex = '%02X%02X%02X%02X' % (
            int(parts[3]), int(parts[2]), int(parts[1]), int(parts[0])
        )
        dst_port_hex = '%04X' % dst_port

        # 收集所有 chrome 相关 PID（共享网络命名空间）
        pids_to_try = _get_chrome_pids()
        pids_to_try.add(pid)

        for try_pid in pids_to_try:
            result = _search_proc_net_tcp(try_pid, dst_hex, dst_port_hex)
            if result:
                return result
    except Exception:
        pass

    return None, None


def _get_chrome_pids():
    """扫描 /proc 获取所有 chrome 进程 PID。"""
    pids = set()
    try:
        for entry in os.scandir('/proc'):
            if not entry.name.isdigit():
                continue
            try:
                comm = open(f'/proc/{entry.name}/comm').read().strip()
                if 'chrome' in comm.lower() or 'Chrome' in comm:
                    pids.add(int(entry.name))
            except (PermissionError, FileNotFoundError, OSError):
                pass
    except Exception:
        pass
    return pids


def _search_proc_net_tcp(pid, dst_hex, dst_port_hex):
    """在指定 PID 的 /proc/net/tcp 中搜索匹配行。"""
    try:
        with open(f'/proc/{pid}/net/tcp') as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) < 4 or fields[0] == 'sl':
                    continue
                local, remote = fields[1], fields[2]
                rip, rport = remote.split(':')
                if rip.upper() == dst_hex and rport.upper() == dst_port_hex:
                    lip, lport = local.split(':')
                    b = bytes.fromhex(lip.zfill(8))
                    src_ip = f'{b[3]}.{b[2]}.{b[1]}.{b[0]}'
                    src_port = int(lport, 16)
                    return src_ip, src_port
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return None
