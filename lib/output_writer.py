"""
lib/output_writer.py — 密钥日志输出管理

输出格式：
    # five_tuple=tcp:192.168.1.5:54321->142.250.80.46:443 pid=12345 fd=48
    CLIENT_HANDSHAKE_TRAFFIC_SECRET <cr_hex> <secret_hex>

支持同时写入：
    - 带五元组注释的完整日志
    - Wireshark 纯净密钥文件（无注释行）
"""

import threading


class OutputWriter:
    """线程安全的密钥日志写入器。"""

    def __init__(self, keylog_path, wireshark_path=None):
        self._keylog_path = keylog_path
        self._wireshark_path = wireshark_path
        self._lock = threading.Lock()

        # 清空文件
        open(self._keylog_path, 'w').close()
        if self._wireshark_path:
            open(self._wireshark_path, 'w').close()

    def write_tuple_comment(self, src_ip, src_port, dst_ip, dst_port, pid, fd):
        """写入五元组注释行。"""
        src_s = f'{src_ip}:{src_port}' if src_ip and src_ip != '?' else '?:?'
        comment = f'# five_tuple=tcp:{src_s}->{dst_ip}:{dst_port} pid={pid} fd={fd}'
        with self._lock:
            with open(self._keylog_path, 'a') as f:
                f.write(comment + '\n')
        return comment

    def write_key(self, line):
        """写入密钥行（同时写入 keylog 和 wireshark 文件）。"""
        with self._lock:
            with open(self._keylog_path, 'a') as f:
                f.write(line + '\n')
            if self._wireshark_path:
                with open(self._wireshark_path, 'a') as f:
                    f.write(line + '\n')

    def export_wireshark(self, path=None):
        """从 keylog 文件导出 Wireshark 纯净版（去掉 # 注释行）。"""
        target = path or self._wireshark_path
        if not target:
            return
        with self._lock:
            with open(self._keylog_path) as src:
                with open(target, 'w') as dst:
                    for line in src:
                        if not line.startswith('#'):
                            dst.write(line)

    @property
    def path(self):
        return self._keylog_path
