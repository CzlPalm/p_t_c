"""
lib/correlator.py — eBPF connect 事件解析 + 时序/fd 关联引擎

从 fd_tracker 的输出解析 connect 事件，
提供 fd 精确匹配和时序 fallback 两种关联策略。
"""

import collections
import re
import threading
import time


class Correlator:
    """TLS 密钥与 TCP 连接五元组的关联引擎。"""

    def __init__(self, maxlen=500):
        self._events = collections.defaultdict(
            lambda: collections.deque(maxlen=maxlen)
        )
        self._lock = threading.Lock()
        self._event_cv = threading.Condition(self._lock)

        self.fd_hits = 0
        self.time_hits = 0

    def parse_fd_tracker_output(self, proc):
        """兼容旧接口：直接从进程 stderr 读取。"""
        try:
            for raw in proc.stderr:
                line = raw.decode('utf-8', errors='ignore').strip()
                self._ingest_line(line)
        except Exception:
            pass

    def parse_fd_tracker_lines(self, line_queue):
        """从队列中持续读取 fd_tracker 行并解析。"""
        while True:
            try:
                line = line_queue.get()
                if line is None:
                    return
                self._ingest_line(line)
            except Exception:
                pass

    def _ingest_line(self, line):
        parsed = self._parse_line(line)
        if parsed:
            pid, fd, dst_ip, dst_port = parsed
            with self._event_cv:
                self._events[pid].append({
                    'time': time.monotonic(),
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'fd': fd,
                    'used': False,
                })
                self._event_cv.notify_all()

    def _parse_line(self, line):
        """解析单行 fd_tracker 输出，返回 (pid, fd, dst_ip, dst_port) 或 None。"""
        m = re.match(
            r'\[connect\] pid=(\d+)(?:\s+tid=\d+)?(?:\s+fd=(\d+))?\s+->\s+([\d.]+):(\d+)',
            line
        )
        if m:
            pid = int(m.group(1))
            fd = int(m.group(2)) if m.group(2) else 0
            dst_ip = m.group(3)
            dst_port = int(m.group(4))
            return pid, fd, dst_ip, dst_port

        m = re.match(r'\[connect\] pid=(\d+)\s+->\s+([\d.]+):(\d+)', line)
        if m:
            return int(m.group(1)), 0, m.group(2), int(m.group(3))

        return None

    def find_connect(self, pid, fd=-1, wait_timeout=0.0):
        """根据 fd 或时序查找最匹配的 connect 事件。"""
        deadline = time.monotonic() + max(0.0, wait_timeout)

        while True:
            with self._event_cv:
                if fd > 0:
                    result = self._find_by_fd_locked(pid, fd)
                    if result:
                        self.fd_hits += 1
                        return result[0], result[1], 'fd'

                result = self._find_by_time_locked(pid)
                if result:
                    self.time_hits += 1
                    return result[0], result[1], 'time'

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None, None, None

                self._event_cv.wait(timeout=remaining)

    def _find_by_fd_locked(self, pid, fd):
        evts = self._events.get(pid)
        if evts:
            for evt in reversed(evts):
                if evt['fd'] == fd and not evt['used']:
                    evt['used'] = True
                    return evt['dst_ip'], evt['dst_port']

        for other_pid, evts in self._events.items():
            if other_pid == pid:
                continue
            for evt in reversed(evts):
                if evt['fd'] == fd and not evt['used']:
                    evt['used'] = True
                    return evt['dst_ip'], evt['dst_port']
        return None

    def _find_by_time_locked(self, pid):
        evts = self._events.get(pid)
        if evts:
            for evt in reversed(evts):
                if not evt['used']:
                    evt['used'] = True
                    return evt['dst_ip'], evt['dst_port']

        for other_pid, evts in self._events.items():
            if other_pid == pid:
                continue
            for evt in reversed(evts):
                if not evt['used']:
                    evt['used'] = True
                    return evt['dst_ip'], evt['dst_port']
        return None

    @property
    def total_events(self):
        with self._lock:
            return sum(len(v) for v in self._events.values())

    def stats(self):
        return {
            'fd_hits': self.fd_hits,
            'time_hits': self.time_hits,
            'cache_hits': 0,
            'total_events': self.total_events,
        }
