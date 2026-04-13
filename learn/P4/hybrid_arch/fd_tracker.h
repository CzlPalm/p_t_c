/* fd_tracker.h — v4
 * 完整五元组版本
 * 同时使用 connect() tracepoint 和 inet_sock_set_state tracepoint
 */
#pragma once
#ifndef __BPF__
#include <linux/types.h>
#endif

struct connect_event {
    __u32 pid;
    __u32 tid;
    __u64 ts_ns;
    __u32 fd;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};
