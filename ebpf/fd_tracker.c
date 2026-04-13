/* fd_tracker.c — v4 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fd_tracker.skel.h"
#include "fd_tracker.h"

#define CONNECT_LOG "/tmp/chrome_connects.log"

static volatile int g_running = 1;
static FILE *g_log = NULL;
static int g_count = 0, g_verbose = 0;

static void sig_handler(int sig) { (void)sig; g_running = 0; }
static int libbpf_print(enum libbpf_print_level lv, const char *f, va_list a)
{ return lv == LIBBPF_DEBUG ? 0 : vfprintf(stderr, f, a); }

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    struct connect_event *e = data;
    if (size < sizeof(*e)) return 0;
    struct in_addr a = { .s_addr = e->dst_ip };
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    if (g_log) {
        fprintf(g_log, "%llu %u %u %u %s %u\n",
                (unsigned long long)e->ts_ns, e->pid, e->tid, e->fd, ip, e->dst_port);
        fflush(g_log);
    }
    g_count++;
    if (g_verbose) fprintf(stderr, "[connect] pid=%u fd=%u -> %s:%u\n", e->pid, e->fd, ip, e->dst_port);
    return 0;
}

int main(int argc, char **argv)
{
    g_verbose = (argc > 1 && strcmp(argv[1], "-v") == 0);
    if (!g_verbose) libbpf_set_print(libbpf_print);
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    struct fd_tracker_bpf *skel = fd_tracker_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "[!] BPF 加载失败\n"); return 1; }
    if (fd_tracker_bpf__attach(skel)) { fprintf(stderr, "[!] attach 失败\n"); goto err; }

    g_log = fopen(CONNECT_LOG, "w");
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "[!] ringbuf 失败\n"); goto err; }

    fprintf(stderr, "[+] fd_tracker v4 启动\n[+] 输出: %s\n[+] Ctrl+C 退出\n\n", CONNECT_LOG);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    while (g_running) ring_buffer__poll(rb, 100);
    fprintf(stderr, "\n[*] 共 %d 个 connect 事件\n", g_count);
    ring_buffer__free(rb);
err:
    if (g_log) fclose(g_log);
    fd_tracker_bpf__destroy(skel);
    return 0;
}
