#!/usr/bin/env python3
"""netfile-top: correlaciona I/O de arquivo com I/O de rede por PID via eBPF.

Ancora kprobes em vfs_read/vfs_write (arquivo) e tcp_sendmsg/tcp_cleanup_rbuf
(rede), alem de um tracepoint em sys_enter_sendfile64. Agrega bytes por PID em
um BPF_HASH e, a cada janela, imprime um ranking ordenado pelo score de
correlacao = min(bytes_de_arquivo, bytes_de_rede) no intervalo.

Uso: sudo python3 netfile_top.py [-i 2] [-n 10] [-j]
"""
import argparse
import json
import signal
import sys
import time

from bcc import BPF

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct stats_t {
    u64 file_read_bytes;
    u64 file_write_bytes;
    u64 tcp_tx_bytes;
    u64 tcp_rx_bytes;
    u64 sendfile_calls;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(stats, u32, struct stats_t);

// S_IFMT=0170000, S_IFREG=0100000: filtra para apenas arquivos regulares.
// Sem esse filtro, vfs_read/write tambem contam sockets, pipes, tty etc.,
// o que polui a coluna de arquivo para processos de rede como iperf3.
static __always_inline int is_regular_file(struct file *f) {
    if (!f) return 0;
    struct inode *inode = f->f_inode;
    if (!inode) return 0;
    umode_t mode = inode->i_mode;
    return (mode & 0170000) == 0100000;
}

static __always_inline struct stats_t *touch(u32 pid) {
    struct stats_t *s = stats.lookup(&pid);
    if (s) return s;
    struct stats_t zero = {};
    bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
    stats.update(&pid, &zero);
    return stats.lookup(&pid);
}

int kp_vfs_read(struct pt_regs *ctx, struct file *file, void *buf, size_t count) {
    if (!is_regular_file(file)) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stats_t *s = touch(pid);
    if (s) __sync_fetch_and_add(&s->file_read_bytes, (u64)count);
    return 0;
}

int kp_vfs_write(struct pt_regs *ctx, struct file *file, void *buf, size_t count) {
    if (!is_regular_file(file)) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stats_t *s = touch(pid);
    if (s) __sync_fetch_and_add(&s->file_write_bytes, (u64)count);
    return 0;
}

int kp_tcp_sendmsg(struct pt_regs *ctx, void *sk, void *msg, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stats_t *s = touch(pid);
    if (s) __sync_fetch_and_add(&s->tcp_tx_bytes, (u64)size);
    return 0;
}

int kp_tcp_cleanup_rbuf(struct pt_regs *ctx, void *sk, int copied) {
    if (copied <= 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stats_t *s = touch(pid);
    if (s) __sync_fetch_and_add(&s->tcp_rx_bytes, (u64)copied);
    return 0;
}

int kretp_tcp_recvmsg(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stats_t *s = touch(pid);
    if (s) __sync_fetch_and_add(&s->tcp_rx_bytes, (u64)ret);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendfile64) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stats_t *s = touch(pid);
    if (s) __sync_fetch_and_add(&s->sendfile_calls, 1);
    return 0;
}
"""


def human(n):
    for unit in ("B", "K", "M", "G"):
        if n < 1024.0:
            return f"{n:6.1f}{unit}"
        n /= 1024.0
    return f"{n:6.1f}T"


def main():
    ap = argparse.ArgumentParser(description="Correlaciona I/O de arquivo e rede por PID.")
    ap.add_argument("-i", "--interval", type=int, default=2, help="janela em segundos (padrao 2)")
    ap.add_argument("-n", "--top", type=int, default=10, help="linhas exibidas (padrao 10)")
    ap.add_argument("-j", "--json", action="store_true", help="uma linha JSON por janela")
    ap.add_argument("--min-bytes", type=int, default=4096,
                    help="esconde PIDs abaixo deste total na janela (padrao 4096)")
    args = ap.parse_args()

    b = BPF(text=BPF_PROGRAM)

    b.attach_kprobe(event="vfs_read", fn_name="kp_vfs_read")
    b.attach_kprobe(event="vfs_write", fn_name="kp_vfs_write")
    b.attach_kprobe(event="tcp_sendmsg", fn_name="kp_tcp_sendmsg")
    try:
        b.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="kp_tcp_cleanup_rbuf")
    except Exception as e:
        print(f"[warn] tcp_cleanup_rbuf indisponivel ({e}); usando kretprobe em tcp_recvmsg",
              file=sys.stderr)
        b.attach_kretprobe(event="tcp_recvmsg", fn_name="kretp_tcp_recvmsg")

    stats = b["stats"]
    prev = {}
    running = True

    def stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    if not args.json:
        print(f"# netfile-top (janela {args.interval}s). Ctrl+C para sair.", flush=True)

    while running:
        time.sleep(args.interval)

        snapshot = {}
        for k, v in stats.items():
            pid = k.value
            snapshot[pid] = {
                "comm": v.comm.decode("utf-8", "replace").strip("\x00"),
                "file_rd": v.file_read_bytes,
                "file_wr": v.file_write_bytes,
                "tcp_tx": v.tcp_tx_bytes,
                "tcp_rx": v.tcp_rx_bytes,
                "sendfile": v.sendfile_calls,
            }

        rows = []
        zero = {"file_rd": 0, "file_wr": 0, "tcp_tx": 0, "tcp_rx": 0, "sendfile": 0}
        for pid, cur in snapshot.items():
            p = prev.get(pid, zero)
            d_rd = cur["file_rd"] - p["file_rd"]
            d_wr = cur["file_wr"] - p["file_wr"]
            d_tx = cur["tcp_tx"] - p["tcp_tx"]
            d_rx = cur["tcp_rx"] - p["tcp_rx"]
            d_sf = cur["sendfile"] - p["sendfile"]
            file_total = d_rd + d_wr
            net_total = d_tx + d_rx
            if file_total + net_total < args.min_bytes and d_sf == 0:
                continue
            corr = min(file_total, net_total)
            rows.append({
                "pid": pid, "comm": cur["comm"],
                "file_rd": d_rd, "file_wr": d_wr,
                "tcp_tx": d_tx, "tcp_rx": d_rx,
                "sendfile": d_sf, "corr": corr,
            })
        prev = snapshot
        rows.sort(key=lambda r: r["corr"], reverse=True)
        top = rows[: args.top]

        if args.json:
            # modo JSON emite todas as linhas que passaram no --min-bytes
            # (top-N e apenas para a tabela de texto)
            print(json.dumps({"ts": time.time(), "top": rows}), flush=True)
            continue

        print(f"\n=== {time.strftime('%H:%M:%S')} (janela {args.interval}s) ===")
        header = (f"{'PID':>7} {'COMM':<16} {'FILE_RD':>8} {'FILE_WR':>8} "
                  f"{'TCP_TX':>8} {'TCP_RX':>8} {'SENDFILE':>8} {'CORR':>8}")
        print(header)
        for r in top:
            print(f"{r['pid']:>7} {r['comm'][:16]:<16} "
                  f"{human(r['file_rd'])} {human(r['file_wr'])} "
                  f"{human(r['tcp_tx'])} {human(r['tcp_rx'])} "
                  f"{r['sendfile']:>8} {human(r['corr'])}")
        if not top:
            print("(sem atividade acima do limiar)")


if __name__ == "__main__":
    main()
