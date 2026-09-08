#!/usr/bin/env python3
from bcc import BPF
from datetime import datetime
import pwd

program = r"""
#define TASK_COMM_LEN 16

struct dogadjaj_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[128];
};

BPF_PERF_OUTPUT(dogadjaji);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct dogadjaj_t d = {};

    d.pid = bpf_get_current_pid_tgid() >> 32;
    d.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&d.comm, sizeof(d.comm));
    bpf_probe_read_user_str(&d.fname, sizeof(d.fname), (void *)args->filename);

    dogadjaji.perf_submit(args, &d, sizeof(d));
    return 0;
}
"""

b = BPF(text=program)

print("%-13s %-10s %-7s %-16s %s" % ("VREME", "KORISNIK", "PID", "RODITELJ", "KOMANDA"))

def obradi(cpu, data, size):
    d = b["dogadjaji"].event(data)
    print("%-13s %-10s %-7d %-16s %s" % (
        datetime.now().strftime("%H:%M:%S.%f")[:12],
        pwd.getpwuid(d.uid).pw_name,
        d.pid,
        d.comm.decode(),
        d.fname.decode(),
    ))

b["dogadjaji"].open_perf_buffer(obradi)

while True:
    b.perf_buffer_poll()
