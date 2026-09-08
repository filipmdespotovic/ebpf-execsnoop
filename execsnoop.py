#!/usr/bin/env python3
from bcc import BPF
from datetime import datetime
import pwd

program = r"""
#define TASK_COMM_LEN 16

struct zapamceno_t {
    u64 ts;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[128];
};

struct dogadjaj_t {
    u32 pid;
    u32 uid;
    int ret;
    u64 trajanje;
    char comm[TASK_COMM_LEN];
    char fname[128];
};

BPF_HASH(u_toku, u32, struct zapamceno_t);
BPF_PERF_OUTPUT(dogadjaji);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct zapamceno_t z = {};
    z.ts  = bpf_ktime_get_ns();
    z.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&z.comm, sizeof(z.comm));
    bpf_probe_read_user_str(&z.fname, sizeof(z.fname), (void *)args->filename);

    u_toku.update(&pid, &z);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct zapamceno_t *z = u_toku.lookup(&pid);
    if (z == NULL)
        return 0;

    struct dogadjaj_t d = {};
    d.pid      = pid;
    d.uid      = z->uid;
    d.ret      = args->ret;
    d.trajanje = bpf_ktime_get_ns() - z->ts;
    __builtin_memcpy(&d.comm, z->comm, sizeof(d.comm));
    __builtin_memcpy(&d.fname, z->fname, sizeof(d.fname));

    dogadjaji.perf_submit(args, &d, sizeof(d));
    u_toku.delete(&pid);
    return 0;
}
"""

b = BPF(text=program)

GRESKE = {-1: "EPERM", -2: "ENOENT", -8: "ENOEXEC", -13: "EACCES", -20: "ENOTDIR"}

def korisnik(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)

print("%-13s %-10s %-7s %-16s %-9s %-10s %s" %
      ("VREME", "KORISNIK", "PID", "RODITELJ", "ISHOD", "TRAJANJE", "KOMANDA"))

def obradi(cpu, data, size):
    d = b["dogadjaji"].event(data)
    ishod = "OK" if d.ret == 0 else GRESKE.get(d.ret, str(d.ret))
    print("%-13s %-10s %-7d %-16s %-9s %-10.1f %s" % (
        datetime.now().strftime("%H:%M:%S.%f")[:12],
        korisnik(d.uid),
        d.pid,
        d.comm.decode("utf-8", "replace"),
        ishod,
        d.trajanje / 1000.0,
        d.fname.decode("utf-8", "replace"),
    ))

b["dogadjaji"].open_perf_buffer(obradi)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
