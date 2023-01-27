//#include <linux/errno.h>

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_core_read.h>     /* for BPF CO-RE helpers */
#include <bpf/bpf_tracing.h>       /* for getting kprobe arguments */

#include "maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EVENTS_RING_SIZE 8192
#define NAME_MAX 256
#define INFLIGHT_MAX 64
#define EVT_OPEN 1

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define MINORBITS 20

// BPF_RING_BUF(events, EVENTS_RING_SIZE);
BPF_PERF_EVENT_ARRAY(events);

static inline int major(u32 dev) {
    return dev >> MINORBITS;
}

struct evt_open {
    u64 cgroup;
    u64 dev;
    u64 ino;
};

static struct file* get_file(int fd) {
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    struct fdtable *fdt = BPF_CORE_READ(current, files, fdt);
    unsigned max_fds = BPF_CORE_READ(fdt, max_fds);
    struct file **files = BPF_CORE_READ(fdt, fd);
    struct file* f = NULL;
    if (bpf_probe_read_kernel(&f, sizeof(f), &files[fd]) < 0) {
        bpf_printk("probe_read err: files: %lx, max=%u, fd=%d", (u64)files, max_fds, fd);
        return NULL;
    }
    return f;
}

/*
static int enter_open(const char *filename, int flags) {
    struct open_inflight_entry entry = {};
    u32 pid = (u32) bpf_get_current_pid_tgid();

    entry.fname = filename;
    entry.flags = flags;
    bpf_map_update_elem(&open_inflight, &pid, &entry, 0);

    return 0;
}
*/

static int do_exit_open(void *ctx, int rc) {
    if (rc < 0)
        return 0;

    struct evt_open evt;
    struct file* f = get_file(rc);
    if (!f) {
        bpf_printk("error get_file");
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(f, f_inode);
    umode_t mode = BPF_CORE_READ(inode, i_mode);
    if (!S_ISREG(mode)) {
        // only report on regular files
        return 0;
    }

    dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
    if (major(dev) == 0) {
        // special dev (proc, sys)
        return 0;
    }

    evt.dev = dev;
    evt.ino = BPF_CORE_READ(inode, i_ino);
    evt.cgroup = bpf_get_current_cgroup_id();

    //bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

/*
SEC("tp/syscalls/sys_enter_creat")
int tracepoint__syscalls__sys_enter_creat(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[0];

    return enter_open(filename, 0);
}
*/

SEC("tp/syscalls/sys_exit_creat")
int exit_creat(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

/*
SEC("tp/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[0];
    int flags = tp->args[1];

    return enter_open(filename, flags);
}
*/

SEC("tp/syscalls/sys_exit_open")
int exit_open(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

/*
SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[1];
    int flags = tp->args[2];

    return enter_open(filename, flags);
}
*/

SEC("tp/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

/*
SEC("tp/syscalls/sys_enter_openat2")
int tracepoint__syscalls__sys_enter_openat2(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[1];
    struct open_how *how = (struct open_how *) tp->args[2];

    return enter_open(filename, BPF_CORE_READ(how, flags));
}
*/

SEC("tp/syscalls/sys_exit_openat2")
int exit_openat2(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}
