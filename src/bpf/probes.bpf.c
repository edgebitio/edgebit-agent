#if defined(__TARGET_ARCH_x86)
#    include "vmlinux-x86_64.h"
#elif defined(__TARGET_ARCH_arm64)
#    include "vmlinux-aarch64.h"
#else
#    error "Unsupported architecture"
#endif

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

#define SB_RDONLY     1    /* Mount read-only */
#define SB_NOSUID     2    /* Ignore suid and sgid bits */
#define SB_NODEV     4    /* Disallow access to device special files */
#define SB_NOEXEC     8    /* Disallow program execution */
#define SB_SYNCHRONOUS    16    /* Writes are synced at once */
#define SB_MANDLOCK    64    /* Allow mandatory locks on an FS */
#define SB_DIRSYNC    128    /* Directory modifications are synchronous */
#define SB_NOATIME    1024    /* Do not update access times. */
#define SB_NODIRATIME    2048    /* Do not update directory access times */
#define SB_SILENT    32768
#define SB_POSIXACL    (1<<16)    /* VFS does not apply the umask */
#define SB_KERNMOUNT    (1<<22) /* this is a kern_mount call */
#define SB_I_VERSION    (1<<23) /* Update inode I_version field */
#define SB_LAZYTIME    (1<<25) /* Update the on-disk [acm]times lazily */

/* These sb flags are internal to the kernel */
#define SB_SUBMOUNT     (1<<26)
#define SB_NOREMOTELOCK    (1<<27)
#define SB_NOSEC    (1<<28)
#define SB_BORN        (1<<29)
#define SB_ACTIVE    (1<<30)
#define SB_NOUSER    (1<<31)

#define MAX_PATH 256

// For working with tracepoint's dynamic array
#define DYN_ARRAY(s, member) ( ((void*)(s)) + ((s)->__data_loc_##member & 0xffff) )

// strcpy into an array
#define KCOPY_STR(dst, src) (bpf_probe_read_kernel_str((dst), sizeof(dst), (src)))
#define UCOPY_STR(dst, src) (bpf_probe_read_user_str((dst), sizeof(dst), (src)))

// Using bpf_probe_printk/bpf_printk introduces symbols into .rodata section that
// libbpf has problems loading into older kernels. The hack is to only enable
// this macro on newer kernels (for development)
#define BPF_PRINTK(fmt, ...) //bpf_trace_printk((fmt), sizeof(fmt), ##__VA_ARGS__)

struct open_inflight_entry {
    const char* filename;
    u32 flags;
};

struct evt_open {
    u32 tgid;
    char filename[MAX_PATH];
};

struct process_info {
    bool zombie;
    char cgroup[255];
};

// Keeps track of parameters passed into variants of open() syscalls
// to be used at the end of the syscall (exit hook)
BPF_HASH(open_inflight, pid_t, struct open_inflight_entry, 1024);

// Keeps tracks of per process information for userspace to correlate
// the PID to cgroup
BPF_HASH(pid_to_info, pid_t, struct process_info, 1024);

// Open file events (either ring buffer or perf event array will be used depending on kernel version)
BPF_RING_BUF(rb_open_events, 256*1024);
BPF_PERF_EVENT_ARRAY(pb_open_events);

// Process exit events (either ring buffer or perf event array will be used depending on kernel version)
BPF_RING_BUF(rb_zombie_events, 4*1024);
BPF_PERF_EVENT_ARRAY(pb_zombie_events);

static inline bool is_abs(const char *filename) {
    return filename && *filename == '/';
}

static int fill_cgroup_name(char *buf, size_t buf_len) {
    struct task_struct *current = (struct task_struct*) bpf_get_current_task();
    struct cgroup_subsys_state **subsys_arr = BPF_CORE_READ(current, cgroups, subsys);
    struct cgroup_subsys_state *subsys = subsys_arr[0];
    const char *name = BPF_CORE_READ(subsys, cgroup, kn, name);

    if (name) {
        if (bpf_probe_read_kernel_str(buf, buf_len, name) < 0) {
            BPF_PRINTK("probe_read_kernel_str error");
            return -1;
        }
    } else {
        buf[0] = '\0';
        BPF_PRINTK("cgroup name is NULL");
    }

    return 0;
}

__attribute__((noinline))
static void ensure_cgroup_mapping(pid_t tgid) {
    struct process_info *existing = bpf_map_lookup_elem(&pid_to_info, &tgid);
    if (!existing || existing->zombie) {
        // It should never really happen but it's possible for the process to exit
        // and the PID to be recycled before the userspace has a chance to clean up
        // the map. In that case, the zombie flag will be set and we grab the new cgroup name.

        struct process_info proc_info;
        __builtin_memset(&proc_info, 0, sizeof(proc_info));

        if (fill_cgroup_name(proc_info.cgroup, sizeof(proc_info.cgroup)) < 0)
            return;

        bpf_map_update_elem(&pid_to_info, &tgid, &proc_info, BPF_ANY);
    }
}

static int do_enter_open(const char *filename, int flags) {
    struct open_inflight_entry entry = {};
    u32 pid = (u32) bpf_get_current_pid_tgid();

    entry.filename = filename;
    entry.flags = flags;
    bpf_map_update_elem(&open_inflight, &pid, &entry, 0);

    return 0;
}

__attribute__((noinline))
static void emit_open_event(void *ctx, pid_t tgid, const char *filename, bool user) {
    struct evt_open evt;
    __builtin_memset(&evt, 0, sizeof(evt));

    evt.tgid = tgid;

    if (user) {
        if (UCOPY_STR(evt.filename, filename) < 0) {
            BPF_PRINTK("emit_open_event: probe_read_user_str error of %lx", (unsigned long)filename);
            return;
        }
    } else {
        if (KCOPY_STR(evt.filename, filename) < 0) {
            BPF_PRINTK("emit_open_event: probe_read_kernel_str error of %lx", (unsigned long)filename);
            return;
        }
    }  

    // Only care about absolute paths
    if (!is_abs(evt.filename))
        return;

    if (bpf_core_type_exists(struct bpf_ringbuf)) {
        if (bpf_ringbuf_output(&rb_open_events, &evt, sizeof(evt), 0) < 0) {
            BPF_PRINTK("error sending evt_open");
        }
    } else {
        if (bpf_perf_event_output(ctx, &pb_open_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt)) < 0) {
            BPF_PRINTK("error sending evt_open");
        }
    }
}

static int do_exit_open(void *ctx, int rc) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = (u32) pid_tgid;
    pid_t tgid = (u32) (pid_tgid >> 32);

    if (rc < 0) {
        bpf_map_delete_elem(&open_inflight, &pid);
        return 0;
    }

    struct open_inflight_entry *entry = bpf_map_lookup_elem(&open_inflight, &pid);
    if (!entry)
        return 0;

    ensure_cgroup_mapping(tgid);

    emit_open_event(ctx, tgid, entry->filename, true);

    return 0;
}

#if defined(__TARGET_ARCH_x86)
SEC("tp/syscalls/sys_enter_creat")
int enter_creat(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[0];

    return do_enter_open(filename, 0);
}

SEC("tp/syscalls/sys_exit_creat")
int exit_creat(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

SEC("tp/syscalls/sys_enter_open")
int enter_open(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[0];
    int flags = tp->args[1];

    return do_enter_open(filename, flags);
}

SEC("tp/syscalls/sys_exit_open")
int exit_open(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}
#endif //_TARGET_ARCH_x86

SEC("tp/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[1];
    int flags = tp->args[2];

    return do_enter_open(filename, flags);
}

SEC("tp/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

SEC("tp/syscalls/sys_enter_openat2")
int enter_openat2(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[1];
    struct open_how *how = (struct open_how *) tp->args[2];

    return do_enter_open(filename, BPF_CORE_READ(how, flags));
}

SEC("tp/syscalls/sys_exit_openat2")
int exit_openat2(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

SEC("kprobe/setup_new_exec")
int BPF_KPROBE(kprobe__setup_new_exec, struct linux_binprm *bprm) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t tgid = (u32) (pid_tgid >> 32);
    ensure_cgroup_mapping(tgid);

    struct evt_open evt;
    __builtin_memset(&evt, 0, sizeof(evt));

    const char *filename = BPF_CORE_READ(bprm, filename);
    if (!filename) {
        BPF_PRINTK("setup_new_exec: filename is NULL");
        return 0;
    }

    emit_open_event(ctx, tgid, filename, false);

    // There are cases where the interpreter is different than the filename.
    // e.g. for bash scripts. Report both.
    const char *interp = BPF_CORE_READ(bprm, interp);
    if (interp != filename) {
        if (!interp) {
            BPF_PRINTK("setup_new_exec: interp is NULL");
            return 0;
        }

        emit_open_event(ctx, tgid, interp, false);
    }

    return 0;
}

static int cgroup_migrate_task(struct trace_event_raw_cgroup_migrate *tp) {
    pid_t pid = tp->pid;
    struct process_info proc_info;
    __builtin_memset(&proc_info, 0, sizeof(proc_info));

    const char *cgrp = (const char*) DYN_ARRAY(tp, dst_path);

    if (KCOPY_STR(&proc_info.cgroup, cgrp) < 0) {
        BPF_PRINTK("cgroup_migrate_task: cgroup name read failed");
        return 0;
    }

    bpf_map_update_elem(&pid_to_info, &pid, &proc_info, BPF_ANY);

    return 0;
}

SEC("tp/cgroup/cgroup_attach_task")
int cgroup_attach_task(struct trace_event_raw_cgroup_migrate *tp) {
    return cgroup_migrate_task(tp);
}

SEC("tp/cgroup/cgroup_transfer_tasks")
int cgroup_transfer_tasks(struct trace_event_raw_cgroup_migrate *tp) {
    return cgroup_migrate_task(tp);
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *tp) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t tgid = pid_tgid >> 32;
    pid_t pid = (pid_t)pid_tgid;

    // only care about the main thread
    if (tgid != pid)
        return 0;

    struct process_info *proc_info = bpf_map_lookup_elem(&pid_to_info, &tgid);
    if (!proc_info)
        return 0;

    // Don't immediately erase from the map as there might still be fsnotify
    // events in-flight to the userspace and it'll need the process info.
    proc_info->zombie = true;

    // Notify the userspace that a process exited so it has a chance to clean up
    // the pid_to_info map.
    if (bpf_core_type_exists(struct bpf_ringbuf)) {
        if (bpf_ringbuf_output(&rb_zombie_events, &pid, sizeof(pid), 0) < 0) {
            BPF_PRINTK("error sending zombie event");
        }
    } else {
        if (bpf_perf_event_output(tp, &pb_zombie_events, BPF_F_CURRENT_CPU, &pid, sizeof(pid)) < 0) {
            BPF_PRINTK("error sending zombie event");
        }
    }

    return 0;
}

SEC("kprobe/fsnotify")
int BPF_KPROBE(fsnotify) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t tgid = (pid_t) (pid_tgid >> 32);

    ensure_cgroup_mapping(tgid);

    return 0;
}