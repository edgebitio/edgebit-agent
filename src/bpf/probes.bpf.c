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

#define SB_RDONLY	 1	/* Mount read-only */
#define SB_NOSUID	 2	/* Ignore suid and sgid bits */
#define SB_NODEV	 4	/* Disallow access to device special files */
#define SB_NOEXEC	 8	/* Disallow program execution */
#define SB_SYNCHRONOUS	16	/* Writes are synced at once */
#define SB_MANDLOCK	64	/* Allow mandatory locks on an FS */
#define SB_DIRSYNC	128	/* Directory modifications are synchronous */
#define SB_NOATIME	1024	/* Do not update access times. */
#define SB_NODIRATIME	2048	/* Do not update directory access times */
#define SB_SILENT	32768
#define SB_POSIXACL	(1<<16)	/* VFS does not apply the umask */
#define SB_KERNMOUNT	(1<<22) /* this is a kern_mount call */
#define SB_I_VERSION	(1<<23) /* Update inode I_version field */
#define SB_LAZYTIME	(1<<25) /* Update the on-disk [acm]times lazily */

/* These sb flags are internal to the kernel */
#define SB_SUBMOUNT     (1<<26)
#define SB_NOREMOTELOCK	(1<<27)
#define SB_NOSEC	(1<<28)
#define SB_BORN		(1<<29)
#define SB_ACTIVE	(1<<30)
#define SB_NOUSER	(1<<31)

#define MINORBITS 20

// For working with tracepoint's dynamic array
#define dyn_array(s, member) ( ((void*)s) + s->__data_loc_##member )

// BPF_RING_BUF(events, EVENTS_RING_SIZE);
// BPF_PERF_EVENT_ARRAY(events);

/*
static inline int major(u32 dev) {
    return dev >> MINORBITS;
}

struct evt_open {
    u64 cgroup;
    u64 dev;
    u64 ino;
    char cgroup_name[128];
};
*/

struct process_info {
    bool zombie;
    char cgroup[255];
};

BPF_HASH(pid_to_info, pid_t, struct process_info, 1024);

BPF_PERF_EVENT_ARRAY(zombie_events);

/*
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
*/

static int fill_cgroup_name(char *buf, size_t buf_len) {
    struct task_struct *current = (struct task_struct*) bpf_get_current_task();
    struct cgroup_subsys_state **subsys_arr = BPF_CORE_READ(current, cgroups, subsys);
    struct cgroup_subsys_state *subsys = subsys_arr[0];
    const char *name = BPF_CORE_READ(subsys, cgroup, kn, name);

    if (name) {
        if (bpf_probe_read_kernel_str(buf, buf_len, name) < 0) {
            bpf_printk("probe_read_kernel_str error");
            return -1;
        }

        if (buf[0] == '\0') {
            bpf_printk("cgroup_name is empty");
        }
    } else {
        buf[0] = '\0';
        bpf_printk("cgroup name is NULL");
    }

    return 0;
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

static int do_exit_open(void *ctx, int rc) {
    if (rc < 0)
        return 0;

    struct evt_open evt;
    __builtin_memset(&evt, 0, sizeof(evt));

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

    struct super_block *sb  = BPF_CORE_READ(inode, i_sb);
    unsigned long s_flags = BPF_CORE_READ(sb, s_flags);

    if (s_flags & SB_NODEV) {
        // ignore special dev (proc, sys).
        // This does not match overlayfs2 but does filter out squashfs (used by snap)
        return 0;
    }

    dev_t dev = BPF_CORE_READ(sb, s_dev);

    evt.dev = dev;
    evt.ino = BPF_CORE_READ(inode, i_ino);

    if (fill_cgroup_name(evt.cgroup_name, sizeof(evt.cgroup_name)) <  0)
        return 0;

    //bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt)) < 0) {
        bpf_printk("error sending event");
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_creat")
int tracepoint__syscalls__sys_enter_creat(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[0];

    return enter_open(filename, 0);
}

SEC("tp/syscalls/sys_exit_creat")
int exit_creat(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

SEC("tp/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[0];
    int flags = tp->args[1];

    return enter_open(filename, flags);
}

SEC("tp/syscalls/sys_exit_open")
int exit_open(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[1];
    int flags = tp->args[2];

    return enter_open(filename, flags);
}

SEC("tp/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

SEC("tp/syscalls/sys_enter_openat2")
int tracepoint__syscalls__sys_enter_openat2(struct trace_event_raw_sys_enter *tp) {
    const char *filename = (const char*) tp->args[1];
    struct open_how *how = (struct open_how *) tp->args[2];

    return enter_open(filename, BPF_CORE_READ(how, flags));
}

SEC("tp/syscalls/sys_exit_openat2")
int exit_openat2(struct trace_event_raw_sys_exit *tp) {
    return do_exit_open(tp, tp->ret);
}

SEC("kprobe/setup_new_exec")
int BPF_KPROBE(kprobe__setup_new_exec, struct linux_binprm *bprm) {
    struct file *f = BPF_CORE_READ(bprm, file);
    if (!f)
        return 0;

    struct inode *inode = BPF_CORE_READ(f, f_inode);

    dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
    if (major(dev) == 0) {
        // special dev (proc, sys)
        return 0;
    }

    struct evt_open evt;
    __builtin_memset(&evt, 0, sizeof(evt));

    evt.dev = dev;
    evt.ino = BPF_CORE_READ(inode, i_ino);

    if (fill_cgroup_name(evt.cgroup_name, sizeof(evt.cgroup_name)) <  0)
        return 0;

    if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt)) < 0) {
        bpf_printk("error sending event");
    }

    return 0;
}
*/

static int cgroup_migrate_task(struct trace_event_raw_cgroup_migrate *tp) {
    pid_t pid = tp->pid;
    struct process_info proc_info;
    __builtin_memset(&proc_info, 0, sizeof(proc_info));

    const char *cgrp = (const char*) dyn_array(tp, dst_path);

    if (bpf_probe_read_kernel_str(&proc_info.cgroup, sizeof(proc_info.cgroup), cgrp) < 0) {
        bpf_printk("tp/cgroup_attach_task: cgroup name read failed");
        return 0;
    }

    bpf_map_update_elem(&pid_to_info, &pid, &proc_info, BPF_ANY);

    bpf_printk("attach: %u to %s", pid, proc_info.cgroup);
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

/*
SEC("tp/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork* tp) {
    struct cgroup_name cgrp_name;
    __builtin_memset(&cgrp_name, 0, sizeof(cgrp_name));

    pid_t parent_pid = tp->parent_pid;
    pid_t child_pid = tp->child_pid;

    struct cgroup_name *name = bpf_map_lookup_elem(&pid_to_info, &parent_pid);
    if (name) {
        if (bpf_probe_read_kernel_str(&cgrp_name.buf, sizeof(cgrp_name.buf), name) < 0) {
            bpf_printk("bpf_probe_read_kernel_str failed");
            return 0;
        }

    } else {
        // have to get it the complicated way
        if (fill_cgroup_name(cgrp_name.buf, sizeof(cgrp_name.buf)) < 0)
            return 0;
    }

    bpf_map_update_elem(&pid_to_info, &child_pid, &cgrp_name.buf, BPF_ANY);

    bpf_printk("fork: %u to %s", child_pid, cgrp_name.buf);
    return 0;
}
*/

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
    if (bpf_perf_event_output(tp, &zombie_events, BPF_F_CURRENT_CPU, &pid, sizeof(pid)) < 0) {
        bpf_printk("error sending zombie event");
    }

    bpf_printk("exit: %u", tgid);
    return 0;
}

SEC("kprobe/fsnotify")
int BPF_KPROBE(fsnotify) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t tgid = pid_tgid >> 32;

    struct process_info *existing = bpf_map_lookup_elem(&pid_to_info, &tgid);
    if (!existing || existing->zombie) {
        // It should never really happen but it's possible for the process to exit
        // and the PID to be recycled before the userspace has a chance to clean up
        // the map. In that case, the zombie flag will be set and we grab the new cgroup name.

        struct process_info proc_info;
        __builtin_memset(&proc_info, 0, sizeof(proc_info));

        if (fill_cgroup_name(&proc_info.cgroup, sizeof(proc_info.cgroup)) < 0)
            return 0;

        bpf_map_update_elem(&pid_to_info, &tgid, &proc_info, BPF_ANY);

        bpf_printk("fsnotify: %u to %s", tgid, proc_info.cgroup);
    }

    return 0;
}
