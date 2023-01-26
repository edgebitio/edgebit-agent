#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod vmlinux;
use vmlinux::{trace_event_raw_sys_exit};
use vmlinux::{task_struct, files_struct, fdtable, file, inode, super_block, umode_t};

use aya_bpf::{
    macros::{tracepoint, map},
    programs::TracePointContext,
    maps::{PerfEventArray},
    cty::{c_long, c_void},
    helpers::*,
};
//use aya_log_ebpf::info;

use memoffset::{offset_of, raw_field};

use common_defs::*;

const S_IFMT: u32  = 0o170000;
const S_IFREG: u16 = 0o100000;

const MINORBITS: usize = 20;

/*
#[repr(C)]
struct OpenInflightEntry {
    filename: c_ulong,
    flags: c_ulong,
}

const INFLIGHT_MAX: u32 = 64;

#[map(name = "OPEN_INFLIGHT")]
static OPEN_INFLIGHT: HashMap<u32, OpenInflightEntry> =
    HashMap::with_max_entries(INFLIGHT_MAX, 0);
*/

#[map(name = "EVENTS")]
static EVENTS: PerfEventArray<EvtOpen> =
    PerfEventArray::<EvtOpen>::with_max_entries(1024, 0);

#[inline(always)]
unsafe fn ctx_as<T>(ctx: &TracePointContext) -> *const T {
    use aya_bpf::BpfContext;
    ctx.as_ptr() as *const T
}

/*
#[tracepoint(name="enter_creat")]
pub fn enter_creat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_enter = unsafe { &*ctx_as(&ctx) };

    match try_enter_open(tp.args[0], 0) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
*/

#[tracepoint(name="exit_creat")]
pub fn exit_creat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/*
#[tracepoint(name="enter_open")]
pub fn enter_open(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_enter = unsafe { &*ctx_as(&ctx) };

    match try_enter_open(tp.args[0], tp.args[1]) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
*/

#[tracepoint(name="exit_open")]
pub fn exit_open(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/*
#[tracepoint(name="enter_openat")]
pub fn enter_openat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_enter = unsafe { &*ctx_as(&ctx) };

    match try_enter_open(tp.args[1], tp.args[2]) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
*/

#[tracepoint(name="exit_openat")]
pub fn exit_openat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/*
#[
tracepoint(name="enter_openat2")]
pub fn enter_openat2(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_enter = unsafe { &*ctx_as(&ctx) };
    let how: &open_how = unsafe { &*(tp.args[2] as *const open_how) };
    match unsafe { bpf_probe_read_user::<c_ulong>(&how.flags as *const c_ulong) } {
        Ok(flags) => {
            match try_enter_open(tp.args[1], flags) {
                Ok(ret) => ret,
                Err(ret) => ret,
            }
        },
        Err(err) => err as u32,
    }
}
*/

#[tracepoint(name="exit_openat2")]
pub fn exit_openat2(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/*
fn try_enter_open(filename: c_ulong, flags: c_ulong) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    let entry = OpenInflightEntry {
        filename,
        flags,
    };

    OPEN_INFLIGHT.insert(&pid, &entry, BPF_ANY.into())
        .map_err(|_| 1u32)?;

    Ok(0)
}
*/

fn try_exit_open(ctx: &TracePointContext, ret: c_long) -> Result<u32, u32> {
    /*
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    if ret < 0 {
        _ = OPEN_INFLIGHT.remove(&pid);
        return Ok(0)
    }

    if let Some(entry) = unsafe { OPEN_INFLIGHT.get(&pid) } {
    */
/*
    let mut evt = EvtOpen::new();
    let f = unsafe { get_file(ret as u32).or_else(|e| { bpf_printk!(b"get_file err"); Err(e) })? };

    //_ = unsafe { bpf_probe_read_user_str_bytes(entry.filename as *const u8, &mut evt.filename[..]) }
    //    .map_err(|_| 1u32)?;

    let inode = get_inode(f).or_else(|e| unsafe { bpf_printk!(b"get_inode err"); Err(e) })?;
    let mode = get_mode(inode).or_else(|e| unsafe { bpf_printk!(b"get_mode err"); Err(e) })?;
    if (mode & S_IFREG) == 0 {
        // only report on regular files
        unsafe { bpf_printk!(b"not a regular file"); }
        return Ok(0);
    }
    let sb = get_sb(inode).or_else(|e| unsafe { bpf_printk!(b"get_sb err"); Err(e) })?;

    evt.dev = unsafe { read_kernel(&((*sb).s_dev)) }? as u64;
    if get_major(evt.dev) == 0 {
        // special dev (proc, sys)
        unsafe { bpf_printk!(b"special dev"); }
        return Ok(0);
    }
    evt.ino = unsafe { read_kernel(&((*inode).i_ino)) }?;
    evt.cgroup = unsafe { bpf_get_current_cgroup_id() } as u64;

    unsafe { bpf_printk!(b"sending event"); }
    EVENTS.output(ctx, &evt, 0);

    //_ = OPEN_INFLIGHT.remove(&pid);
*/
    let offset = offset_of!(task_struct, files) as u32;
    unsafe { bpf_printk!(b"offset = %u", offset); }
    Ok(0)
}

// Assumes that fd is valid
unsafe fn get_file(fd: u32) -> Result<*const file, u32> {
    let current = unsafe { bpf_get_current_task() as *const task_struct };
    let files = get_files(current).map_err(|e| unsafe { bpf_printk!(b"get_files"); e })?;
    let fdt = get_fdtable(files).map_err(|e| unsafe { bpf_printk!(b"get_fdtable"); e })?;
    let fds = read_kernel(&((*fdt).fd)).map_err(|e| unsafe { bpf_printk!(b"fd[]"); e })?;
    let f = read_kernel(fds.add(fd as usize)).map_err(|e| unsafe { bpf_printk!(b"fd[i]"); e })?;

    Ok(f)
}

#[inline(always)]
fn get_files(task: *const task_struct) -> Result<*const files_struct, u32> {
    let offset = offset_of!(task_struct, files) as u32;
    unsafe { bpf_printk!(b"offset = %u", offset); }
    let files = unsafe { read_kernel(raw_field!(task, task_struct, files)) }?;
    Ok(files as *const files_struct)
}

#[inline(always)]
fn get_fdtable(files: *const files_struct) -> Result<*const fdtable, u32> {
    unsafe { bpf_printk!(b"files: %lx", (files as *const c_void)); };
    let fdt = unsafe { &((*files).fdt) as *const *mut fdtable as *const c_void };
    unsafe { bpf_printk!(b"fdt: %lx", fdt); };
    let fdt = unsafe { read_kernel(&((*files).fdt)) }?;
    Ok(fdt as *const fdtable)
}

#[inline(always)]
fn get_inode(f: *const file) -> Result<*const inode, u32> {
    let ino = unsafe { read_kernel(&((*f).f_inode))}?;
    Ok(ino  as *const inode)
}

#[inline(always)]
fn get_mode(n: *const inode) -> Result<umode_t, u32> {
    let mode = unsafe { read_kernel(&((*n).i_mode))}?;
    Ok(mode)
}

#[inline(always)]
fn get_sb(n: *const inode) -> Result<*const super_block, u32> {
    let sb = unsafe { read_kernel(&((*n).i_sb))}?;
    Ok(sb as *const super_block)
}

#[inline(always)]
unsafe fn read_kernel<T>(src: *const T) -> Result<T, u32> {
    bpf_probe_read_kernel(src)
        .map_err(|e| e as u32)
}

#[inline(always)]
fn get_major(dev: u64) -> u16 {
    (dev >> MINORBITS) as u16
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}