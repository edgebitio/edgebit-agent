#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod vmlinux;
use vmlinux::{trace_event_raw_sys_enter, trace_event_raw_sys_exit, open_how};

const ENOENT: i64 = 2;

use aya_bpf::{
    macros::{tracepoint, map},
    programs::TracePointContext,
    maps::{HashMap, PerfEventArray},
    cty::{c_ulong, c_long},
    helpers::*,
    bindings::BPF_ANY,
};
//use aya_log_ebpf::info;

use common_defs::*;

#[repr(C)]
struct OpenInflightEntry {
    filename: c_ulong,
    flags: c_ulong,
}

const INFLIGHT_MAX: u32 = 64;

#[map(name = "OPEN_INFLIGHT")]
static OPEN_INFLIGHT: HashMap<u32, OpenInflightEntry> =
    HashMap::with_max_entries(INFLIGHT_MAX, 0);

#[map(name = "EVENTS")]
static EVENTS: PerfEventArray<EvtOpen> =
    PerfEventArray::<EvtOpen>::with_max_entries(1024, 0);

#[inline(always)]
unsafe fn ctx_as<T>(ctx: &TracePointContext) -> *const T {
    use aya_bpf::BpfContext;
    ctx.as_ptr() as *const T
}

#[tracepoint(name="enter_creat")]
pub fn enter_creat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_enter = unsafe { &*ctx_as(&ctx) };

    match try_enter_open(tp.args[0], 0) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name="exit_creat")]
pub fn exit_creat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name="enter_open")]
pub fn enter_open(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_enter = unsafe { &*ctx_as(&ctx) };

    match try_enter_open(tp.args[0], tp.args[1]) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name="exit_open")]
pub fn exit_open(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name="enter_openat")]
pub fn enter_openat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_enter = unsafe { &*ctx_as(&ctx) };

    match try_enter_open(tp.args[1], tp.args[2]) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name="exit_openat")]
pub fn exit_openat(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
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

#[tracepoint(name="exit_openat2")]
pub fn exit_openat2(ctx: TracePointContext) -> u32 {
    let tp: &trace_event_raw_sys_exit = unsafe { &*ctx_as(&ctx) };

    match try_exit_open(&ctx, tp.ret) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

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

fn try_exit_open(ctx: &TracePointContext, ret: c_long) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    if ret == -ENOENT {
        _ = OPEN_INFLIGHT.remove(&pid);
        return Ok(0)
    }

    if let Some(entry) = unsafe { OPEN_INFLIGHT.get(&pid) } {
        let mut evt = EvtOpen::new();
        _ = unsafe { bpf_probe_read_user_str_bytes(entry.filename as *const u8, &mut evt.filename[..]) }
            .map_err(|_| 1u32)?;

        evt.flags = entry.flags as u32;
        evt.ret = ret as i32;
        evt.cgroup = unsafe { bpf_get_current_cgroup_id() } as u64;

        EVENTS.output(ctx, &evt, 0);

        _ = OPEN_INFLIGHT.remove(&pid);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
