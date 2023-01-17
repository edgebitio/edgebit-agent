#!/bin/sh

aya-tool generate \
	trace_entry \
	trace_event_raw_sys_enter \
	trace_event_raw_sys_exit \
	open_how \
> ebpf/src/vmlinux.rs
