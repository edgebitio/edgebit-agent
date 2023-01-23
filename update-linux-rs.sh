#!/bin/sh

aya-tool generate \
	trace_entry \
	trace_event_raw_sys_enter \
	trace_event_raw_sys_exit \
	open_how \
	task_struct \
	fdtable \
	file \
	super_block \
> ebpf/src/vmlinux.rs
