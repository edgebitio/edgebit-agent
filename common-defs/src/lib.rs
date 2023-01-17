#![no_std]

use bytemuck::{Pod, Zeroable};

const MAX_PATH: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct EvtOpen {
    pub cgroup: u64,
    pub flags: u32,
    pub ret: i32,
    pub filename: [u8; MAX_PATH],
}

impl EvtOpen {
    pub fn new() -> Self {
        Self {
            cgroup: 0u64,
            flags: 0u32,
            ret: 0i32,
            filename: [0u8; MAX_PATH],
        }
    }
}
