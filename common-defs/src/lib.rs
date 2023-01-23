#![no_std]

use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct EvtOpen {
    pub cgroup: u64,
    pub dev: u64,
    pub ino: u64,
}

impl EvtOpen {
    pub fn new() -> Self {
        Self {
            cgroup: 0u64,
            dev: 0u64,
            ino: 0u64,
        }
    }
}

impl TryFrom<&[u8]> for EvtOpen {
    type Error = ();

    fn try_from(buf: &[u8]) -> Result<Self, ()> {
        let sz = core::mem::size_of::<EvtOpen>();
        if buf.len() < sz {
            return Err(())
        }

        let evt: &EvtOpen = bytemuck::from_bytes(&buf[..sz]);

        Ok(*evt)
    }
}