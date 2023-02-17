use bytemuck::{Pod, Zeroable};

const CGROUP_NAME_LEN: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod)]
pub struct EvtOpen {
    pub cgroup: u64,
    pub dev: u64,
    pub ino: u64,
    pub cgroup_name: [u8; CGROUP_NAME_LEN],
}

impl EvtOpen {
    pub fn new() -> Self {
        Self {
            cgroup: 0u64,
            dev: 0u64,
            ino: 0u64,
            cgroup_name: [0u8; CGROUP_NAME_LEN],
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

        let evt: EvtOpen = bytemuck::pod_read_unaligned(&buf[..sz]);
        Ok(evt)
    }
}
