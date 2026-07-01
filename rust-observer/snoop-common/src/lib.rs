#![no_std]

pub const OBSERVER_NAME: &str = "exfil-analyzer-rust-observer";

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BringupEvent {
    pub pid: u32,
    pub tid: u32,
    pub counter: u64,
    pub timestamp_ns: u64,
}
