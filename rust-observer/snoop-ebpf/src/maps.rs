use aya_ebpf::{macros::map, maps::RingBuf};

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);
