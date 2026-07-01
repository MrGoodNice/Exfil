use aya_ebpf::{macros::map, maps::RingBuf};

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
