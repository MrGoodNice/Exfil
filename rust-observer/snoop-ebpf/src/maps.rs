use aya_ebpf::{
    macros::map,
    maps::{LruHashMap, RingBuf},
};
use snoop_common::ConnectArgs;

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
pub static CONNECT_ARGS: LruHashMap<u64, ConnectArgs> = LruHashMap::with_max_entries(4096, 0);
