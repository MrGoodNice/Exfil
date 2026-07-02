#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

#[cfg(target_arch = "bpf")]
mod maps;

#[cfg(target_arch = "bpf")]
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, tracepoint},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
    EbpfContext,
};
#[cfg(target_arch = "bpf")]
use snoop_common::{
    ConnectArgs, SensorEvent, EVENT_KIND_CONNECT, EVENT_KIND_EXECVE, EVENT_KIND_EXIT,
    EVENT_KIND_OPENAT, PROTO_OTHER, PROTO_TCP, SENSOR_AF_INET, SENSOR_AF_INET6, SENSOR_PATH_MAX,
};

#[cfg(target_arch = "bpf")]
use crate::maps::{CONNECT_ARGS, EVENTS};

#[cfg(target_arch = "bpf")]
const AF_INET: u16 = SENSOR_AF_INET;
#[cfg(target_arch = "bpf")]
const AF_INET6: u16 = SENSOR_AF_INET6;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("r0 = 0", "exit", options(noreturn));
    }
}

#[cfg(target_arch = "bpf")]
#[tracepoint(name = "sys_enter_openat", category = "raw_syscalls")]
pub fn sys_enter_openat(ctx: TracePointContext) -> i64 {
    match try_sys_enter_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(target_arch = "bpf")]
#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(ctx: TracePointContext) -> i64 {
    match try_sched_process_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(target_arch = "bpf")]
#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(_ctx: TracePointContext) -> i64 {
    match try_sched_process_exit() {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(target_arch = "bpf")]
#[kprobe(function = "__sys_connect")]
pub fn net_enter_sys_connect(ctx: ProbeContext) -> i64 {
    match try_net_enter_sys_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(target_arch = "bpf")]
#[kretprobe(function = "__sys_connect")]
pub fn net_exit_sys_connect(ctx: RetProbeContext) -> i64 {
    match try_net_exit_sys_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<(), i64> {
    // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/programs/sys_enter.rs:59
    let syscall_nr: i64 = unsafe { ctx.read_at(8) }.map_err(|e| e as i64)?;
    let args: [u64; 6] = unsafe { ctx.read_at(16) }.map_err(|e| e as i64)?;
    let path_ptr = match syscall_nr {
        2 => args[0] as *const u8,         // open(path, ...)
        257 | 437 => args[1] as *const u8, // openat/openat2(dirfd, path, ...)
        _ => return Ok(()),
    };
    if path_ptr.is_null() {
        return Ok(());
    }

    let mut entry = match EVENTS.reserve::<SensorEvent>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let event = entry.as_mut_ptr();
    write_base_event(event, EVENT_KIND_OPENAT);
    let path_len = write_user_path(event, path_ptr);
    unsafe {
        core::ptr::addr_of_mut!((*event).path_len).write(path_len);
    }
    entry.submit(0);
    Ok(())
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn try_sched_process_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = match EVENTS.reserve::<SensorEvent>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let event = entry.as_mut_ptr();
    write_base_event(event, EVENT_KIND_EXECVE);
    let exe_len = write_sched_exec_filename(ctx, event);
    unsafe {
        core::ptr::addr_of_mut!((*event).exe_len).write(exe_len);
    }
    entry.submit(0);
    Ok(())
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn try_sched_process_exit() -> Result<(), i64> {
    let mut entry = match EVENTS.reserve::<SensorEvent>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let event = entry.as_mut_ptr();
    write_base_event(event, EVENT_KIND_EXIT);
    entry.submit(0);
    Ok(())
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn try_net_enter_sys_connect(ctx: &ProbeContext) -> Result<(), i64> {
    // ref: /home/mrg/Desktop/exfil-step-a-refs/kunai/kunai-ebpf/src/probes/connect.rs:15
    let fd: i32 = ctx.arg(0).ok_or(1i64)?;
    let sockaddr_ptr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    if sockaddr_ptr.is_null() {
        return Ok(());
    }
    let mut args = ConnectArgs::empty();
    args.fd = fd;
    if !read_sockaddr(sockaddr_ptr, &mut args) {
        return Ok(());
    }
    let key = bpf_get_current_pid_tgid();
    // ref: /home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/maps/hash_map.rs:152
    let _ = CONNECT_ARGS.insert(&key, &args, 0);
    Ok(())
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn try_net_exit_sys_connect(ctx: &RetProbeContext) -> Result<(), i64> {
    // ref: /home/mrg/Desktop/exfil-step-a-refs/kunai/kunai-ebpf/src/probes/connect.rs:27
    let key = bpf_get_current_pid_tgid();
    // ref: /home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/maps/hash_map.rs:130
    let saved = match unsafe { CONNECT_ARGS.get(&key) } {
        Some(args) => *args,
        None => return Ok(()),
    };
    // ref: /home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/maps/hash_map.rs:158
    let _ = CONNECT_ARGS.remove(&key);

    let mut entry = match EVENTS.reserve::<SensorEvent>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let event = entry.as_mut_ptr();
    write_base_event(event, EVENT_KIND_CONNECT);
    unsafe {
        core::ptr::addr_of_mut!((*event).retval).write(ctx.ret::<i64>().unwrap_or(0));
        core::ptr::addr_of_mut!((*event).fd).write(saved.fd);
        core::ptr::addr_of_mut!((*event).dst_port).write(saved.dst_port);
        core::ptr::addr_of_mut!((*event).dst_family).write(saved.dst_family);
        core::ptr::addr_of_mut!((*event).proto).write(saved.proto);
        core::ptr::addr_of_mut!((*event).dst_ip).write(saved.dst_ip);
    }
    entry.submit(0);
    Ok(())
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn write_base_event(event: *mut SensorEvent, kind: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    unsafe {
        core::ptr::addr_of_mut!((*event).kind).write(kind);
        core::ptr::addr_of_mut!((*event).pid).write(tgid);
        core::ptr::addr_of_mut!((*event).tgid).write(tgid);
        core::ptr::addr_of_mut!((*event).ppid).write(0);
        // ref: /home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/helpers.rs:14
        core::ptr::addr_of_mut!((*event).cgroup_id).write(bpf_get_current_cgroup_id());
        core::ptr::addr_of_mut!((*event).timestamp_ns).write(bpf_ktime_get_ns());
        core::ptr::addr_of_mut!((*event).comm).write(comm);
        core::ptr::addr_of_mut!((*event).path_len).write(0);
        core::ptr::addr_of_mut!((*event).exe_len).write(0);
        core::ptr::addr_of_mut!((*event)._pad).write(0);
        core::ptr::addr_of_mut!((*event).retval).write(0);
        core::ptr::addr_of_mut!((*event).fd).write(0);
        core::ptr::addr_of_mut!((*event).dst_port).write(0);
        core::ptr::addr_of_mut!((*event).dst_family).write(0);
        core::ptr::addr_of_mut!((*event).proto).write(PROTO_OTHER);
        core::ptr::addr_of_mut!((*event)._pad2).write([0; 3]);
        core::ptr::addr_of_mut!((*event).dst_ip).write([0; 16]);
        core::ptr::addr_of_mut!((*event).path).write_bytes(0, 1);
        core::ptr::addr_of_mut!((*event).exe).write_bytes(0, 1);
    }
}

#[cfg(target_arch = "bpf")]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: [u8; 4],
    _zero: [u8; 8],
}

#[cfg(target_arch = "bpf")]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn read_sockaddr(sockaddr_ptr: *const u8, args: &mut ConnectArgs) -> bool {
    // ref: /home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/helpers.rs:122
    let family = match unsafe { bpf_probe_read_user(sockaddr_ptr as *const u16) } {
        Ok(value) => value,
        Err(_) => return false,
    };
    args.dst_family = family;
    args.proto = PROTO_TCP;
    match family {
        AF_INET => {
            let sockaddr = match unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockaddrIn) } {
                Ok(value) => value,
                Err(_) => return false,
            };
            args.dst_port = u16::from_be(sockaddr.port);
            args.dst_ip[..4].copy_from_slice(&sockaddr.addr);
            true
        }
        AF_INET6 => {
            let sockaddr = match unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockaddrIn6) }
            {
                Ok(value) => value,
                Err(_) => return false,
            };
            args.dst_port = u16::from_be(sockaddr.port);
            args.dst_ip.copy_from_slice(&sockaddr.addr);
            true
        }
        _ => false,
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn write_user_path(event: *mut SensorEvent, path_ptr: *const u8) -> u16 {
    let dest = unsafe {
        let path_field = core::ptr::addr_of_mut!((*event).path) as *mut u8;
        core::slice::from_raw_parts_mut(path_field, SENSOR_PATH_MAX)
    };
    // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/programs/sys_exit.rs:184
    match unsafe { bpf_probe_read_user_str_bytes(path_ptr, dest) } {
        Ok(bytes) => bytes.len() as u16,
        Err(_) => 0,
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn write_sched_exec_filename(ctx: &TracePointContext, event: *mut SensorEvent) -> u16 {
    // sched_process_exec tracepoint starts its first data field after common fields.
    // __data_loc filename stores offset in low 16 bits and length in high 16 bits.
    let data_loc: u32 = match unsafe { ctx.read_at(8) } {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let offset = (data_loc & 0xffff) as usize;
    if offset == 0 {
        return 0;
    }
    let source = unsafe { (ctx.as_ptr() as *const u8).add(offset) };
    let dest = unsafe {
        let exe_field = core::ptr::addr_of_mut!((*event).exe) as *mut u8;
        core::slice::from_raw_parts_mut(exe_field, SENSOR_PATH_MAX)
    };
    match unsafe { bpf_probe_read_kernel_str_bytes(source, dest) } {
        Ok(bytes) => bytes.len() as u16,
        Err(_) => 0,
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {
    let _ = snoop_common::OBSERVER_NAME;
}
