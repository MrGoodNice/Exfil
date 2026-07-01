#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

#[cfg(target_arch = "bpf")]
mod maps;

#[cfg(target_arch = "bpf")]
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
#[cfg(target_arch = "bpf")]
use snoop_common::BringupEvent;

#[cfg(target_arch = "bpf")]
use crate::maps::EVENTS;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("r0 = 0", "exit", options(noreturn));
    }
}

#[cfg(target_arch = "bpf")]
#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(_ctx: TracePointContext) -> i64 {
    match try_sched_process_exec() {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
fn try_sched_process_exec() -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let mut entry = match EVENTS.reserve::<BringupEvent>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let event: *mut BringupEvent = entry.as_mut_ptr();
    unsafe {
        core::ptr::addr_of_mut!((*event).pid).write(pid);
        core::ptr::addr_of_mut!((*event).tid).write(tid);
        core::ptr::addr_of_mut!((*event).counter).write(1);
        core::ptr::addr_of_mut!((*event).timestamp_ns).write(bpf_ktime_get_ns());
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(target_arch = "bpf"))]
fn main() {
    let _ = snoop_common::OBSERVER_NAME;
}
