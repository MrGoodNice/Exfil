use std::{error::Error, process::ExitCode};

#[cfg(target_os = "linux")]
use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use aya::{
    include_bytes_aligned,
    maps::{MapData, RingBuf},
    programs::TracePoint,
    Ebpf,
};
#[cfg(target_os = "linux")]
use snoop_common::BringupEvent;

#[cfg(target_os = "linux")]
static SNOOP_EBPF_BYTES: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/snoop-ebpf"));

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if is_permission_error(err.as_ref()) => {
            eprintln!("F2.0 BPF self-test skipped: {err}");
            ExitCode::from(77)
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let self_test = std::env::args().any(|arg| arg == "--self-test");
    if self_test {
        return run_self_test();
    }
    println!("{}", snoop_common::OBSERVER_NAME);
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_self_test() -> Result<(), Box<dyn Error>> {
    let bytes = if let Ok(path) = std::env::var("SNOOP_EBPF_OBJ") {
        std::fs::read(path)?
    } else {
        SNOOP_EBPF_BYTES.to_vec()
    };
    if bytes.is_empty() {
        return Err(
            "embedded eBPF object is empty; set SNOOP_EBPF_OBJ or unset SNOOP_SKIP_EBPF_BUILD"
                .into(),
        );
    }

    // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/loader.rs:41 (aya::Ebpf::load)
    let mut ebpf = Ebpf::load(&bytes)?;
    // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/loader.rs:81
    let program: &mut TracePoint = ebpf
        .program_mut("sched_process_exec")
        .ok_or("program `sched_process_exec` not found")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/tracer.rs:243
    let map = ebpf
        .take_map("EVENTS")
        .ok_or("EVENTS ring buffer not found")?;
    // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/tracer.rs:245
    let mut ring_buf: RingBuf<MapData> = RingBuf::try_from(map)?;

    let _ = Command::new("/bin/true").status()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        while let Some(item) = ring_buf.next() {
            if item.len() < std::mem::size_of::<BringupEvent>() {
                continue;
            }
            // ref: /home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/tracer.rs:272
            let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const BringupEvent) };
            if event.counter == 1 {
                println!("f2_0_self_test_event pid={} tid={}", event.pid, event.tid);
                drop(ebpf);
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err("timed out waiting for sched_process_exec event".into())
}

#[cfg(not(target_os = "linux"))]
fn run_self_test() -> Result<(), Box<dyn Error>> {
    Err("BPF self-test is Linux-only".into())
}

fn is_permission_error(err: &dyn Error) -> bool {
    let text = err.to_string();
    text.contains("Operation not permitted")
        || text.contains("Permission denied")
        || text.contains("EPERM")
}
