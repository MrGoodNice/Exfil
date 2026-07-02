# rust-observer REF_LEDGER

## F2.0

- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/rust-toolchain.toml:1` — eBPF crate pins nightly and `rust-src`.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/build.rs:1` — build script pattern with skip/prebuilt/inline eBPF object build.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/loader.rs:41` — `aya::Ebpf::load` from bytes.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/loader.rs:81` — `program_mut(...).try_into::<TracePoint>()`.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/tracer.rs:243` — `Ebpf::take_map("EVENTS")`.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/tracer.rs:245` — userspace `RingBuf::try_from(map)`.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop/src/tracer.rs:272` — `std::ptr::read_unaligned` for ring-buffer payloads.

## F2.1

- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/maps.rs:17` — eBPF `RingBuf::with_byte_size`.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-common/src/event.rs:30` — shared `#[repr(C)]` event struct across eBPF/userspace.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-common/src/event.rs:46` — `comm: [u8; 16]` wire field.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/programs/sys_enter.rs:59` — `TracePointContext::read_at(8)` for raw syscall id.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/programs/sys_enter.rs:60` — `TracePointContext::read_at(16)` for raw syscall args.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/programs/sys_enter.rs:66` — `bpf_get_current_comm`.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/programs/sys_exit.rs:184` — `bpf_probe_read_user_str_bytes` into ring-buffer memory.
- `/home/mrg/Desktop/exfil-step-a-refs/snoop/snoop-ebpf/src/programs/sys_exit.rs:272` — fixed-slot/string-capture verifier note; F2.1 keeps fixed-size path buffers.
- `/home/mrg/Desktop/exfil-step-a-refs/kunai/kunai-ebpf/src/probes/execve.rs:144` — target design reference for current-task cgroup parsing.
- `/home/mrg/Desktop/exfil-step-a-refs/kunai/kunai-ebpf/src/probes/execve.rs:145` — kunai CO-RE chain `current -> sched_task_group -> css -> cgroup`.
- `/home/mrg/Desktop/exfil-step-a-refs/kunai/kunai-common/src/cgroup/bpf.rs:11` — kunai cgroup path resolve algorithm.
- `/home/mrg/Desktop/exfil-step-a-refs/kunai/kunai/src/containers.rs:85` — userspace `from_cgroup` container classification pattern.
- `/home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/programs/tracepoint.rs:14` — `TracePointContext::read_at` signature.
- `/home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/helpers.rs:14` — `pub use gen::*` exposes generated helpers through `aya_ebpf::helpers`.
- `/home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/helpers.rs:553` — `bpf_probe_read_kernel_str_bytes`.
- `/home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-bindings-0.1.2/src/x86_64/helpers.rs:808` — `bpf_get_current_cgroup_id` helper used for F2.1 `cgroup_id`.
- `/home/mrg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-0.13.1/src/maps/ring_buf.rs:130` — userspace `RingBuf::next`.

F2.1 scope note: full kunai cgroup path resolution is recorded above but not ported wholesale.
This slice uses the kernel helper `bpf_get_current_cgroup_id()` for the JSON `cgroup_id` string
and userspace filtering. Runtime review should verify that helper value scopes the target cgroup
correctly on kernel 6.18.
