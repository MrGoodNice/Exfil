# F2.0 eBPF Toolchain Bring-Up

Fact captured on this local Arch box:

- Kernel: `6.18.36-1-lts`
- BTF: `/sys/kernel/btf/vmlinux` present
- System Rust before bring-up: `/usr/bin/rustc 1.96.0` and `/usr/bin/cargo 1.96.0`
- `rustup` was not present in PATH before bring-up
- `bpf-linker` was not present before bring-up
- Clang: `clang version 22.1.6`

Working recipe used here, keeping pacman Rust installed and adding user-local rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

Observed installed versions:

```text
rustup 1.29.0
stable-x86_64-unknown-linux-gnu rustc 1.96.1
nightly-x86_64-unknown-linux-gnu rustc 1.98.0-nightly (f46ec5218 2026-06-30)
bpf-linker 0.10.3
```

During the eBPF link step, `bpf-linker 0.10.3` prints this warning on the box:
`unable to open LLVM shared lib ... libLLVM-22-rust-1.98.0-nightly.so: dlopen failed`.
The object is still produced and the gate verifies it is a non-empty eBPF ELF.

Important PATH detail: rustup was installed with `--no-modify-path`, so normal shells that only
see `/usr/bin` will continue using pacman Rust. F2.0 gates prepend:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Build commands proven by the gate:

```bash
cd /home/mrg/Desktop/exfil-analyzer/rust-observer
CARGO_TARGET_DIR="$PWD/target" rustup run nightly cargo build \
  --release \
  --package snoop-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core

SNOOP_SKIP_EBPF_BUILD=1 cargo build --package snoop-common --package snoop
SNOOP_SKIP_EBPF_BUILD=1 cargo clippy --package snoop-common --package snoop -- -D warnings
```

Runtime load test:

```bash
EXFIL_RUN_BPF_TESTS=1 tests/f2_0_toolchain_gate.sh
```

On this normal `uid=1000` shell, `capsh --print` showed no current `CAP_BPF` or `CAP_PERFMON`,
so the gate explicitly skips the runtime load path. To prove runtime loading on this box, run the
same gate with root/current caps:

```bash
sudo -E env PATH="$HOME/.cargo/bin:$PATH" EXFIL_RUN_BPF_TESTS=1 ./tests/f2_0_toolchain_gate.sh
```

Equivalent direct binary flow after the gate has built the object:

```bash
cd /home/mrg/Desktop/exfil-analyzer/rust-observer
SNOOP_SKIP_EBPF_BUILD=1 cargo build --package snoop
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_ipc_lock+ep target/debug/snoop
SNOOP_EBPF_OBJ=target/bpfel-unknown-none/release/snoop-ebpf ./target/debug/snoop --self-test
```

F2.0 loads only the project's minimal `sched/sched_process_exec` tracepoint program and reads one
ring-buffer event; it does not implement real `openat`, `execve`, `connect`, cgroup scoping, or
schema output.
