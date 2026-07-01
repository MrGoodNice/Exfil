#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rust_dir="$repo_root/rust-observer"
docs_file="$repo_root/docs/F2_0_TOOLCHAIN.md"
common_crate="$rust_dir/snoop-common"
userspace_crate="$rust_dir/snoop"
ebpf_crate="$rust_dir/snoop-ebpf"
ebpf_obj="$rust_dir/target/bpfel-unknown-none/release/snoop-ebpf"

fail() {
  echo "F2.0 gate failed: $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_executable() {
  [[ -x "$1" ]] || fail "not executable: $1"
}

assert_contains_file() {
  local file="$1"
  local needle="$2"
  grep -F -- "$needle" "$file" >/dev/null || fail "$file missing: $needle"
}

has_bpf_load_rights() {
  if [[ "$(id -u)" == "0" ]]; then
    return 0
  fi
  if command -v capsh >/dev/null 2>&1; then
    local current_caps
    current_caps="$(capsh --print 2>/dev/null | sed -n 's/^Current: //p')"
    [[ "$current_caps" == *cap_bpf* && "$current_caps" == *cap_perfmon* ]] && return 0
  fi
  return 1
}

assert_file "$rust_dir/Cargo.toml"
assert_file "$common_crate/Cargo.toml"
assert_file "$userspace_crate/Cargo.toml"
assert_file "$ebpf_crate/Cargo.toml"
assert_file "$ebpf_crate/rust-toolchain.toml"
assert_file "$ebpf_crate/src/main.rs"
assert_file "$ebpf_crate/src/maps.rs"
assert_file "$common_crate/src/lib.rs"
assert_file "$userspace_crate/src/main.rs"
assert_file "$userspace_crate/build.rs"
assert_file "$docs_file"

assert_contains_file "$docs_file" "rustup toolchain install nightly"
assert_contains_file "$docs_file" "rustup component add rust-src --toolchain nightly"
assert_contains_file "$docs_file" "cargo install bpf-linker"
assert_contains_file "$docs_file" "bpf-linker"

command -v rustup >/dev/null 2>&1 || fail "rustup is required"
command -v bpf-linker >/dev/null 2>&1 || fail "bpf-linker is required"
bpf-linker --version >/dev/null || fail "bpf-linker --version failed"
rustup run nightly rustc --version >/dev/null || fail "nightly rustc is required"
rustup component list --toolchain nightly --installed | grep -Fx rust-src >/dev/null || fail "rust-src component is required on nightly"
rustup run nightly rustc --print target-list | grep -Fx bpfel-unknown-none >/dev/null || fail "nightly rustc must know bpfel-unknown-none"

assert_contains_file "$rust_dir/Cargo.toml" 'default-members = ["snoop", "snoop-common"]'
assert_contains_file "$userspace_crate/Cargo.toml" 'aya = { version = "=0.13.1", features = ["async_tokio"] }'
assert_contains_file "$userspace_crate/Cargo.toml" 'aya-log = "=0.2.1"'
assert_contains_file "$ebpf_crate/Cargo.toml" 'aya-ebpf = "=0.1.1"'
assert_contains_file "$ebpf_crate/Cargo.toml" 'aya-log-ebpf = "=0.1.0"'
assert_contains_file "$ebpf_crate/rust-toolchain.toml" 'channel = "nightly"'
assert_contains_file "$ebpf_crate/rust-toolchain.toml" 'components = ["rust-src"]'
assert_contains_file "$userspace_crate/build.rs" "SNOOP_SKIP_EBPF_BUILD"
assert_contains_file "$userspace_crate/build.rs" "SNOOP_EBPF_OBJ"
assert_contains_file "$userspace_crate/build.rs" "rustup"
assert_contains_file "$userspace_crate/src/main.rs" "aya::Ebpf::load"
assert_contains_file "$userspace_crate/src/main.rs" "program_mut"
assert_contains_file "$userspace_crate/src/main.rs" "TracePoint"
assert_contains_file "$userspace_crate/src/main.rs" "RingBuf"
assert_contains_file "$ebpf_crate/src/main.rs" "sched_process_exec"
assert_contains_file "$ebpf_crate/src/maps.rs" "RingBuf::with_byte_size"

(
  cd "$rust_dir"
  CARGO_TARGET_DIR="$rust_dir/target" rustup run nightly cargo build \
    --release \
    --package snoop-ebpf \
    --target bpfel-unknown-none \
    -Z build-std=core
)
[[ -s "$ebpf_obj" ]] || fail "missing or empty BPF object: $ebpf_obj"

(
  cd "$rust_dir"
  SNOOP_SKIP_EBPF_BUILD=1 cargo build --package snoop-common --package snoop
  SNOOP_SKIP_EBPF_BUILD=1 cargo clippy --package snoop-common --package snoop -- -D warnings
)

if [[ "${EXFIL_RUN_BPF_TESTS:-0}" == "1" ]]; then
  if ! has_bpf_load_rights; then
    echo "F2.0 BPF load self-test skipped: missing root or current CAP_BPF/CAP_PERFMON" >&2
    exit 0
  fi
  set +e
  (
    cd "$rust_dir"
    SNOOP_EBPF_OBJ="$ebpf_obj" cargo run --package snoop -- --self-test
  )
  rc=$?
  set -e
  if [[ "$rc" -eq 77 ]]; then
    echo "F2.0 BPF load self-test skipped: missing CAP_BPF/CAP_PERFMON or root" >&2
  elif [[ "$rc" -ne 0 ]]; then
    fail "BPF load self-test failed with exit code $rc"
  fi
fi
