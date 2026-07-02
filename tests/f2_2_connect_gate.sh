#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rust_dir="$repo_root/rust-observer"
common_crate="$rust_dir/snoop-common"
userspace_crate="$rust_dir/snoop"
ebpf_crate="$rust_dir/snoop-ebpf"
ref_ledger="$rust_dir/REF_LEDGER.md"
ebpf_obj="$rust_dir/target/bpfel-unknown-none/release/snoop-ebpf"
network_schema="$repo_root/schema/network.schema.json"
runtime_container_log=""

if [[ -z "${PYTHON:-}" && -x /tmp/exfil-contracts-venv/bin/python ]]; then
  PYTHON=/tmp/exfil-contracts-venv/bin/python
fi

dump_container_log() {
  if [[ -n "${runtime_container_log:-}" && -f "$runtime_container_log" ]]; then
    echo "---- tail of $runtime_container_log ----" >&2
    tail -n 80 "$runtime_container_log" >&2 || true
    echo "---- end container log ----" >&2
  fi
}

fail() {
  echo "F2.2 gate failed: $*" >&2
  dump_container_log
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
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

container_cgroup_id() {
  local container="$1"
  local pid=""
  for _ in $(seq 1 50); do
    pid="$(docker inspect -f '{{.State.Pid}}' "$container" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ && "$pid" != "0" && -r "/proc/$pid/cgroup" ]]; then
      break
    fi
    sleep 0.1
  done
  [[ "$pid" =~ ^[0-9]+$ && "$pid" != "0" ]] || fail "could not inspect pid for $container"
  local cgroup_rel
  cgroup_rel="$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' "/proc/$pid/cgroup")"
  [[ -n "$cgroup_rel" ]] || fail "could not resolve cgroup v2 path for $container"
  local cgroup_path="/sys/fs/cgroup${cgroup_rel}"
  [[ -d "$cgroup_path" ]] || fail "container cgroup path missing: $cgroup_path"
  stat -Lc '%i' "$cgroup_path"
}

wait_for_sensor_readiness() {
  local proc_log="$1"
  local cgroup_id="$2"
  for _ in $(seq 1 100); do
    if [[ -s "$proc_log" ]] && grep -F "\"cgroup_id\":\"$cgroup_id\"" "$proc_log" >/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  fail "sensor did not report a readiness event for cgroup_id=$cgroup_id"
}

assert_file "$common_crate/src/lib.rs"
assert_file "$userspace_crate/src/main.rs"
assert_file "$userspace_crate/src/sensor.rs"
assert_file "$ebpf_crate/src/main.rs"
assert_file "$ebpf_crate/src/maps.rs"
assert_file "$ref_ledger"
assert_file "$network_schema"

assert_contains_file "$ref_ledger" "kunai/kunai-ebpf/src/probes/connect.rs:15"
assert_contains_file "$ref_ledger" "kunai/kunai-ebpf/src/probes/connect.rs:27"
assert_contains_file "$ref_ledger" "aya-ebpf-0.1.1/src/programs/probe.rs:49"
assert_contains_file "$ref_ledger" "aya-ebpf-0.1.1/src/programs/retprobe.rs:43"
assert_contains_file "$ref_ledger" "aya-ebpf-0.1.1/src/helpers.rs:122"
assert_contains_file "$ref_ledger" "aya-ebpf-0.1.1/src/maps/hash_map.rs:98"
assert_contains_file "$ref_ledger" "aya-0.13.1/src/programs/kprobe.rs:76"

assert_contains_file "$common_crate/src/lib.rs" "EVENT_KIND_CONNECT"
assert_contains_file "$common_crate/src/lib.rs" "PROTO_TCP"
assert_contains_file "$common_crate/src/lib.rs" "PROTO_UDP"
assert_contains_file "$common_crate/src/lib.rs" "dst_ip_bytes"
assert_contains_file "$ebpf_crate/src/main.rs" "net_enter_sys_connect"
assert_contains_file "$ebpf_crate/src/main.rs" "net_exit_sys_connect"
assert_contains_file "$ebpf_crate/src/main.rs" "__sys_connect"
assert_contains_file "$ebpf_crate/src/main.rs" "bpf_probe_read_user"
assert_contains_file "$ebpf_crate/src/maps.rs" "CONNECT_ARGS"
assert_contains_file "$userspace_crate/src/sensor.rs" "EXFIL_NETWORK_LOG"
assert_contains_file "$userspace_crate/src/sensor.rs" "render_network_event"
assert_contains_file "$userspace_crate/src/sensor.rs" '"aya_connect"'
assert_contains_file "$userspace_crate/src/sensor.rs" '"flow_id": null'

(
  cd "$rust_dir"
  cargo test --package snoop sensor::tests
)

(
  cd "$rust_dir"
  CARGO_TARGET_DIR="$rust_dir/target" rustup run nightly cargo build \
    --release \
    --package snoop-ebpf \
    --target bpfel-unknown-none \
    -Z build-std=core
)
[[ -s "$ebpf_obj" ]] || fail "missing or empty BPF object: $ebpf_obj"
file "$ebpf_obj" | grep -F "eBPF" >/dev/null || fail "BPF object is not an eBPF ELF"

(
  cd "$rust_dir"
  SNOOP_SKIP_EBPF_BUILD=1 cargo build --package snoop-common --package snoop
  SNOOP_SKIP_EBPF_BUILD=1 cargo clippy --package snoop-common --package snoop -- -D warnings
)

if [[ "${EXFIL_RUN_BPF_TESTS:-0}" == "1" ]]; then
  if ! has_bpf_load_rights; then
    echo "F2.2 runtime e2e skipped: missing root or current CAP_BPF/CAP_PERFMON" >&2
    exit 0
  fi

  tmpdir="$(mktemp -d)"
  container="exfil-f2-2-$$"
  trap 'docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$tmpdir"' EXIT
  sandbox_uid="${SUDO_UID:-$(id -u)}"
  sandbox_gid="${SUDO_GID:-$(id -g)}"
  [[ "$sandbox_uid" != "0" ]] || fail "runtime e2e needs a non-root sandbox UID; run through sudo so SUDO_UID is set"
  "$repo_root/sandbox/canary-gen.sh" --target-dir "$tmpdir/canary" --run-id f2-2-run >/dev/null
  if [[ "$(id -u)" == "0" ]]; then
    chown -R "${sandbox_uid}:${sandbox_gid}" "$tmpdir/canary"
  fi

  files_log="$tmpdir/files.jsonl"
  proc_log="$tmpdir/proc.jsonl"
  network_log="$tmpdir/network.jsonl"
  ready_marker="$tmpdir/canary/.sensor-ready"
  runtime_container_log="$tmpdir/container.log"
  image="${EXFIL_SANDBOX_TEST_IMAGE:-busybox:latest}"

  (
    cd "$rust_dir"
    SNOOP_SKIP_EBPF_BUILD=1 cargo build --package snoop >/dev/null
  )

  EXFIL_SANDBOX_USER="${sandbox_uid}:${sandbox_gid}" "$repo_root/sandbox/run-sandboxed.sh" \
    --name "$container" \
    --canary-dir "$tmpdir/canary" \
    "$image" \
    sh -c 'while [ ! -e /canary/.sensor-ready ]; do /bin/true; sleep 1; done; sh -c "exec wget -T 2 -q -O - http://198.51.100.10/exfil"' \
    >"$runtime_container_log" 2>&1 &
  container_runner_pid=$!

  cgroup_id="$(container_cgroup_id "$container")"

  (
    cd "$rust_dir"
    EXFIL_RUN_ID=f2-2-run \
    EXFIL_SAMPLE_ID=f2-2-sample \
    EXFIL_FILES_LOG="$files_log" \
    EXFIL_PROC_LOG="$proc_log" \
    EXFIL_NETWORK_LOG="$network_log" \
    EXFIL_CANARY_CATALOG="$tmpdir/canary/canary.json" \
    EXFIL_TARGET_CGROUP_ID="$cgroup_id" \
    EXFIL_CONTAINER_ID="$container" \
    SNOOP_EBPF_OBJ="$ebpf_obj" \
    ./target/debug/snoop --sensor --duration-ms 15000 &
    sensor_pid=$!
    wait_for_sensor_readiness "$proc_log" "$cgroup_id"
    touch "$ready_marker"
    wait "$sensor_pid"
  )
  wait "$container_runner_pid" || true

  [[ -s "$network_log" ]] || fail "network.jsonl was not written"
  "${PYTHON:-python3}" - "$network_schema" "$network_log" "$cgroup_id" "$container" <<'PY'
import json
import sys
from pathlib import Path

try:
    from jsonschema.validators import Draft202012Validator
except ModuleNotFoundError as exc:
    raise SystemExit("missing jsonschema; set PYTHON to the project dev venv") from exc

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
events = [json.loads(line) for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines() if line.strip()]
target_cgroup_id = sys.argv[3]
container_id = sys.argv[4]
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
for event in events:
    validator.validate(event)
if not events:
    raise SystemExit("network log is empty")
if not all(event["source"] == "aya_connect" for event in events):
    raise SystemExit(f"unexpected source in network events: {events!r}")
if not all(event["flow_id"] is None for event in events):
    raise SystemExit(f"aya_connect flow_id must stay null: {events!r}")
if not all(event["src_ip"] is None and event["src_port"] is None for event in events):
    raise SystemExit(f"connect src fields must stay null: {events!r}")
if not all(event.get("cgroup_id") == target_cgroup_id for event in events):
    raise SystemExit(f"cgroup scope leaked: events={events!r} target={target_cgroup_id!r}")
if not all(event.get("container_id") == container_id for event in events):
    raise SystemExit(f"container_id mismatch: {events!r} wanted {container_id!r}")
matched = [
    event for event in events
    if event["dst_ip"] == "198.51.100.10"
    and event["dst_port"] == 80
    and event["proto"] == "tcp"
    and event["pid"] is not None
    and isinstance(event["retval"], int)
]
if not matched:
    raise SystemExit(f"no scoped TCP connect event for 198.51.100.10:80: {events!r}")
PY
fi
