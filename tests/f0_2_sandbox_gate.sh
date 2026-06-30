#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_script="$repo_root/sandbox/run-sandboxed.sh"
cleanup_script="$repo_root/sandbox/cleanup.sh"

fail() {
  echo "F0.2 gate failed: $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_executable() {
  [[ -x "$1" ]] || fail "not executable: $1"
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  [[ "$haystack" == *"$needle"* ]] || fail "missing docker arg: $needle"
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  [[ "$haystack" != *"$needle"* ]] || fail "forbidden content present: $needle"
}

assert_file "$run_script"
assert_file "$cleanup_script"
assert_executable "$run_script"
assert_executable "$cleanup_script"

for forbidden in "iptables" "iptables-restore" "nft " "ip link" "docker network create" "--network host" "--privileged"; do
  if grep -Rsn -- "$forbidden" "$run_script" "$cleanup_script" >/dev/null; then
    fail "host-network or privileged primitive found: $forbidden"
  fi
done

dry_run="$("$run_script" --dry-run --name exfil-f0-2-test example.local/target:latest sh -c true)"

assert_contains "$dry_run" "docker"
assert_contains "$dry_run" "run"
assert_contains "$dry_run" "--rm"
assert_contains "$dry_run" "--pull"
assert_contains "$dry_run" "never"
assert_contains "$dry_run" "--network"
assert_contains "$dry_run" "none"
assert_contains "$dry_run" "--cap-drop"
assert_contains "$dry_run" "ALL"
assert_contains "$dry_run" "--security-opt"
assert_contains "$dry_run" "no-new-privileges"
assert_contains "$dry_run" "--read-only"
assert_contains "$dry_run" "--tmpfs"
assert_contains "$dry_run" "/tmp:rw"
assert_contains "$dry_run" "noexec"
assert_contains "$dry_run" "nosuid"
assert_contains "$dry_run" "nodev"
assert_contains "$dry_run" "/run:rw"
assert_contains "$dry_run" "--user"
assert_contains "$dry_run" "65532:65532"
assert_contains "$dry_run" "--pids-limit"
assert_contains "$dry_run" "--memory"
assert_contains "$dry_run" "--cpus"
assert_not_contains "$dry_run" "--network host"
assert_not_contains "$dry_run" "seccomp=unconfined"

"$cleanup_script"
"$cleanup_script"

if [[ "${EXFIL_RUN_DOCKER_TESTS:-0}" == "1" ]]; then
  image="${EXFIL_SANDBOX_TEST_IMAGE:?set EXFIL_SANDBOX_TEST_IMAGE for runtime F0.2 test}"
  probe='if command -v wget >/dev/null 2>&1; then wget -T 3 -O- http://1.1.1.1/; elif command -v curl >/dev/null 2>&1; then curl --connect-timeout 3 http://1.1.1.1/; else echo "missing wget/curl in EXFIL_SANDBOX_TEST_IMAGE" >&2; exit 125; fi'
  set +e
  "$run_script" --name exfil-f0-2-runtime "$image" sh -c "$probe"
  rc=$?
  set -e
  [[ "$rc" -ne 125 ]] || fail "runtime image lacks wget/curl for public-IP probe"
  [[ "$rc" -ne 0 ]] || fail "public IP was reachable from sandbox"

  if command -v curl >/dev/null 2>&1; then
    curl --head --max-time 5 https://example.com >/dev/null || fail "host network check failed"
  fi

  "$cleanup_script"
  "$cleanup_script"
fi
