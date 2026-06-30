#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
samples_dir="$repo_root/sandbox/samples"
run_sandboxed="$repo_root/sandbox/run-sandboxed.sh"
canary_gen="$repo_root/sandbox/canary-gen.sh"

fail() {
  echo "F0.4 gate failed: $*" >&2
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

assert_not_contains_file() {
  local file="$1"
  local needle="$2"
  if grep -F -- "$needle" "$file" >/dev/null; then
    fail "$file must not contain: $needle"
  fi
}

assert_file "$run_sandboxed"
assert_executable "$run_sandboxed"
assert_file "$canary_gen"
assert_executable "$canary_gen"

for sample in benign malicious-direct malicious-child; do
  dir="$samples_dir/$sample"
  [[ -d "$dir" ]] || fail "missing sample dir: $dir"
  assert_file "$dir/Dockerfile"
  assert_file "$dir/entrypoint.sh"
  assert_file "$dir/run.sh"
  assert_executable "$dir/entrypoint.sh"
  assert_executable "$dir/run.sh"
  assert_contains_file "$dir/Dockerfile" "FROM busybox@sha256:"
  assert_contains_file "$dir/run.sh" "run-sandboxed.sh"
  assert_contains_file "$dir/run.sh" "--canary-dir"
  assert_contains_file "$dir/entrypoint.sh" "EXFIL_SAMPLE name=$sample"
done

assert_not_contains_file "$samples_dir/benign/entrypoint.sh" "/canary/canary_rsa"
assert_not_contains_file "$samples_dir/benign/entrypoint.sh" "cat /canary"
assert_contains_file "$samples_dir/benign/entrypoint.sh" "canary_read=0"
assert_contains_file "$samples_dir/benign/entrypoint.sh" "wget"

assert_contains_file "$samples_dir/malicious-direct/entrypoint.sh" "cat /canary/canary_rsa"
assert_contains_file "$samples_dir/malicious-direct/entrypoint.sh" "canary_read=1"
assert_contains_file "$samples_dir/malicious-direct/entrypoint.sh" "egress_actor=self"
assert_contains_file "$samples_dir/malicious-direct/entrypoint.sh" "--post-data"

assert_contains_file "$samples_dir/malicious-child/entrypoint.sh" "cat /canary/canary_rsa"
assert_contains_file "$samples_dir/malicious-child/entrypoint.sh" "egress_actor=child"
assert_contains_file "$samples_dir/malicious-child/entrypoint.sh" "sh -c"
assert_contains_file "$samples_dir/malicious-child/entrypoint.sh" "--post-data"
assert_contains_file "$samples_dir/malicious-child/entrypoint.sh" 'wait "$child_pid"'

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
"$canary_gen" --target-dir "$tmpdir/canaries" --run-id f0-4-test >/dev/null

dry_run="$("$run_sandboxed" --dry-run --canary-dir "$tmpdir/canaries" busybox@sha256:fd8d9aa63ba2f0982b5304e1ee8d3b90a210bc1ffb5314d980eb6962f1a9715d true)"
[[ "$dry_run" == *"--mount"* ]] || fail "run-sandboxed dry-run missing --mount for canary dir"
[[ "$dry_run" == *"type=bind"* ]] || fail "run-sandboxed dry-run missing bind mount"
[[ "$dry_run" == *"dst=/canary"* ]] || fail "run-sandboxed dry-run missing /canary destination"
[[ "$dry_run" == *"readonly"* ]] || fail "run-sandboxed dry-run missing readonly canary mount"

if [[ "${EXFIL_RUN_DOCKER_TESTS:-0}" == "1" ]]; then
  for sample in benign malicious-direct malicious-child; do
    log="$tmpdir/$sample.log"
    if ! "$samples_dir/$sample/run.sh" --build --canary-dir "$tmpdir/canaries" >"$log" 2>&1; then
      sed -n '1,200p' "$log" >&2
      fail "runtime sample failed: $sample"
    fi
    assert_contains_file "$log" "EXFIL_SAMPLE name=$sample"
  done
  assert_contains_file "$tmpdir/benign.log" "canary_read=0"
  assert_contains_file "$tmpdir/malicious-direct.log" "canary_read=1"
  assert_contains_file "$tmpdir/malicious-direct.log" "egress_result=failed_expected"
  assert_contains_file "$tmpdir/malicious-child.log" "egress_actor=child"
  assert_contains_file "$tmpdir/malicious-child.log" "egress_result=failed_expected"
fi
