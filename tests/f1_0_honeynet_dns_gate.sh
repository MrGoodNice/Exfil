#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_sandboxed="$repo_root/sandbox/run-sandboxed.sh"
cleanup_script="$repo_root/sandbox/cleanup.sh"
honeynet_dir="$repo_root/sandbox/honeynet"
start_script="$honeynet_dir/start.sh"
dns_dir="$honeynet_dir/dns-sinkhole"
dns_main="$dns_dir/main.go"
dns_test="$dns_dir/main_test.go"
ref_ledger="$honeynet_dir/REF_LEDGER.md"

fail() {
  echo "F1.0 gate failed: $*" >&2
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
  [[ "$haystack" == *"$needle"* ]] || fail "missing content: $needle"
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
assert_file "$cleanup_script"
assert_executable "$cleanup_script"
assert_file "$start_script"
assert_executable "$start_script"
assert_file "$dns_main"
assert_file "$dns_test"
assert_file "$dns_dir/Dockerfile"
assert_file "$ref_ledger"

assert_contains_file "$ref_ledger" "flare-fakenet-ng/fakenet/listeners/DNSListener.py:101"
assert_contains_file "$start_script" "docker network create"
assert_contains_file "$start_script" "--internal"
assert_contains_file "$start_script" "exfil-analyzer.managed=true"
assert_contains_file "$start_script" "exfil-analyzer.kind=honeynet-network"
assert_contains_file "$cleanup_script" "docker network rm"
assert_contains_file "$cleanup_script" "exfil-analyzer.kind=honeynet-network"
assert_contains_file "$dns_main" "canary_match"
assert_contains_file "$dns_main" "sinkholed"
assert_contains_file "$dns_main" "DNSListener.py:101"
assert_not_contains_file "$start_script" "--publish"
assert_not_contains_file "$start_script" "-p "
assert_not_contains_file "$run_sandboxed" "--network host"

default_dry_run="$("$run_sandboxed" --dry-run --name exfil-f1-default example.local/target:latest true)"
assert_contains "$default_dry_run" "--network"
assert_contains "$default_dry_run" "none"

honeynet_dry_run="$("$run_sandboxed" \
  --dry-run \
  --name exfil-f1-honeynet \
  --honeynet-network exfil-honeynet-test \
  --honeynet-dns 172.30.0.2 \
  example.local/target:latest true)"
assert_contains "$honeynet_dry_run" "--network"
assert_contains "$honeynet_dry_run" "exfil-honeynet-test"
assert_contains "$honeynet_dry_run" "--dns"
assert_contains "$honeynet_dry_run" "172.30.0.2"
[[ "$honeynet_dry_run" != *"--network none"* ]] || fail "honeynet dry-run must not use --network none"

if "$run_sandboxed" --dry-run --honeynet-network exfil-honeynet-test example.local/target:latest true >/dev/null 2>&1; then
  fail "--honeynet-network without --honeynet-dns must be refused"
fi
if "$run_sandboxed" --dry-run --honeynet-dns 172.30.0.2 example.local/target:latest true >/dev/null 2>&1; then
  fail "--honeynet-dns without --honeynet-network must be refused"
fi
for unsafe_network in host bridge none; do
  if "$run_sandboxed" --dry-run --honeynet-network "$unsafe_network" --honeynet-dns 172.30.0.2 example.local/target:latest true >/dev/null 2>&1; then
    fail "--honeynet-network=$unsafe_network must be refused"
  fi
done

(cd "$dns_dir" && go test ./...)

"$cleanup_script"
"$cleanup_script"

if [[ "${EXFIL_RUN_DOCKER_TESTS:-0}" == "1" ]]; then
  image="${EXFIL_SANDBOX_TEST_IMAGE:-busybox:latest}"
  tmpdir="$(mktemp -d)"
  trap '"$cleanup_script"; rm -rf "$tmpdir"' EXIT

  env_file="$tmpdir/honeynet.env"
  "$start_script" \
    --build \
    --run-id f1-0-run \
    --sample-id f1-0-sample \
    --log-dir "$tmpdir/logs" \
    --env-file "$env_file" >/dev/null

  # shellcheck disable=SC1090
  source "$env_file"

  nslookup_log="$tmpdir/nslookup.log"
  "$run_sandboxed" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" nslookup f1-0.example.test >"$nslookup_log" 2>&1

  assert_contains_file "$nslookup_log" "$EXFIL_HONEYNET_RESPONSE_IP"
  [[ -s "$EXFIL_HONEYNET_DNS_LOG" ]] || fail "dns.jsonl was not written"

  "${PYTHON:-python3}" - "$repo_root/schema/dns.schema.json" "$EXFIL_HONEYNET_DNS_LOG" <<'PY'
import json
import sys
from pathlib import Path

try:
    from jsonschema.validators import Draft202012Validator
except ModuleNotFoundError as exc:
    raise SystemExit("missing jsonschema; set PYTHON to the project dev venv") from exc

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
events = [
    json.loads(line)
    for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if not events:
    raise SystemExit("no dns events")
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
for event in events:
    validator.validate(event)
if not any(
    event["query"].rstrip(".") == "f1-0.example.test"
    and event["qtype"] == "A"
    and event["resolved_ip"] == "198.51.100.53"
    and event["canary_match"] == []
    and event["sinkholed"] is True
    for event in events
):
    raise SystemExit(f"expected sinkholed A event not found: {events!r}")
PY

  set +e
  "$run_sandboxed" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 3 -O- http://1.1.1.1/ >/dev/null 2>&1
  public_rc=$?
  set -e
  [[ "$public_rc" -ne 0 ]] || fail "public IP was reachable from internal honeynet"

  tailscale_probe_ip="${EXFIL_TAILSCALE_PROBE_IP:-}"
  if [[ -z "$tailscale_probe_ip" ]] && command -v tailscale >/dev/null 2>&1; then
    tailscale_probe_ip="$(tailscale ip -4 2>/dev/null | sed -n '1p' || true)"
  fi
  if [[ -n "$tailscale_probe_ip" ]]; then
    set +e
    "$run_sandboxed" \
      --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
      --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
      "$image" wget -T 3 -O- "http://$tailscale_probe_ip/" >/dev/null 2>&1
    tail_rc=$?
    set -e
    [[ "$tail_rc" -ne 0 ]] || fail "Tailscale IP was reachable from internal honeynet"
  fi

  if command -v curl >/dev/null 2>&1; then
    curl --head --max-time 5 https://example.com >/dev/null || fail "host network check failed"
  fi

  "$cleanup_script"
  if docker ps -aq --filter label=exfil-analyzer.managed=true | grep -q .; then
    fail "managed containers remain after cleanup"
  fi
  if docker network ls -q --filter label=exfil-analyzer.managed=true --filter label=exfil-analyzer.kind=honeynet-network | grep -q .; then
    fail "managed honeynet networks remain after cleanup"
  fi
fi
