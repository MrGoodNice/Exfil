#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_sandboxed="$repo_root/sandbox/run-sandboxed.sh"
cleanup_script="$repo_root/sandbox/cleanup.sh"
honeynet_dir="$repo_root/sandbox/honeynet"
start_script="$honeynet_dir/start.sh"
dns_dir="$honeynet_dir/dns-sinkhole"
http_dir="$honeynet_dir/http-listener"
http_main="$http_dir/main.go"
http_test="$http_dir/main_test.go"
ref_ledger="$honeynet_dir/REF_LEDGER.md"

fail() {
  echo "F1.1 gate failed: $*" >&2
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
assert_file "$cleanup_script"
assert_executable "$cleanup_script"
assert_file "$start_script"
assert_executable "$start_script"
assert_file "$dns_dir/main.go"
assert_file "$http_main"
assert_file "$http_test"
assert_file "$http_dir/Dockerfile"
assert_file "$ref_ledger"

assert_contains_file "$ref_ledger" "flare-fakenet-ng/fakenet/listeners/HTTPListener.py:63"
assert_contains_file "$ref_ledger" "flare-fakenet-ng/fakenet/listeners/HTTPListener.py:288"
assert_contains_file "$http_main" "HTTPListener.py:63"
assert_contains_file "$http_main" "upstream"
assert_contains_file "$http_main" "flow_id"
assert_contains_file "$http_main" "tls"
assert_contains_file "$start_script" "EXFIL_HONEYNET_HTTP_IP"
assert_contains_file "$start_script" "EXFIL_HONEYNET_HTTP_LOG"
assert_contains_file "$start_script" 'EXFIL_DNS_RESPONSE_IP=$response_ip'
assert_not_contains_file "$start_script" "--publish"
assert_not_contains_file "$start_script" "-p "
assert_not_contains_file "$http_main" "https"
assert_not_contains_file "$http_main" "mitmproxy"
assert_not_contains_file "$http_main" "certificate"

(cd "$dns_dir" && go test ./...)
(cd "$http_dir" && go test ./...)

"$cleanup_script"
"$cleanup_script"

if [[ "${EXFIL_RUN_DOCKER_TESTS:-0}" == "1" ]]; then
  image="${EXFIL_SANDBOX_TEST_IMAGE:-busybox:latest}"
  tmpdir="$(mktemp -d)"
  trap '"$cleanup_script"; rm -rf "$tmpdir"' EXIT

  env_file="$tmpdir/honeynet.env"
  "$start_script" \
    --build \
    --run-id f1-1-run \
    --sample-id f1-1-sample \
    --log-dir "$tmpdir/logs" \
    --env-file "$env_file" >/dev/null

  # shellcheck disable=SC1090
  source "$env_file"

  get_log="$tmpdir/get.log"
  post_log="$tmpdir/post.log"
  "$run_sandboxed" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 3 -O- "http://f1-1.example.test/download?x=1" >"$get_log" 2>&1
  "$run_sandboxed" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 3 -O- --post-data "payload=f1-1" "http://f1-1.example.test/submit" >"$post_log" 2>&1

  assert_contains_file "$get_log" "exfil-analyzer synthetic response"
  assert_contains_file "$post_log" "exfil-analyzer synthetic response"
  [[ -s "$EXFIL_HONEYNET_HTTP_LOG" ]] || fail "http.jsonl was not written"

  "${PYTHON:-python3}" - "$repo_root/schema/http.schema.json" "$EXFIL_HONEYNET_HTTP_LOG" <<'PY'
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
if len(events) < 2:
    raise SystemExit(f"expected at least two HTTP events, got {events!r}")
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
for event in events:
    validator.validate(event)
    if not event["flow_id"]:
        raise SystemExit(f"missing flow_id: {event!r}")
    if event["tls"] is not False or event["upstream"] is not False:
        raise SystemExit(f"bad network flags: {event!r}")
    if event["opaque_reason"] is not None:
        raise SystemExit(f"opaque_reason must be null for F1.1 HTTP: {event!r}")
    if event["canary_match"] != []:
        raise SystemExit(f"canary_match must be empty in F1.1: {event!r}")

def has_event(method, path):
    return any(
        event["method"] == method
        and event["host"].split(":", 1)[0] == "f1-1.example.test"
        and event["path"] == path
        for event in events
    )

if not has_event("GET", "/download?x=1"):
    raise SystemExit(f"GET event missing: {events!r}")
if not has_event("POST", "/submit"):
    raise SystemExit(f"POST event missing: {events!r}")
post_events = [event for event in events if event["method"] == "POST"]
if not any(event["request_body_sha256"] and len(event["request_body_sha256"]) == 64 for event in post_events):
    raise SystemExit(f"POST request_body_sha256 missing: {post_events!r}")
PY

  "${PYTHON:-python3}" - "$repo_root/schema/dns.schema.json" "$EXFIL_HONEYNET_DNS_LOG" "$EXFIL_HONEYNET_HTTP_IP" <<'PY'
import json
import sys
from pathlib import Path

try:
    from jsonschema.validators import Draft202012Validator
except ModuleNotFoundError as exc:
    raise SystemExit("missing jsonschema; set PYTHON to the project dev venv") from exc

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_ip = sys.argv[3]
events = [
    json.loads(line)
    for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
for event in events:
    validator.validate(event)
if not any(
    event["query"].rstrip(".") == "f1-1.example.test"
    and event["qtype"] == "A"
    and event["resolved_ip"] == expected_ip
    for event in events
):
    raise SystemExit(f"DNS did not resolve target domain to HTTP listener {expected_ip}: {events!r}")
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
