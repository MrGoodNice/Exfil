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
  echo "F1.2a gate failed: $*" >&2
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
assert_file "$dns_dir/main.go"
assert_file "$http_main"
assert_file "$http_test"
assert_file "$ref_ledger"

assert_contains_file "$ref_ledger" "mitmproxy/mitmproxy/certs.py:232"
assert_contains_file "$ref_ledger" "mitmproxy/mitmproxy/certs.py:314"
assert_contains_file "$ref_ledger" "crypto/tls Config.GetCertificate"
assert_contains_file "$http_main" "GetCertificate"
assert_contains_file "$http_main" "CreateCertificate"
assert_contains_file "$http_main" "EXFIL_TLS_CA_CERT"
assert_contains_file "$http_main" "TLS:                tlsTerminated"
assert_contains_file "$http_main" "CanaryMatch:        []string{}"
assert_contains_file "$start_script" "EXFIL_HONEYNET_CA_CERT"
assert_contains_file "$start_script" "EXFIL_TLS_CA_CERT"
assert_contains_file "$run_sandboxed" "--ca-cert"
assert_contains_file "$run_sandboxed" "SSL_CERT_FILE"
assert_contains_file "$run_sandboxed" "NODE_EXTRA_CA_CERTS"
assert_contains_file "$run_sandboxed" "REQUESTS_CA_BUNDLE"
assert_contains_file "$run_sandboxed" "CURL_CA_BUNDLE"
assert_not_contains_file "$start_script" "--publish"
assert_not_contains_file "$start_script" "-p "

tmpdir="$(mktemp -d)"
trap '"$cleanup_script"; rm -rf "$tmpdir"' EXIT
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'test' '-----END CERTIFICATE-----' >"$tmpdir/ca.pem"
ca_dry_run="$("$run_sandboxed" \
  --dry-run \
  --ca-cert "$tmpdir/ca.pem" \
  --honeynet-network exfil-honeynet-test \
  --honeynet-dns 172.30.0.2 \
  example.local/target:latest true)"
assert_contains "$ca_dry_run" "--mount"
assert_contains "$ca_dry_run" "src=$tmpdir/ca.pem"
assert_contains "$ca_dry_run" "dst=/tmp/exfil-analyzer-ca.pem"
assert_contains "$ca_dry_run" "dst=/etc/ssl/certs/exfil-analyzer-ca.pem"
assert_contains "$ca_dry_run" "readonly"
assert_contains "$ca_dry_run" "SSL_CERT_FILE=/tmp/exfil-analyzer-ca.pem"
assert_contains "$ca_dry_run" "SSL_CERT_DIR=/etc/ssl/certs"
assert_contains "$ca_dry_run" "NODE_EXTRA_CA_CERTS=/tmp/exfil-analyzer-ca.pem"
assert_contains "$ca_dry_run" "REQUESTS_CA_BUNDLE=/tmp/exfil-analyzer-ca.pem"
assert_contains "$ca_dry_run" "CURL_CA_BUNDLE=/tmp/exfil-analyzer-ca.pem"
[[ "$ca_dry_run" != *"PRIVATE KEY"* ]] || fail "dry-run leaked private key material"

(cd "$dns_dir" && go test ./...)
(cd "$http_dir" && go test ./...)

"$cleanup_script"
"$cleanup_script"

if [[ "${EXFIL_RUN_DOCKER_TESTS:-0}" == "1" ]]; then
  image="${EXFIL_SANDBOX_TEST_IMAGE:-busybox:latest}"
  env_file="$tmpdir/honeynet.env"
  "$start_script" \
    --build \
    --run-id f1-2a-run \
    --sample-id f1-2a-sample \
    --log-dir "$tmpdir/logs" \
    --env-file "$env_file" >/dev/null

  # shellcheck disable=SC1090
  source "$env_file"

  [[ -s "$EXFIL_HONEYNET_CA_CERT" ]] || fail "missing CA certificate"
  assert_contains_file "$EXFIL_HONEYNET_CA_CERT" "BEGIN CERTIFICATE"
  if grep -R -I "PRIVATE KEY" "$tmpdir" >/dev/null; then
    fail "CA private key leaked into honeynet artifacts"
  fi

  https_log="$tmpdir/https-post.log"
  "$run_sandboxed" \
    --ca-cert "$EXFIL_HONEYNET_CA_CERT" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 5 -O- --post-data "payload=f1-2a" "https://f1-2a.example.test/submit" >"$https_log" 2>&1
  assert_contains_file "$https_log" "exfil-analyzer synthetic response"
  if grep -R -I "PRIVATE KEY" "$tmpdir" >/dev/null; then
    fail "CA private key leaked after target HTTPS run"
  fi

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
if not events:
    raise SystemExit("no HTTP events")
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
for event in events:
    validator.validate(event)

matches = [
    event for event in events
    if event["method"] == "POST"
    and event["host"].split(":", 1)[0] == "f1-2a.example.test"
    and event["path"] == "/submit"
]
if not matches:
    raise SystemExit(f"TLS POST event missing: {events!r}")
for event in matches:
    if event["tls"] is not True:
        raise SystemExit(f"tls must be true: {event!r}")
    if event["upstream"] is not False or event["opaque_reason"] is not None:
        raise SystemExit(f"bad TLS honeynet flags: {event!r}")
    if not event["flow_id"]:
        raise SystemExit(f"missing flow_id: {event!r}")
    if event["canary_match"] != []:
        raise SystemExit(f"canary_match must stay empty in F1.2a: {event!r}")
    if not event["request_body_sha256"] or len(event["request_body_sha256"]) != 64:
        raise SystemExit(f"missing request_body_sha256: {event!r}")
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
    event["query"].rstrip(".") == "f1-2a.example.test"
    and event["qtype"] == "A"
    and event["resolved_ip"] == expected_ip
    for event in events
):
    raise SystemExit(f"DNS did not resolve TLS target to listener {expected_ip}: {events!r}")
PY

  set +e
  "$run_sandboxed" \
    --ca-cert "$EXFIL_HONEYNET_CA_CERT" \
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
      --ca-cert "$EXFIL_HONEYNET_CA_CERT" \
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
