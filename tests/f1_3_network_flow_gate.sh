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
network_schema="$repo_root/schema/network.schema.json"
http_schema="$repo_root/schema/http.schema.json"

fail() {
  echo "F1.3 gate failed: $*" >&2
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
assert_file "$ref_ledger"
assert_file "$network_schema"
assert_file "$http_schema"

assert_contains_file "$ref_ledger" "go doc net/http Server.ConnContext"
assert_contains_file "$ref_ledger" "go doc context.WithValue"
assert_contains_file "$ref_ledger" "go doc net Conn.RemoteAddr"
assert_contains_file "$ref_ledger" "go doc net Conn.LocalAddr"
assert_contains_file "$http_main" "ConnContext"
assert_contains_file "$http_main" "context.WithValue"
assert_contains_file "$http_main" "RemoteAddr()"
assert_contains_file "$http_main" "LocalAddr()"
assert_contains_file "$http_main" "EXFIL_NETWORK_LOG"
assert_contains_file "$start_script" "EXFIL_NETWORK_LOG=/logs/network.jsonl"
assert_contains_file "$start_script" "EXFIL_HONEYNET_NETWORK_LOG"
assert_not_contains_file "$start_script" "--publish"
assert_not_contains_file "$start_script" "-p "

(cd "$dns_dir" && go test ./...)
(cd "$http_dir" && go test ./...)

"$cleanup_script"
"$cleanup_script"

if [[ "${EXFIL_RUN_DOCKER_TESTS:-0}" == "1" ]]; then
  image="${EXFIL_SANDBOX_TEST_IMAGE:-busybox:latest}"
  tmpdir="$(mktemp -d)"
  untrusted_image="exfil-f1-3-untrusted-client:local"
  trap '"$cleanup_script"; docker image rm "$untrusted_image" >/dev/null 2>&1 || true; rm -rf "$tmpdir"' EXIT

  env_file="$tmpdir/honeynet.env"
  "$start_script" \
    --build \
    --run-id f1-3-run \
    --sample-id f1-3-sample \
    --log-dir "$tmpdir/logs" \
    --env-file "$env_file" >/dev/null

  # shellcheck disable=SC1090
  source "$env_file"

  [[ -s "$EXFIL_HONEYNET_CA_CERT" ]] || fail "missing CA certificate"
  [[ -n "${EXFIL_HONEYNET_NETWORK_LOG:-}" ]] || fail "EXFIL_HONEYNET_NETWORK_LOG was not exported"

  https_log="$tmpdir/https-post.log"
  "$run_sandboxed" \
    --ca-cert "$EXFIL_HONEYNET_CA_CERT" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$image" wget -T 5 -O- --post-data "payload=f1-3" "https://f1-3.example.test/submit" >"$https_log" 2>&1
  assert_contains_file "$https_log" "exfil-analyzer synthetic response"

  client_dir="$tmpdir/untrusted-client"
  mkdir -p "$client_dir"
  cat >"$client_dir/client.go" <<'GO'
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: client URL")
		os.Exit(2)
	}
	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = response.Body.Close()
}
GO
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$client_dir/client" "$client_dir/client.go"
  cat >"$client_dir/Dockerfile" <<'DOCKER'
FROM scratch
COPY client /client
DOCKER
  docker build --pull=false -t "$untrusted_image" "$client_dir" >/dev/null

  set +e
  "$run_sandboxed" \
    --honeynet-network "$EXFIL_HONEYNET_NETWORK" \
    --honeynet-dns "$EXFIL_HONEYNET_DNS_IP" \
    "$untrusted_image" /client "https://f1-3-untrusted.example.test/opaque" >"$tmpdir/untrusted.log" 2>&1
  untrusted_rc=$?
  set -e
  [[ "$untrusted_rc" -ne 0 ]] || fail "untrusted HTTPS unexpectedly succeeded"

  [[ -s "$EXFIL_HONEYNET_NETWORK_LOG" ]] || fail "network.jsonl was not written"
  [[ -s "$EXFIL_HONEYNET_HTTP_LOG" ]] || fail "http.jsonl was not written"

  "${PYTHON:-python3}" - "$network_schema" "$http_schema" "$EXFIL_HONEYNET_NETWORK_LOG" "$EXFIL_HONEYNET_HTTP_LOG" <<'PY'
import json
import sys
from pathlib import Path

try:
    from jsonschema.validators import Draft202012Validator
except ModuleNotFoundError as exc:
    raise SystemExit("missing jsonschema; set PYTHON to the project dev venv") from exc

network_schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
http_schema = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
network_events = [
    json.loads(line)
    for line in Path(sys.argv[3]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
http_events = [
    json.loads(line)
    for line in Path(sys.argv[4]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
network_validator = Draft202012Validator(network_schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
http_validator = Draft202012Validator(http_schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
for event in network_events:
    network_validator.validate(event)
    if event["source"] != "honeynet" or event["proto"] != "tcp":
        raise SystemExit(f"bad network source/proto: {event!r}")
    if event["pid"] is not None:
        raise SystemExit(f"honeynet pid must be null until aya: {event!r}")
    if not event["flow_id"]:
        raise SystemExit(f"missing network flow_id: {event!r}")
    if not event["src_ip"] or not isinstance(event["src_port"], int):
        raise SystemExit(f"bad source endpoint: {event!r}")
    if not event["dst_ip"] or not isinstance(event["dst_port"], int):
        raise SystemExit(f"bad destination endpoint: {event!r}")
for event in http_events:
    http_validator.validate(event)
    if not event["flow_id"]:
        raise SystemExit(f"missing http flow_id: {event!r}")

post = [
    event for event in http_events
    if event["method"] == "POST"
    and event["host"].split(":", 1)[0] == "f1-3.example.test"
    and event["path"] == "/submit"
    and event["tls"] is True
]
if not post:
    raise SystemExit(f"trusted TLS POST missing: {http_events!r}")
post_event = post[-1]
post_network = [event for event in network_events if event["flow_id"] == post_event["flow_id"]]
if len(post_network) != 1:
    raise SystemExit(f"trusted TLS flow_id did not join exactly once: http={post_event!r} network={post_network!r}")
if post_network[0]["dst_port"] != 443:
    raise SystemExit(f"trusted TLS dst_port must be 443: {post_network[0]!r}")

opaque = [
    event for event in http_events
    if event["tls"] is True
    and event["opaque_reason"] == "failed-handshake"
]
if not opaque:
    raise SystemExit(f"failed-handshake event missing: {http_events!r}")
opaque_event = opaque[-1]
opaque_network = [event for event in network_events if event["flow_id"] == opaque_event["flow_id"]]
if len(opaque_network) != 1:
    raise SystemExit(f"opaque flow_id did not join exactly once: http={opaque_event!r} network={opaque_network!r}")
if opaque_event["method"] is not None or opaque_event["path"] is not None:
    raise SystemExit(f"failed-handshake method/path must be null: {opaque_event!r}")
PY

  if grep -R -I "PRIVATE KEY" "$tmpdir" >/dev/null; then
    fail "CA private key leaked into honeynet artifacts"
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
