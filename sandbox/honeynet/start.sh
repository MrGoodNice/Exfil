#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dns_dir="$script_dir/dns-sinkhole"
http_dir="$script_dir/http-listener"

usage() {
  cat >&2 <<'USAGE'
Usage: sandbox/honeynet/start.sh [--build] --log-dir DIR [OPTIONS]

Starts the F1 honeynet DNS sinkhole and HTTP listener on a Docker internal network.

Options:
  --run-id ID          Run id written to dns.jsonl, default f1-0-<timestamp>-<pid>.
  --sample-id ID       Sample id written to dns.jsonl, default manual.
  --network-name NAME  Docker internal network name, default exfil-honeynet-<run-id>.
  --image IMAGE        Alias for --dns-image.
  --dns-image IMAGE    DNS sinkhole image, default exfil-honeynet-dns:local.
  --http-image IMAGE   HTTP listener image, default exfil-honeynet-http:local.
  --response-ip IP     Override IPv4 returned for A records; default HTTP listener IP.
  --canary-catalog FILE  Optional canary.json mounted read-only into the HTTP listener.
  --env-file FILE      Write source-able EXFIL_HONEYNET_* values to FILE.
  --build              Build the honeynet listener images before starting.
USAGE
}

fail() {
  echo "honeynet/start.sh: $*" >&2
  exit 1
}

require_name() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "$label must contain only A-Z a-z 0-9 _ . -"
}

quote_env() {
  local name="$1"
  local value="$2"
  printf '%s=%q\n' "$name" "$value"
}

build_image() {
  local image="$1"
  local source_dir="$2"
  local build_dir
  build_dir="$(mktemp -d)"
  trap 'rm -rf "$build_dir"' RETURN

  (cd "$source_dir" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$build_dir/$(basename "$source_dir")" .)
  docker build --pull=false -t "$image" -f "$source_dir/Dockerfile" "$build_dir" >/dev/null
}

build=0
run_id="f1-0-$(date +%s)-$$"
sample_id="manual"
network_name=""
dns_image="exfil-honeynet-dns:local"
http_image="exfil-honeynet-http:local"
response_ip=""
log_dir=""
env_file=""
canary_catalog=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)
      build=1
      shift
      ;;
    --run-id)
      [[ $# -ge 2 ]] || fail "--run-id requires a value"
      run_id="$2"
      shift 2
      ;;
    --sample-id)
      [[ $# -ge 2 ]] || fail "--sample-id requires a value"
      sample_id="$2"
      shift 2
      ;;
    --network-name)
      [[ $# -ge 2 ]] || fail "--network-name requires a value"
      network_name="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || fail "--image requires a value"
      dns_image="$2"
      shift 2
      ;;
    --dns-image)
      [[ $# -ge 2 ]] || fail "--dns-image requires a value"
      dns_image="$2"
      shift 2
      ;;
    --http-image)
      [[ $# -ge 2 ]] || fail "--http-image requires a value"
      http_image="$2"
      shift 2
      ;;
    --response-ip)
      [[ $# -ge 2 ]] || fail "--response-ip requires a value"
      response_ip="$2"
      shift 2
      ;;
    --canary-catalog)
      [[ $# -ge 2 ]] || fail "--canary-catalog requires a value"
      canary_catalog="$2"
      shift 2
      ;;
    --log-dir)
      [[ $# -ge 2 ]] || fail "--log-dir requires a value"
      log_dir="$2"
      shift 2
      ;;
    --env-file)
      [[ $# -ge 2 ]] || fail "--env-file requires a value"
      env_file="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v go >/dev/null 2>&1 || fail "go is required to build/check the DNS sinkhole"

[[ -n "$log_dir" ]] || fail "--log-dir is required"
require_name "run id" "$run_id"
require_name "sample id" "$sample_id"

if [[ -z "$network_name" ]]; then
  network_name="exfil-honeynet-$run_id"
fi
require_name "network name" "$network_name"

install -d -m 700 "$log_dir"
log_dir="$(cd "$log_dir" && pwd -P)"
dns_log="$log_dir/dns.jsonl"
ca_dir="$log_dir/ca"
install -d -m 700 "$ca_dir"
ca_cert="$ca_dir/exfil-analyzer-ca.pem"
canary_mount_args=()
if [[ -n "$canary_catalog" ]]; then
  [[ -f "$canary_catalog" ]] || fail "--canary-catalog must point to a regular file"
  canary_catalog="$(cd "$(dirname "$canary_catalog")" && pwd -P)/$(basename "$canary_catalog")"
  canary_mount_args=(
    --mount "type=bind,src=${canary_catalog},dst=/canary/canary.json,readonly"
    --env "EXFIL_CANARY_CATALOG=/canary/canary.json"
  )
fi

honeynet_user="${EXFIL_HONEYNET_USER:-$(id -u):$(id -g)}"
[[ "$honeynet_user" =~ ^[0-9]+:[0-9]+$ ]] || fail "EXFIL_HONEYNET_USER must be numeric UID:GID"
(( 10#${honeynet_user%%:*} != 0 )) || fail "refusing root UID 0 for honeynet service"
(( 10#${honeynet_user#*:} != 0 )) || fail "refusing root GID 0 for honeynet service"

if [[ "$build" == "1" ]]; then
  build_image "$dns_image" "$dns_dir"
  build_image "$http_image" "$http_dir"
else
  docker image inspect "$dns_image" >/dev/null 2>&1 || fail "missing image: $dns_image (use --build)"
  docker image inspect "$http_image" >/dev/null 2>&1 || fail "missing image: $http_image (use --build)"
fi

docker network create \
  --internal \
  --label exfil-analyzer.managed=true \
  --label exfil-analyzer.kind=honeynet-network \
  --label exfil-analyzer.phase=F1.3 \
  --label "exfil-analyzer.run_id=$run_id" \
  "$network_name" >/dev/null

http_log="$log_dir/http.jsonl"
network_log="$log_dir/network.jsonl"
http_container="exfil-honeynet-http-$run_id"
docker run -d \
  --rm \
  --pull never \
  --name "$http_container" \
  --label exfil-analyzer.managed=true \
  --label exfil-analyzer.kind=honeynet-http \
  --label exfil-analyzer.phase=F1.3 \
  --label "exfil-analyzer.run_id=$run_id" \
  --network "$network_name" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --user "$honeynet_user" \
  --pids-limit 64 \
  --memory 128m \
  --cpus 0.25 \
  --mount "type=bind,src=${log_dir},dst=/logs" \
  --mount "type=bind,src=${ca_dir},dst=/ca" \
  "${canary_mount_args[@]}" \
  --env "EXFIL_RUN_ID=$run_id" \
  --env "EXFIL_SAMPLE_ID=$sample_id" \
  --env "EXFIL_HTTP_LOG=/logs/http.jsonl" \
  --env "EXFIL_NETWORK_LOG=/logs/network.jsonl" \
  --env "EXFIL_TLS_CA_CERT=/ca/exfil-analyzer-ca.pem" \
  "$http_image" >/dev/null

sleep 0.3
http_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$http_container")"
[[ -n "$http_ip" ]] || fail "could not inspect HTTP container IP"
for _ in {1..50}; do
  [[ -s "$ca_cert" ]] && break
  sleep 0.1
done
[[ -s "$ca_cert" ]] || fail "TLS listener did not publish a CA certificate"
if grep -F "PRIVATE KEY" "$ca_cert" >/dev/null; then
  fail "CA certificate file contains private key material"
fi

if [[ -z "$response_ip" ]]; then
  response_ip="$http_ip"
fi

dns_container="exfil-honeynet-dns-$run_id"
docker run -d \
  --rm \
  --pull never \
  --name "$dns_container" \
  --label exfil-analyzer.managed=true \
  --label exfil-analyzer.kind=honeynet-dns \
  --label exfil-analyzer.phase=F1.3 \
  --label "exfil-analyzer.run_id=$run_id" \
  --network "$network_name" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --user "$honeynet_user" \
  --pids-limit 64 \
  --memory 128m \
  --cpus 0.25 \
  --mount "type=bind,src=${log_dir},dst=/logs" \
  --env "EXFIL_RUN_ID=$run_id" \
  --env "EXFIL_SAMPLE_ID=$sample_id" \
  --env "EXFIL_DNS_LOG=/logs/dns.jsonl" \
  --env "EXFIL_DNS_RESPONSE_IP=$response_ip" \
  "${canary_mount_args[@]}" \
  "$dns_image" >/dev/null

sleep 0.3
dns_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$dns_container")"
[[ -n "$dns_ip" ]] || fail "could not inspect DNS container IP"

{
  quote_env EXFIL_HONEYNET_NETWORK "$network_name"
  quote_env EXFIL_HONEYNET_DNS_IP "$dns_ip"
  quote_env EXFIL_HONEYNET_DNS_CONTAINER "$dns_container"
  quote_env EXFIL_HONEYNET_DNS_LOG "$dns_log"
  quote_env EXFIL_HONEYNET_HTTP_IP "$http_ip"
  quote_env EXFIL_HONEYNET_HTTP_CONTAINER "$http_container"
  quote_env EXFIL_HONEYNET_HTTP_LOG "$http_log"
  quote_env EXFIL_HONEYNET_NETWORK_LOG "$network_log"
  quote_env EXFIL_HONEYNET_CA_CERT "$ca_cert"
  quote_env EXFIL_HONEYNET_RESPONSE_IP "$response_ip"
} >"${env_file:-/dev/stdout}"
