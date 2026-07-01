#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dns_dir="$script_dir/dns-sinkhole"

usage() {
  cat >&2 <<'USAGE'
Usage: sandbox/honeynet/start.sh [--build] --log-dir DIR [OPTIONS]

Starts the F1.0 honeynet DNS sinkhole on a Docker internal network.

Options:
  --run-id ID          Run id written to dns.jsonl, default f1-0-<timestamp>-<pid>.
  --sample-id ID       Sample id written to dns.jsonl, default manual.
  --network-name NAME  Docker internal network name, default exfil-honeynet-<run-id>.
  --image IMAGE        DNS sinkhole image, default exfil-honeynet-dns:local.
  --response-ip IP     IPv4 returned for A records, default 198.51.100.53.
  --env-file FILE      Write source-able EXFIL_HONEYNET_* values to FILE.
  --build              Build the DNS sinkhole image before starting.
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
  local build_dir
  build_dir="$(mktemp -d)"
  trap 'rm -rf "$build_dir"' RETURN

  (cd "$dns_dir" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$build_dir/dns-sinkhole" .)
  docker build --pull=false -t "$image" -f "$dns_dir/Dockerfile" "$build_dir" >/dev/null
}

build=0
run_id="f1-0-$(date +%s)-$$"
sample_id="manual"
network_name=""
image="exfil-honeynet-dns:local"
response_ip="198.51.100.53"
log_dir=""
env_file=""

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
      image="$2"
      shift 2
      ;;
    --response-ip)
      [[ $# -ge 2 ]] || fail "--response-ip requires a value"
      response_ip="$2"
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

honeynet_user="${EXFIL_HONEYNET_USER:-$(id -u):$(id -g)}"
[[ "$honeynet_user" =~ ^[0-9]+:[0-9]+$ ]] || fail "EXFIL_HONEYNET_USER must be numeric UID:GID"
(( 10#${honeynet_user%%:*} != 0 )) || fail "refusing root UID 0 for honeynet service"
(( 10#${honeynet_user#*:} != 0 )) || fail "refusing root GID 0 for honeynet service"

if [[ "$build" == "1" ]]; then
  build_image "$image"
else
  docker image inspect "$image" >/dev/null 2>&1 || fail "missing image: $image (use --build)"
fi

docker network create \
  --internal \
  --label exfil-analyzer.managed=true \
  --label exfil-analyzer.kind=honeynet-network \
  --label exfil-analyzer.phase=F1.0 \
  --label "exfil-analyzer.run_id=$run_id" \
  "$network_name" >/dev/null

dns_container="exfil-honeynet-dns-$run_id"
docker run -d \
  --rm \
  --pull never \
  --name "$dns_container" \
  --label exfil-analyzer.managed=true \
  --label exfil-analyzer.kind=honeynet-dns \
  --label exfil-analyzer.phase=F1.0 \
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
  "$image" >/dev/null

sleep 0.3
dns_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$dns_container")"
[[ -n "$dns_ip" ]] || fail "could not inspect DNS container IP"

{
  quote_env EXFIL_HONEYNET_NETWORK "$network_name"
  quote_env EXFIL_HONEYNET_DNS_IP "$dns_ip"
  quote_env EXFIL_HONEYNET_DNS_CONTAINER "$dns_container"
  quote_env EXFIL_HONEYNET_DNS_LOG "$dns_log"
  quote_env EXFIL_HONEYNET_RESPONSE_IP "$response_ip"
} >"${env_file:-/dev/stdout}"
