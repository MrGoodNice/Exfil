#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: sandbox/run-sandboxed.sh [--dry-run] [--name NAME] [--canary-dir DIR]
                                [--ca-cert FILE]
                                [--honeynet-network NAME --honeynet-dns IP]
                                IMAGE [COMMAND...]

Runs IMAGE with a hardened, fail-closed Docker profile for F0.2.
The image must already exist locally; this script uses --pull never.

Environment:
  EXFIL_SANDBOX_USERNS       Optional Docker user namespace mode. "host" is refused.
  EXFIL_SANDBOX_MEMORY       Memory limit, default 512m.
  EXFIL_SANDBOX_CPUS         CPU limit, default 1.
  EXFIL_SANDBOX_PIDS_LIMIT   PID limit, default 128.
  EXFIL_SANDBOX_TMPFS_SIZE   /tmp tmpfs size, default 64m.
  EXFIL_SANDBOX_USER         Numeric non-root UID:GID, default 65532:65532.
USAGE
}

fail() {
  echo "run-sandboxed.sh: $*" >&2
  exit 1
}

shell_quote_command() {
  printf '%q' docker
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
}

docker_security_options() {
  docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true
}

require_docker_runtime_baseline() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"

  local security_options
  security_options="$(docker_security_options)"
  [[ "$security_options" == *"name=seccomp"* ]] ||
    fail "Docker daemon does not report seccomp support in SecurityOptions"
}

dry_run=0
container_name="exfil-f0-2-$(date +%s)-$$"
canary_dir=""
ca_cert=""
honeynet_network=""
honeynet_dns=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run=1
      shift
      ;;
    --name)
      [[ $# -ge 2 ]] || fail "--name requires a value"
      container_name="$2"
      shift 2
      ;;
    --canary-dir)
      [[ $# -ge 2 ]] || fail "--canary-dir requires a value"
      canary_dir="$2"
      shift 2
      ;;
    --ca-cert)
      [[ $# -ge 2 ]] || fail "--ca-cert requires a value"
      ca_cert="$2"
      shift 2
      ;;
    --honeynet-network)
      [[ $# -ge 2 ]] || fail "--honeynet-network requires a value"
      honeynet_network="$2"
      shift 2
      ;;
    --honeynet-dns)
      [[ $# -ge 2 ]] || fail "--honeynet-dns requires a value"
      honeynet_dns="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      fail "unknown option: $1"
      ;;
    *)
      break
      ;;
  esac
done

[[ $# -ge 1 ]] || {
  usage
  exit 2
}

image="$1"
shift

memory_limit="${EXFIL_SANDBOX_MEMORY:-512m}"
cpu_limit="${EXFIL_SANDBOX_CPUS:-1}"
pids_limit="${EXFIL_SANDBOX_PIDS_LIMIT:-128}"
tmpfs_size="${EXFIL_SANDBOX_TMPFS_SIZE:-64m}"
userns_mode="${EXFIL_SANDBOX_USERNS:-}"
container_user="${EXFIL_SANDBOX_USER:-65532:65532}"

if [[ "$userns_mode" == "host" ]]; then
  fail "refusing EXFIL_SANDBOX_USERNS=host because it disables user namespace isolation"
fi

# Refuse any container user that resolves to root. Numeric UID[:GID] only, so an
# image-supplied username (which could map to uid 0) cannot be smuggled in; leading
# zeros ("00"/"000") are normalized via base-10 so they cannot bypass the check.
[[ "$container_user" =~ ^[0-9]+(:[0-9]+)?$ ]] ||
  fail "EXFIL_SANDBOX_USER must be numeric UID[:GID], got: $container_user"
(( 10#${container_user%%:*} != 0 )) ||
  fail "refusing root UID 0 (including 00/000): $container_user"
if [[ "$container_user" == *:* ]]; then
  (( 10#${container_user#*:} != 0 )) ||
    fail "refusing root GID 0: $container_user"
fi

if [[ -n "$canary_dir" ]]; then
  [[ -d "$canary_dir" ]] || fail "--canary-dir must be an existing directory: $canary_dir"
  canary_dir="$(cd "$canary_dir" && pwd -P)"
fi

if [[ -n "$ca_cert" ]]; then
  [[ -f "$ca_cert" ]] || fail "--ca-cert must be an existing file: $ca_cert"
  ca_cert="$(cd "$(dirname "$ca_cert")" && pwd -P)/$(basename "$ca_cert")"
fi

if [[ -n "$honeynet_network" || -n "$honeynet_dns" ]]; then
  [[ -n "$honeynet_network" ]] || fail "--honeynet-dns requires --honeynet-network"
  [[ -n "$honeynet_dns" ]] || fail "--honeynet-network requires --honeynet-dns"
  case "$honeynet_network" in
    host|bridge|none)
      fail "refusing Docker builtin network for honeynet mode: $honeynet_network"
      ;;
  esac
fi

network_args=(--network none)
container_phase="F0.2"
if [[ -n "$honeynet_network" ]]; then
  # ref: docker run --help on Docker 29.6.0: --network connects to a named network; --dns sets container resolvers.
  network_args=(--network "$honeynet_network" --dns "$honeynet_dns")
  container_phase="F1.0"
fi

docker_args=(
  # ref: /home/mrg/Desktop/exfil-step-a-refs/package-analysis/internal/sandbox/sandbox.go:295 (create container before run lifecycle)
  run
  --rm
  --pull never
  --name "$container_name"
  --label exfil-analyzer.managed=true
  --label "exfil-analyzer.phase=${container_phase}"
  "${network_args[@]}"
  # ref: docker run --help on Docker 29.6.0: --cap-drop, --security-opt, --read-only, --tmpfs, --user, --pids-limit, --memory, --cpus
  --cap-drop ALL
  --security-opt no-new-privileges
  --read-only
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=${tmpfs_size}"
  --tmpfs /run:rw,nosuid,nodev,size=16m
  --user "$container_user"
  --pids-limit "$pids_limit"
  --memory "$memory_limit"
  --cpus "$cpu_limit"
)

if [[ -n "$canary_dir" ]]; then
  # ref: docker run --help on Docker 29.6.0: --mount mount attaches a filesystem mount.
  docker_args+=(--mount "type=bind,src=${canary_dir},dst=/canary,readonly")
fi

if [[ -n "$ca_cert" ]]; then
  # ref: crypto/x509 SystemCertPool docs on Go 1.26: SSL_CERT_FILE/SSL_CERT_DIR override Unix roots.
  docker_args+=(
    --tmpfs /etc/ssl/certs:rw,nosuid,nodev,size=1m
    --mount "type=bind,src=${ca_cert},dst=/tmp/exfil-analyzer-ca.pem,readonly"
    --mount "type=bind,src=${ca_cert},dst=/etc/ssl/certs/exfil-analyzer-ca.pem,readonly"
    --env SSL_CERT_FILE=/tmp/exfil-analyzer-ca.pem
    --env SSL_CERT_DIR=/etc/ssl/certs
    --env NODE_EXTRA_CA_CERTS=/tmp/exfil-analyzer-ca.pem
    --env REQUESTS_CA_BUNDLE=/tmp/exfil-analyzer-ca.pem
    --env CURL_CA_BUNDLE=/tmp/exfil-analyzer-ca.pem
    --env GIT_SSL_CAINFO=/tmp/exfil-analyzer-ca.pem
  )
fi

if [[ -n "$userns_mode" ]]; then
  # ref: https://docs.docker.com/engine/security/userns-remap/ (--userns=host disables remapping; non-host modes are operator-provided)
  docker_args+=(--userns "$userns_mode")
fi

docker_args+=("$image")
docker_args+=("$@")

if [[ "$dry_run" == "1" ]]; then
  shell_quote_command "${docker_args[@]}"
  exit 0
fi

require_docker_runtime_baseline

security_options="$(docker_security_options)"
if [[ -z "$userns_mode" && "$security_options" != *"name=userns"* ]]; then
  echo "run-sandboxed.sh: warning: Docker daemon userns-remap is not enabled; set EXFIL_SANDBOX_USERNS to a safe non-host mode if your daemon supports one" >&2
fi

exec docker "${docker_args[@]}"
