#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: sandbox/run-sandboxed.sh [--dry-run] [--name NAME] IMAGE [COMMAND...]

Runs IMAGE with a hardened, fail-closed Docker profile for F0.2.
The image must already exist locally; this script uses --pull never.

Environment:
  EXFIL_SANDBOX_USERNS       Optional Docker user namespace mode. "host" is refused.
  EXFIL_SANDBOX_MEMORY       Memory limit, default 512m.
  EXFIL_SANDBOX_CPUS         CPU limit, default 1.
  EXFIL_SANDBOX_PIDS_LIMIT   PID limit, default 128.
  EXFIL_SANDBOX_TMPFS_SIZE   /tmp tmpfs size, default 64m.
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

if [[ "$userns_mode" == "host" ]]; then
  fail "refusing EXFIL_SANDBOX_USERNS=host because it disables user namespace isolation"
fi

docker_args=(
  # ref: /home/mrg/Desktop/exfil-step-a-refs/package-analysis/internal/sandbox/sandbox.go:295 (create container before run lifecycle)
  run
  --rm
  --pull never
  --name "$container_name"
  --label exfil-analyzer.managed=true
  --label exfil-analyzer.phase=F0.2
  # ref: /home/mrg/Desktop/exfil-step-a-refs/package-analysis/internal/sandbox/sandbox.go:309 (offline network=none)
  --network none
  # ref: docker run --help on Docker 29.6.0: --cap-drop, --security-opt, --read-only, --tmpfs, --user, --pids-limit, --memory, --cpus
  --cap-drop ALL
  --security-opt no-new-privileges
  --read-only
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=${tmpfs_size}"
  --tmpfs /run:rw,nosuid,nodev,size=16m
  --user 65532:65532
  --pids-limit "$pids_limit"
  --memory "$memory_limit"
  --cpus "$cpu_limit"
)

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
