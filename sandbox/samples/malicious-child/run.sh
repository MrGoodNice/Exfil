#!/usr/bin/env bash
set -euo pipefail

sample_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sandbox_dir="$(cd "$sample_dir/../.." && pwd)"
image="${EXFIL_SAMPLE_MALICIOUS_CHILD_IMAGE:-exfil-analyzer-sample-malicious-child:local}"
canary_dir=""
build=0

usage() {
  echo "Usage: $0 [--build] --canary-dir DIR" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)
      build=1
      shift
      ;;
    --canary-dir)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      canary_dir="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n "$canary_dir" ]] || { usage; exit 2; }

if [[ "$build" == "1" ]]; then
  docker build --pull=false -t "$image" "$sample_dir"
fi

EXFIL_SANDBOX_USER="$(id -u):$(id -g)" exec "$sandbox_dir/run-sandboxed.sh" --canary-dir "$canary_dir" "$image"
