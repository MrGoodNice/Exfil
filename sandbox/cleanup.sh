#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  exit 0
fi

# ref: /home/mrg/Desktop/exfil-step-a-refs/package-analysis/internal/sandbox/sandbox.go:95 (Clean is safe after use)
mapfile -t containers < <(docker ps -aq --filter label=exfil-analyzer.managed=true 2>/dev/null || true)
if [[ "${#containers[@]}" -gt 0 ]]; then
  docker rm -f "${containers[@]}" >/dev/null
fi
