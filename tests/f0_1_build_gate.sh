#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required_files=(
  "$repo_root/rust-observer/Cargo.toml"
  "$repo_root/rust-observer/snoop/Cargo.toml"
  "$repo_root/rust-observer/snoop-common/Cargo.toml"
  "$repo_root/rust-observer/snoop-ebpf/Cargo.toml"
  "$repo_root/java-analyzer/settings.gradle"
  "$repo_root/java-analyzer/build.gradle"
  "$repo_root/java-analyzer/gradlew"
  "$repo_root/java-analyzer/gradle/wrapper/gradle-wrapper.properties"
)

for path in "${required_files[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "missing required F0.1 skeleton file: $path" >&2
    exit 1
  fi
done

cargo build --manifest-path "$repo_root/rust-observer/Cargo.toml"
"$repo_root/java-analyzer/gradlew" --project-dir "$repo_root/java-analyzer" build
