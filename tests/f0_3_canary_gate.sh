#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$repo_root/sandbox/canary-gen.sh"
schema="$repo_root/schema/canary.schema.json"
python_bin="${PYTHON:-python3}"

fail() {
  echo "F0.3 gate failed: $*" >&2
  exit 1
}

[[ -f "$script" ]] || fail "missing file: $script"
[[ -x "$script" ]] || fail "not executable: $script"
[[ -f "$schema" ]] || fail "missing schema: $schema"

for forbidden in "curl" "wget" "nc " "ncat" "socat" "/dev/tcp" "ssh " "scp " "rsync" "ftp " "http://" "https://"; do
  if grep -Rsn -- "$forbidden" "$script" >/dev/null; then
    fail "network primitive found in canary generator: $forbidden"
  fi
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

out_a="$tmpdir/run-a"
out_b="$tmpdir/run-b"
mkdir -p "$out_a" "$out_b"

catalog_a="$("$script" --target-dir "$out_a" --run-id run-a)"
catalog_b="$("$script" --target-dir "$out_b" --run-id run-b)"

[[ "$catalog_a" == "$out_a/canary.json" ]] || fail "unexpected catalog path for run-a: $catalog_a"
[[ "$catalog_b" == "$out_b/canary.json" ]] || fail "unexpected catalog path for run-b: $catalog_b"
[[ -f "$catalog_a" ]] || fail "catalog missing for run-a"
[[ -f "$catalog_b" ]] || fail "catalog missing for run-b"

"$python_bin" - "$schema" "$catalog_a" "$catalog_b" <<'PY'
import json
import re
import sys
from pathlib import Path

try:
    # ref: jsonschema 4.26.0 jsonschema/validators.py:306 (check_schema), :448 (validate)
    from jsonschema.validators import Draft202012Validator
except ModuleNotFoundError as exc:
    raise SystemExit(
        "missing jsonschema: run with PYTHON pointing at a venv created from requirements-dev.txt"
    ) from exc

schema_path, catalog_a_path, catalog_b_path = map(Path, sys.argv[1:])
schema = json.loads(schema_path.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
if "date-time" not in Draft202012Validator.FORMAT_CHECKER.checkers:
    raise SystemExit("jsonschema format extra is required: install requirements-dev.txt")
validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)

catalogs = [
    json.loads(catalog_a_path.read_text(encoding="utf-8")),
    json.loads(catalog_b_path.read_text(encoding="utf-8")),
]
for catalog in catalogs:
    validator.validate(catalog)

token_re = re.compile(r"^[0-9a-z]{25}$")
aws_key_id_re = re.compile(r"^AKIA[0-9A-Z]{16}$")
secret_key_re = re.compile(r"^[A-Za-z0-9/+=]{40}$")
expected_types = {"canary_rsa", "aws_access_key", "env_token", "kubeconfig"}

all_tokens = []
for catalog_path, catalog in zip([catalog_a_path, catalog_b_path], catalogs):
    base = catalog_path.parent
    secrets = catalog["secrets"]
    types = {secret["type"] for secret in secrets}
    if types != expected_types:
        raise AssertionError(f"unexpected secret types for {catalog_path}: {types}")
    for secret in secrets:
        token = secret["match_token"]
        if not token_re.fullmatch(token):
            raise AssertionError(f"bad match_token format: {token}")
        all_tokens.append(token)
        path = Path(secret["path"])
        if not path.is_absolute():
            raise AssertionError(f"secret path must be absolute: {path}")
        if not path.is_relative_to(base):
            raise AssertionError(f"secret path escapes target dir: {path}")
        text = path.read_text(encoding="utf-8")
        if token not in text:
            raise AssertionError(f"match_token not present in file: {path}")

        if secret["type"] == "canary_rsa":
            if "BEGIN RSA PRIVATE KEY" not in text or "END RSA PRIVATE KEY" not in text:
                raise AssertionError("canary_rsa does not look like an RSA private key")
        elif secret["type"] == "aws_access_key":
            key_id = re.search(r"aws_access_key_id\s*=\s*(\S+)", text)
            secret_key = re.search(r"aws_secret_access_key\s*=\s*(\S+)", text)
            if not key_id or not aws_key_id_re.fullmatch(key_id.group(1)):
                raise AssertionError("bad fake AWS access key id")
            if not secret_key or not secret_key_re.fullmatch(secret_key.group(1)):
                raise AssertionError("bad fake AWS secret access key")
        elif secret["type"] == "env_token":
            if secret.get("env_name") != "EXFIL_CANARY_TOKEN":
                raise AssertionError("env_token must declare EXFIL_CANARY_TOKEN")
            if "EXFIL_CANARY_TOKEN=" not in text:
                raise AssertionError("env file missing EXFIL_CANARY_TOKEN")
        elif secret["type"] == "kubeconfig":
            for needle in ["apiVersion: v1", "kind: Config", "clusters:", "users:", "contexts:"]:
                if needle not in text:
                    raise AssertionError(f"kubeconfig missing {needle}")

if len(set(all_tokens)) != len(all_tokens):
    raise AssertionError("match_token values must be unique across runs and secret types")
PY
