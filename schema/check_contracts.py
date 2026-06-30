#!/usr/bin/env python3
import json
import sys
from copy import deepcopy
from importlib.metadata import version
from pathlib import Path

try:
    # ref: jsonschema 4.26.0 jsonschema/validators.py:306 (check_schema), :448 (validate)
    from jsonschema.validators import Draft202012Validator
    # ref: jsonschema 4.26.0 jsonschema/exceptions.py:200 (ValidationError)
    from jsonschema.exceptions import ValidationError
except ModuleNotFoundError as exc:
    raise SystemExit(
        "missing dev dependency: install with "
        "`python3 -m pip install -r requirements-dev.txt`"
    ) from exc


SCHEMA_DIR = Path(__file__).resolve().parent
EXPECTED_JSONSCHEMA_VERSION = "4.26.0"
VALIDATOR_KWARGS = {
    # ref: jsonschema 4.26.0 jsonschema/validators.py:228 (FORMAT_CHECKER)
    "format_checker": Draft202012Validator.FORMAT_CHECKER,
}


def load_schema(name):
    path = SCHEMA_DIR / name
    if not path.exists():
        raise AssertionError(f"missing schema: {name}")
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def require_property(schema, name):
    properties = schema.get("properties", {})
    if name not in properties:
        raise AssertionError(f"{schema.get('title', '<schema>')} missing property: {name}")
    return properties[name]


def require_required(schema, names):
    required = set(schema.get("required", []))
    missing = [name for name in names if name not in required]
    if missing:
        raise AssertionError(f"{schema.get('title', '<schema>')} required missing: {missing}")


def require_object_schema(schema, name):
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise AssertionError(f"{name} must use JSON Schema draft 2020-12")
    if schema.get("type") != "object":
        raise AssertionError(f"{name} must describe a JSON object")
    if schema.get("additionalProperties") is not False:
        raise AssertionError(f"{name} must reject unknown properties")


def require_nullable_string(prop, schema_name, property_name):
    if prop.get("type") != ["string", "null"]:
        raise AssertionError(f"{schema_name}.{property_name} must be ['string', 'null']")


def require_string_array(prop, schema_name, property_name):
    if prop.get("type") != "array" or prop.get("items", {}).get("type") != "string":
        raise AssertionError(f"{schema_name}.{property_name} must be an array of strings")


def valid_instances():
    now = "2026-06-30T12:00:00Z"
    return {
        "network.schema.json": {
            "ts": now,
            "run_id": "run-001",
            "sample_id": "sample-001",
            "source": "honeynet",
            "flow_id": "flow-001",
            "pid": None,
            "src_ip": "172.18.0.2",
            "src_port": 43122,
            "dst_ip": "203.0.113.10",
            "dst_port": 443,
            "proto": "tcp",
            "retval": None,
            "container_id": "container-001",
            "cgroup_id": "123456789",
        },
        "http.schema.json": {
            "ts": now,
            "run_id": "run-001",
            "sample_id": "sample-001",
            "flow_id": "flow-001",
            "method": "POST",
            "host": "example.test",
            "path": "/collect",
            "tls": True,
            "opaque_reason": None,
            "canary_match": ["secret-001"],
            "request_body_sha256": "a" * 64,
            "response_body_sha256": None,
            "upstream": False,
        },
        "dns.schema.json": {
            "ts": now,
            "run_id": "run-001",
            "sample_id": "sample-001",
            "query": "secret-001.example.test",
            "qtype": "A",
            "resolved_ip": "203.0.113.10",
            "canary_match": ["secret-001"],
            "sinkholed": True,
            "container_id": "container-001",
        },
        "files.schema.json": {
            "ts": now,
            "run_id": "run-001",
            "sample_id": "sample-001",
            "pid": 4242,
            "tgid": 4242,
            "comm": "curl",
            "path": "/run/exfil-analyzer/canary_rsa",
            "is_canary": True,
            "container_id": "container-001",
            "cgroup_id": "123456789",
        },
        "proc.schema.json": {
            "ts": now,
            "run_id": "run-001",
            "sample_id": "sample-001",
            "pid": 4242,
            "ppid": 4200,
            "tgid": 4242,
            "comm": "curl",
            "exe": "/usr/bin/curl",
            "argv_hash": "b" * 64,
            "event": "execve",
            "container_id": "container-001",
            "cgroup_id": "123456789",
        },
        "manifest.schema.json": {
            "repo": "https://github.com/example/package",
            "generated_at": now,
            "analyzer_version": "0.1.0",
            "items": [
                {
                    "type": "url",
                    "value": "https://example.test/collect",
                    "evidence": [
                        {
                            "path": "package.json",
                            "line": 12,
                            "snippet": "curl https://example.test/collect",
                            "rule": "capability-network-outbound",
                        }
                    ],
                    "capability": "network-outbound",
                    "threat": "filesystem-read",
                    "confidence": "high",
                    "suspicious": True,
                }
            ],
        },
        "canary.schema.json": {
            "run_id": "run-001",
            "generated_at": now,
            "secrets": [
                {
                    "secret_id": "secret-001",
                    "type": "canary_rsa",
                    "path": "/run/exfil-analyzer/canary_rsa",
                    "env_name": None,
                    "match_token": "EXFIL_CANARY_SECRET_001",
                }
            ],
        },
    }


def expect_valid(schema, instance, label):
    Draft202012Validator(schema, **VALIDATOR_KWARGS).validate(instance)


def expect_invalid(schema, instance, label):
    try:
        Draft202012Validator(schema, **VALIDATOR_KWARGS).validate(instance)
    except ValidationError:
        return
    raise AssertionError(f"{label} unexpectedly validated")


def without(instance, key):
    copy = deepcopy(instance)
    del copy[key]
    return copy


def with_value(instance, key, value):
    copy = deepcopy(instance)
    copy[key] = value
    return copy


def invalid_instances(good):
    return {
        "network.schema.json": [
            without(good["network.schema.json"], "flow_id"),
            with_value(good["network.schema.json"], "dst_port", "443"),
            with_value(good["network.schema.json"], "unexpected", True),
            with_value(good["network.schema.json"], "ts", "not-a-date-time"),
        ],
        "http.schema.json": [
            without(good["http.schema.json"], "canary_match"),
            with_value(good["http.schema.json"], "flow_id", 17),
            with_value(good["http.schema.json"], "unexpected", True),
        ],
        "dns.schema.json": [
            without(good["dns.schema.json"], "canary_match"),
            with_value(good["dns.schema.json"], "canary_match", "secret-001"),
            with_value(good["dns.schema.json"], "unexpected", True),
        ],
        "files.schema.json": [
            without(good["files.schema.json"], "is_canary"),
            with_value(good["files.schema.json"], "pid", "4242"),
            with_value(good["files.schema.json"], "unexpected", True),
        ],
        "proc.schema.json": [
            without(good["proc.schema.json"], "tgid"),
            with_value(good["proc.schema.json"], "event", "fork"),
            with_value(good["proc.schema.json"], "unexpected", True),
        ],
        "manifest.schema.json": [
            without(good["manifest.schema.json"], "items"),
            with_value(good["manifest.schema.json"], "items", "not-an-array"),
            with_value(good["manifest.schema.json"], "unexpected", True),
        ],
        "canary.schema.json": [
            without(good["canary.schema.json"], "secrets"),
            with_value(good["canary.schema.json"], "secrets", "not-an-array"),
            with_value(good["canary.schema.json"], "unexpected", True),
        ],
    }


def main():
    if version("jsonschema") != EXPECTED_JSONSCHEMA_VERSION:
        raise AssertionError(
            f"jsonschema version must be {EXPECTED_JSONSCHEMA_VERSION}, got {version('jsonschema')}"
        )

    network = load_schema("network.schema.json")
    http = load_schema("http.schema.json")
    dns = load_schema("dns.schema.json")
    files = load_schema("files.schema.json")
    proc = load_schema("proc.schema.json")
    manifest = load_schema("manifest.schema.json")
    canary = load_schema("canary.schema.json")

    schemas = {
        "network.schema.json": network,
        "http.schema.json": http,
        "dns.schema.json": dns,
        "files.schema.json": files,
        "proc.schema.json": proc,
        "manifest.schema.json": manifest,
        "canary.schema.json": canary,
    }

    for name, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
        require_object_schema(schema, name)

    require_nullable_string(require_property(network, "flow_id"), "network", "flow_id")
    require_nullable_string(require_property(http, "flow_id"), "http", "flow_id")

    http_canary = require_property(http, "canary_match")
    require_string_array(http_canary, "http", "canary_match")
    description = http_canary.get("description", "").lower()
    if "заголов" not in description or "тел" not in description:
        raise AssertionError("http.canary_match description must state headers and body scanning")

    require_string_array(require_property(dns, "canary_match"), "dns", "canary_match")

    require_required(manifest, ["repo", "generated_at", "analyzer_version", "items"])
    manifest_item = manifest.get("properties", {}).get("items", {}).get("items", {})
    require_required(
        manifest_item,
        ["type", "value", "evidence", "capability", "threat", "confidence", "suspicious"],
    )
    for field in ["type", "value", "evidence", "capability", "threat", "confidence"]:
        require_property(manifest_item, field)
    if require_property(manifest_item, "suspicious").get("type") != "boolean":
        raise AssertionError("manifest item suspicious must be boolean")

    require_required(canary, ["run_id", "generated_at", "secrets"])
    secret_item = canary.get("properties", {}).get("secrets", {}).get("items", {})
    require_required(secret_item, ["secret_id", "type", "path", "match_token"])
    for field in ["secret_id", "type", "path", "env_name", "match_token"]:
        require_property(secret_item, field)

    good = valid_instances()
    bad = invalid_instances(good)
    for name, instance in good.items():
        expect_valid(schemas[name], instance, f"{name} valid fixture")
    for name, instances in bad.items():
        for index, instance in enumerate(instances, start=1):
            expect_invalid(schemas[name], instance, f"{name} invalid fixture {index}")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
