#!/bin/sh
set -eu

# ref: /home/mrg/Desktop/exfil-step-a-refs/package-analysis/internal/dynamicanalysis/analysis.go:35 (runner executes a command and records runtime behavior)
echo "EXFIL_SAMPLE name=benign canary_read=0 egress_attempt=1"

if wget -T 3 -q -O /tmp/benign-download.txt http://example.com/; then
  echo "EXFIL_SAMPLE name=benign egress_result=unexpected_success"
else
  echo "EXFIL_SAMPLE name=benign egress_result=failed_expected"
fi
