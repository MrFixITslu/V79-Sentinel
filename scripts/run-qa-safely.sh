#!/usr/bin/env bash
# Manual, sequential, public-page-only QA on the Acer.
set -euo pipefail
cd "$(dirname "$0")/.."
exec 9>data/.qa-run.lock
if ! flock -n 9; then
  echo "Sentinel QA is already running. No overlapping Chrome sessions allowed." >&2
  exit 2
fi
echo "Starting public-page QA: seven approved services, two viewports; no logins or form writes."
echo "Safety limit: 240 seconds. Intermediate reports are saved after every browser check."
timeout -k 5s 240s node qa/run.js "$@"
