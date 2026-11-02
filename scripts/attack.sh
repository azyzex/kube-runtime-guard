#!/usr/bin/env bash
# The "attacker": opens an interactive shell inside the orders-api pod and runs two commands.
# A TTY is needed for Falco's "Terminal shell in container" rule, so `script` provides one.
set -euo pipefail
POD=$(kubectl -n shop get pod -l app=orders-api -o jsonpath='{.items[0].metadata.name}')
echo "target pod: $POD"
date -u +"attack started: %H:%M:%S.%N UTC"
script -qec "kubectl -n shop exec -it $POD -- sh -c 'id; hostname'" /dev/null || true
echo "(shell closed)"
