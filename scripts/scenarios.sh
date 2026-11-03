#!/usr/bin/env bash
# Add-on 2: several attack scenarios + one false-positive case, against the running cluster.
# For each: run the action, wait for the responder to receive Falco's alert, record rule + decision +
# whether the pod survived. Writes results/scenarios.md.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p results
kubectl -n guard-system port-forward svc/responder 18080:8080 >/dev/null 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT; sleep 3

pod() { kubectl -n shop get pod -l app=orders-api -o jsonpath='{.items[0].metadata.name}'; }
n_stats() { curl -s localhost:18080/stats | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))'; }
last_stat() { curl -s localhost:18080/stats | python3 -c 'import json,sys;d=json.load(sys.stdin);print(json.dumps(d[-1]) if d else "{}")'; }

ROWS=()
run() {  # id, description, command-using-$P, expected-rule
  local id=$1 what=$2 cmd=$3 expect=$4
  kubectl -n shop rollout status deploy/orders-api --timeout=120s >/dev/null
  local P; P=$(pod); local before; before=$(n_stats)
  eval "$cmd" >/dev/null 2>&1 || true
  local got="{}"
  for _ in $(seq 1 40); do
    [ "$(n_stats)" -gt "$before" ] && { got=$(last_stat); break; }; sleep 0.5
  done
  sleep 3
  local alive="yes"; kubectl -n shop get pod "$P" >/dev/null 2>&1 || alive="no (replaced)"
  local rule decision lat
  rule=$(echo "$got" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("rule","(no alert)"))')
  decision=$(echo "$got" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("decision","-"))')
  lat=$(echo "$got" | python3 -c 'import json,sys;v=json.load(sys.stdin).get("alert_latency_s");print("-" if v is None else v)')
  local ok="✅"; [ "$rule" = "$expect" ] || ok="❌ expected: $expect"
  ROWS+=("| $id | $what | $rule | $decision | $lat s | $alive | $ok |")
  echo "$id: $rule -> $decision (pod alive: $alive) $ok"
  sleep 32   # longer than the responder cooldown
}

run S1 "interactive shell in the pod (attacker)" \
  'script -qec "kubectl -n shop exec -it $P -- sh -c id" /dev/null' "Terminal shell in container"
run S2 "read /etc/shadow (credential theft)" \
  'kubectl -n shop exec $P -- cat /etc/shadow' "Read sensitive file untrusted"
run S3 "search for private keys" \
  'kubectl -n shop exec $P -- find / -name id_rsa' "Search Private Keys or Passwords"
run FP "operator's sanctioned debug shell (break-glass label)" \
  'kubectl -n shop label pod $P guard.fibertwin.io/break-glass=true --overwrite && script -qec "kubectl -n shop exec -it $P -- sh -c id" /dev/null' \
  "Terminal shell in container"

{
  echo "# Attack scenarios and false-positive tuning (add-on 2)"
  echo
  echo "Run by \`scripts/scenarios.sh\` on $(date -u +%F) ($(kubectl version -o json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])' 2>/dev/null), Falco modern eBPF)."
  echo
  echo "| # | Scenario | Falco rule | Responder decision | syscall → responder | Pod survived | |"
  echo "|---|---|---|---|---|---|---|"
  printf '%s\n' "${ROWS[@]}"
} > results/scenarios.md
cat results/scenarios.md
grep -q "❌" results/scenarios.md && exit 1 || exit 0
