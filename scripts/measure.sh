#!/usr/bin/env bash
# Runs N attacks and prints the numbers for the README: detection + response latency, RAM.
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-5}"
mkdir -p results/raw
kubectl -n guard-system port-forward svc/responder 18080:8080 >/dev/null 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT; sleep 2
for i in $(seq 1 "$N"); do
  kubectl -n shop rollout status deploy/orders-api --timeout=120s >/dev/null
  OLD=$(kubectl -n shop get pod -l app=orders-api -o jsonpath='{.items[0].metadata.name}')
  T0=$(date +%s.%N)
  bash scripts/attack.sh >/dev/null 2>&1
  # wait until the attacked pod is gone and a new one is Ready
  until ! kubectl -n shop get pod "$OLD" >/dev/null 2>&1; do sleep 0.1; done
  T1=$(date +%s.%N)
  kubectl -n shop rollout status deploy/orders-api --timeout=120s >/dev/null
  T2=$(date +%s.%N)
  python3 -c "print(f'run $i: attack -> pod gone {$T1-$T0:.2f} s · attack -> clean pod ready {$T2-$T0:.2f} s')"
  sleep 32   # longer than the responder cooldown
done
curl -s localhost:18080/stats > results/raw/stats.json
python3 - <<'PY'
import json, statistics as st
rows = [r for r in json.load(open("results/raw/stats.json")) if r["decision"] == "delete"]
a = [r["alert_latency_s"] for r in rows if r.get("alert_latency_s") is not None]
b = [r["response_s"] for r in rows if r.get("response_s") is not None]
print(f"\ncontainment actions: {len(rows)}")
if a: print(f"syscall -> responder (Falco + Falcosidekick): median {st.median(a):.3f} s, max {max(a):.3f} s")
if b: print(f"responder -> pod deleted (K8s API):          median {st.median(b):.3f} s, max {max(b):.3f} s")
PY
echo; echo "RAM (k3d node container = whole cluster):"
docker stats --no-stream --format '{{.Name}}: {{.MemUsage}}' | grep k3d-guard
