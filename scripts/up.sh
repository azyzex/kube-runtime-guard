#!/usr/bin/env bash
# One command: cluster + app + responder + Falco/Falcosidekick. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."
CLUSTER=guard
WEBHOOK_FILE="${SLACK_WEBHOOK_FILE:-$HOME/.secrets/slack-webhook}"
say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

say "1/5 k3d cluster '$CLUSTER' (traefik + metrics-server off to save RAM)"
k3d cluster list | grep -q "^$CLUSTER " || k3d cluster create "$CLUSTER" --servers 1 --agents 0 \
  --k3s-arg "--disable=traefik@server:0" --k3s-arg "--disable=metrics-server@server:0" --wait

say "2/5 build images and load them into the cluster"
docker build -q -t orders-api:0.1 app
docker build -q -t responder:0.1 responder
k3d image import -c "$CLUSTER" orders-api:0.1 responder:0.1

say "3/5 app (namespace shop) + responder (namespace guard-system)"
kubectl apply -f k8s/app.yaml -f k8s/responder.yaml
if [ -r "$WEBHOOK_FILE" ]; then
  kubectl -n guard-system create secret generic slack-webhook --from-file=slack-webhook="$WEBHOOK_FILE" \
    --dry-run=client -o yaml | kubectl apply -f -
fi
kubectl -n shop rollout status deploy/orders-api --timeout=120s
kubectl -n guard-system rollout restart deploy/responder >/dev/null
kubectl -n guard-system rollout status deploy/responder --timeout=120s

say "4/5 Falco + Falcosidekick (modern eBPF)"
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
SLACK_ARGS=()
# tr strips the trailing newline: Falcosidekick rejects a URL that ends with one
[ -r "$WEBHOOK_FILE" ] && SLACK_ARGS=(--set falcosidekick.config.slack.webhookurl="$(tr -d '\n\r' < "$WEBHOOK_FILE")")
helm upgrade --install falco falcosecurity/falco --version 9.2.2 -n falco --create-namespace \
  -f falco/values.yaml "${SLACK_ARGS[@]}" --wait --timeout 10m

say "5/5 status"
kubectl get pods -A -o wide | grep -E "NAMESPACE|shop|guard-system|falco"
