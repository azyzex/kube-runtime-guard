"""responder: receives Falco alerts (via Falcosidekick's webhook output) and contains the pod.

Containment, not remediation: deleting the pod stops the live intrusion and lets the
Deployment start a clean replacement, but whatever weakness let the attacker in is still
in the image. That is fixed elsewhere (image scanning, admission policies).

Guardrails:
  - only rules in RESPOND_RULES trigger an action
  - only pods in PROTECTED_NAMESPACES are touched (never kube-system or the responder itself)
  - one action per pod per COOLDOWN_S (no loops)
  - DRY_RUN=true logs what it would do without deleting
"""
import json
import logging
import os
import re
import ssl
import time
import urllib.request
from datetime import datetime
from urllib.error import HTTPError

from fastapi import FastAPI, Request

log = logging.getLogger("responder")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

RESPOND_RULES = {r.strip() for r in os.getenv("RESPOND_RULES", "Terminal shell in container").split(",") if r.strip()}
PROTECTED_NAMESPACES = {n.strip() for n in os.getenv("PROTECTED_NAMESPACES", "shop").split(",") if n.strip()}
COOLDOWN_S = float(os.getenv("COOLDOWN_S", "30"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
SLACK_FILE = os.getenv("SLACK_WEBHOOK_FILE", "/secrets/slack-webhook")

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
API = f"https://{os.getenv('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc')}:{os.getenv('KUBERNETES_SERVICE_PORT', '443')}"

app = FastAPI(title="responder")
_last_action: dict[str, float] = {}
HISTORY: list[dict] = []


def parse_falco_time(t: str) -> float:
    """Falco time is RFC3339 with nanoseconds; Python handles microseconds."""
    m = re.fullmatch(r"(.+?)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)", t)
    if not m:
        raise ValueError(f"bad time: {t}")
    head, frac, tz = m.group(1), (m.group(2) or "0"), m.group(3).replace("Z", "+00:00")
    return datetime.fromisoformat(f"{head}.{frac[:6].ljust(6, '0')}{tz}").timestamp()


def k8s_delete_pod(ns: str, pod: str) -> int:
    token = open(f"{SA}/token").read()
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    req = urllib.request.Request(
        f"{API}/api/v1/namespaces/{ns}/pods/{pod}",
        method="DELETE",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps({"gracePeriodSeconds": 0}).encode(),
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return r.status
    except HTTPError as e:
        return e.code


def slack(text: str) -> None:
    try:
        url = open(SLACK_FILE).read().strip()
    except OSError:
        return
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(), headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:  # a Slack outage must never block containment
        log.warning("slack post failed: %s", e)


def decide(alert: dict) -> tuple[str, str, str]:
    """Return (decision, namespace, pod). Pure logic: unit-tested."""
    rule = alert.get("rule", "")
    f = alert.get("output_fields", {}) or {}
    ns, pod = f.get("k8s.ns.name") or "", f.get("k8s.pod.name") or ""
    if rule not in RESPOND_RULES:
        return "ignored: rule not in allow-list", ns, pod
    if not ns or not pod:
        return "ignored: no pod metadata", ns, pod
    if ns not in PROTECTED_NAMESPACES:
        return "ignored: namespace not protected", ns, pod
    if time.time() - _last_action.get(f"{ns}/{pod}", 0) < COOLDOWN_S:
        return "ignored: cooldown", ns, pod
    return ("dry-run: would delete" if DRY_RUN else "delete"), ns, pod


@app.post("/falco")
async def falco(request: Request) -> dict:
    received = time.time()
    alert = await request.json()
    decision, ns, pod = decide(alert)
    record = {"rule": alert.get("rule"), "namespace": ns, "pod": pod, "decision": decision}
    try:
        record["alert_latency_s"] = round(received - parse_falco_time(alert["time"]), 3)
    except Exception:
        record["alert_latency_s"] = None

    if decision == "delete":
        _last_action[f"{ns}/{pod}"] = received
        status = k8s_delete_pod(ns, pod)
        record["k8s_status"] = status
        record["response_s"] = round(time.time() - received, 3)
        ok = status in (200, 202)
        slack(
            f":shield: *Contained* `{ns}/{pod}` (rule: {alert.get('rule')}). "
            f"Pod {'deleted' if ok else f'NOT deleted (HTTP {status})'}; the Deployment starts a clean one.\n"
            f"syscall → responder: {record['alert_latency_s']} s · responder → pod deleted: {record['response_s']} s\n"
            "_Containment, not remediation: the weakness is still in the image._"
        )
    log.info(json.dumps(record))
    HISTORY.append({**record, "at": received})
    del HISTORY[:-200]
    return record


@app.get("/stats")
def stats() -> list[dict]:
    return HISTORY


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "dry_run": DRY_RUN, "rules": sorted(RESPOND_RULES), "namespaces": sorted(PROTECTED_NAMESPACES)}
