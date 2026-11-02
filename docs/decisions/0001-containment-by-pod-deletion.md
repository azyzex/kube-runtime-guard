# 0001: Respond to a shell in a container by deleting the pod

- **Date:** 2 Nov 2026
- **Status:** accepted

## Problem
Falco detects an interactive shell inside a production pod. Someone (or something) is inside the container right now. What should happen automatically, without waiting for a human?

## Options
1. **Alert only** (Slack) and let a human decide. Safe, but the attacker keeps working until someone reads the message.
2. **Delete the pod.** The Deployment immediately starts a clean replacement from the original image. The live session is cut and anything the attacker changed on the pod's filesystem is gone.
3. **Network-isolate the pod** (a NetworkPolicy that blocks all traffic) and keep it for forensics. Better for investigation, but needs a CNI that enforces policies and more logic.
4. **Kill only the shell process.** Precise, but the attacker can open another one.

## Choice
Option 2, with guardrails: only one rule triggers it, only in namespace `shop`, a 30 s cooldown per pod, a dry-run switch, and the responder's ServiceAccount can only `get`/`delete` pods in `shop` (a Role, not a ClusterRole).

## Why
It cuts the attack in under a second with ~20 lines of logic, and Kubernetes already guarantees the service comes back. It is **containment, not remediation**: whatever let the attacker in (a vulnerable dependency, an exposed debug endpoint) is still in the image. The real fix is upstream: image scanning (Trivy) and admission policies (Kyverno), the next add-ons.

## What would change my mind
- If evidence matters more than speed (a real incident), option 3: isolate, snapshot, then delete.
- If false positives appear (e.g. legitimate `kubectl exec` by operators), an exception for a "break-glass" label or group before any automatic deletion.
