# kube-runtime-guard

**Runtime threat detection and automated containment for a Kubernetes workload**, built with Falco (modern eBPF), Falcosidekick, Slack and a small Python responder, on a laptop (k3d).

🇫🇷 [Version française plus bas](#-version-française)

```
 attacker                  Kubernetes (k3d)                              you
 ────────                  ────────────────                              ───
 kubectl exec -it  ──►  orders-api pod (ns: shop)
                            │ syscalls (execve of a shell with a TTY)
                            ▼
                        Falco (modern eBPF, kernel-level)
                            │ rule "Terminal shell in container"
                            ▼
                        Falcosidekick ──────────────────────────────►  Slack #falco-alerts
                            │ webhook
                            ▼
                        responder (FastAPI)
                            │ guardrails: rule allow-list · namespace allow-list · cooldown · dry-run
                            │ RBAC: may only get/delete pods in "shop"
                            ▼
                        DELETE pod  ──►  Deployment starts a clean pod  ─►  Slack ":shield: Contained"
```

## Results (measured on the laptop)

Laptop: Ryzen 7 4800H, WSL 2 (kernel 6.18), k3d v5.9 (k3s v1.35), Falco 0.45.2 (modern eBPF), 2 Nov 2026. 5 attacks in a row (`scripts/measure.sh 5`), plus 2 earlier manual runs counted in the responder stats.

| Step | Median | Worst |
|---|---|---|
| shell `execve` in the pod → alert received by the responder (Falco + Falcosidekick) | **0.008 s** | 0.079 s |
| responder → pod deleted (Kubernetes API) | **0.016 s** | 0.213 s |
| attack started → attacked pod gone (seen from outside, includes `kubectl` polling) | **0.72 s** | 1.90 s |
| attack started → clean replacement pod Ready | **2.5 s** | 2.7 s |
| Slack alert + ":shield: Contained" message | delivered every run | |

| RAM | |
|---|---|
| whole cluster (k3d node: k3s + Falco + Falcosidekick + app + responder) | **~850 MiB** |
| WSL total with the cluster running | ~1.35 GB of 4.9 GB |

**Measured caveats:** the two latencies compare Falco's event timestamp with the responder's clock on the same machine. On the WSL kernel, Falco logs that some syscall tracepoints are missing: its TOCTOU mitigation for `open`/`connect` is off, detection works (shown above).

## Add-on 1 ✅: image vulnerabilities before / after hardening (Trivy in CI)

Every push builds each image twice: the original (`python:3.13-slim`) and a hardened one (`Dockerfile.hardened`: multi-stage build, **distroless** runtime with no shell and no package manager, non-root user). Trivy 0.75 scans both; CI fails if a hardened image has a fixable CRITICAL vulnerability.

| Image (same app, same Python 3.13) | CRITICAL | HIGH | MEDIUM | LOW | fixable HIGH+CRIT |
|---|---|---|---|---|---|
| original (`python:3.13-slim`, Debian 13) | 0 | 53 | 76 | 63 | 8 |
| hardened (distroless Debian 13, non-root) | 0 | **32** | 111 | 54 | **3** |

- **HIGH −40 %, fixable HIGH/CRITICAL 8 → 3.** MEDIUM goes up (the distroless Python image ships some libraries the slim one doesn't); that trade-off is stated, not hidden.
- **Lesson from the first run:** my first "hardened" image used distroless *Debian 12* + Python 3.11 and had **more** vulnerabilities (48 fixable vs 8): an older base erases the benefit of a smaller one. The fair comparison keeps the same Debian and Python versions.
- **Defence in depth:** the hardened image has **no shell at all**, so the attack in this demo (`kubectl exec … sh`) fails before Falco even needs to act. The demo keeps the original image on purpose, so there is something to detect.

## Add-on 2 ✅: more scenarios + false-positive tuning (tested end to end in CI)

Every PR now runs the **whole project on a real cluster in GitHub Actions** (`e2e.yml`: k3d + Falco modern eBPF + Falcosidekick + responder) and replays these scenarios (`scripts/scenarios.sh`, results in [`results/scenarios.md`](results/scenarios.md)):

| # | Scenario | Falco rule | Responder decision | syscall → responder | Pod survived |
|---|---|---|---|---|---|
| S1 | interactive shell (attacker) | Terminal shell in container | **delete** (containment) | 0.036 s | no, replaced |
| S2 | read `/etc/shadow` | Read sensitive file untrusted | alert only | 0.017 s | yes |
| S3 | search for private keys | Search Private Keys or Passwords | alert only | 0.011 s | yes |
| FP | operator's sanctioned debug shell | Terminal shell in container | **ignored: break-glass** | 0.012 s | yes |

**False-positive tuning log**
1. *Problem:* the only automatic action (delete the pod) also fires when an operator legitimately opens a shell to debug. Killing their session would make the tool something people disable.
2. *Options:* turn the rule off (loses detection); exclude by user (Falco sees the container's root user, not the human); mark the pod.
3. *Choice:* a pod label `guard.fibertwin.io/break-glass=true`. Falco **still alerts** (audit trail in Slack), the responder **does not delete**. The label is set on purpose, visibly, by someone with RBAC on pods.
4. *Why S2/S3 are alert-only:* reading a secret or searching for keys is serious but often investigative; automatic deletion would destroy evidence. Only an interactive shell (an attacker inside, now) justifies instant containment.

## What it is, honestly
- **Detection** happens in the kernel: Falco's eBPF probe sees the `execve` of a shell attached to a terminal inside a container, and enriches it with the pod name and namespace from containerd.
- **Response is containment, not remediation.** Deleting the pod cuts the live session and discards anything the attacker changed in the pod; Kubernetes starts a clean copy. The weakness that let the attacker in is **still in the image**: fixing it is the job of image scanning and admission policies (planned add-ons). Decision record: [docs/decisions/0001](docs/decisions/0001-containment-by-pod-deletion.md).
- **The responder can't go rogue:** it acts on one rule only, in one namespace only, at most once per pod per 30 s, has a dry-run switch, and its ServiceAccount can only `get`/`delete` pods in `shop` (a namespaced Role).

## Run it
Requirements: Docker, k3d, kubectl, helm, a Linux kernel with BTF (`/sys/kernel/btf/vmlinux`). Optional: a Slack incoming-webhook URL in `~/.secrets/slack-webhook`.

```bash
bash scripts/up.sh        # cluster + app + responder + Falco/Falcosidekick
bash scripts/attack.sh    # open a shell in the pod -> Slack alert -> pod replaced
bash scripts/measure.sh 5 # 5 attacks, prints latencies and RAM
bash scripts/down.sh      # delete everything
```

Unit tests (no cluster): `pytest -q tests`.

## Next add-ons (each only after the previous one works)
Loki + Grafana → Sigma → LogQL → n8n replacing the responder → Kyverno blocking privileged pods.

---

## 🇫🇷 Version française

**Détection d'intrusion à l'exécution et confinement automatique pour une charge Kubernetes**, avec Falco (eBPF moderne), Falcosidekick, Slack et un petit répondeur Python, sur un portable (k3d).

- **Détection** au niveau du noyau : la sonde eBPF de Falco voit l'`execve` d'un shell attaché à un terminal dans un conteneur, enrichi avec le nom du pod et le namespace.
- **La réponse est un confinement, pas une correction.** Supprimer le pod coupe la session et efface ce que l'attaquant a modifié ; Kubernetes recrée un pod propre. La faiblesse reste **dans l'image** : la corriger relève du scan d'images et des politiques d'admission (extensions prévues).
- **Garde-fous du répondeur :** une seule règle, un seul namespace, au plus une action par pod toutes les 30 s, mode simulation, et un compte de service limité à `get`/`delete` des pods de `shop`.

Résultats : voir le tableau ci-dessus (mesuré sur le portable).
