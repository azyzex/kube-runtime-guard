# Attack scenarios and false-positive tuning (add-on 2)

Run by `scripts/scenarios.sh` on 2026-11-03 (v1.35.5+k3s1, Falco modern eBPF).

| # | Scenario | Falco rule | Responder decision | syscall → responder | Pod survived | |
|---|---|---|---|---|---|---|
| S1 | interactive shell in the pod (attacker) | Terminal shell in container | delete | 0.036 s | no (replaced) | ✅ |
| S2 | read /etc/shadow (credential theft) | Read sensitive file untrusted | ignored: rule not in allow-list | 0.017 s | yes | ✅ |
| S3 | search for private keys | Search Private Keys or Passwords | ignored: rule not in allow-list | 0.011 s | yes | ✅ |
| FP | operator's sanctioned debug shell (break-glass label) | Terminal shell in container | ignored: break-glass pod (sanctioned operator session) | 0.012 s | yes | ✅ |
