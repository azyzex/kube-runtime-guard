"""Unit tests for the responder's decision logic and time parsing (no cluster needed)."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "responder"))


def load(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import main
    return importlib.reload(main)


def alert(rule="Terminal shell in container", ns="shop", pod="orders-api-abc"):
    return {"rule": rule, "time": "2026-11-02T20:00:00.123456789Z",
            "output_fields": {"k8s.ns.name": ns, "k8s.pod.name": pod}}


def test_deletes_shell_in_protected_namespace(monkeypatch):
    m = load(monkeypatch, DRY_RUN="false")
    assert m.decide(alert())[0] == "delete"


def test_ignores_other_rules(monkeypatch):
    m = load(monkeypatch)
    assert m.decide(alert(rule="Read sensitive file untrusted"))[0].startswith("ignored: rule")


def test_never_touches_unprotected_namespaces(monkeypatch):
    m = load(monkeypatch)
    for ns in ("kube-system", "falco", "guard-system"):
        assert m.decide(alert(ns=ns))[0] == "ignored: namespace not protected"


def test_missing_pod_metadata(monkeypatch):
    m = load(monkeypatch)
    assert m.decide({"rule": "Terminal shell in container", "output_fields": {}})[0] == "ignored: no pod metadata"


def test_cooldown_prevents_loops(monkeypatch):
    m = load(monkeypatch)
    m._last_action["shop/orders-api-abc"] = m.time.time()
    assert m.decide(alert())[0] == "ignored: cooldown"


def test_dry_run(monkeypatch):
    m = load(monkeypatch, DRY_RUN="true")
    assert m.decide(alert())[0] == "dry-run: would delete"


def test_falco_time_nanoseconds():
    import main
    assert abs(main.parse_falco_time("2026-11-02T20:00:00.123456789Z") - 1793649600.123456) < 1e-5
    assert main.parse_falco_time("2026-11-02T20:00:00Z") == 1793649600.0
