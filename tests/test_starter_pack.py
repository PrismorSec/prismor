"""The bundled starter pack (`prismor policy test` with no tests of its own)
must pass against the bundled default policy. It drifted twice unnoticed when
rules were split or strengthened; this keeps it honest."""

from pathlib import Path

from prismor.runtime.policy_test import load_cases, run_cases

PACK = Path(__file__).resolve().parents[1] / "templates" / "policy-tests-owasp.yaml"


def test_starter_pack_passes_on_default_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    for k in [k for k in __import__("os").environ if k.startswith("PRISMOR_WORKSPACE")]:
        monkeypatch.delenv(k, raising=False)
    result = run_cases(load_cases(PACK), workspace=tmp_path)
    failed = [r for r in result["results"] if r["status"] != "ok"]
    assert not failed, failed
