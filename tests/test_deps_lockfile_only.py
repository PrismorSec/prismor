"""deps: lockfile-only dirs are scanned, BOMs are read, bad manifests are loud."""
from __future__ import annotations

import json

from prismor.runtime.deps import scan_workspace


def _scan(ws):
    return scan_workspace(ws, {"advisories": []}, osv=False)


def test_package_lock_only(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {
        "": {}, "node_modules/left-pad": {"version": "1.3.0"}}}))
    r = _scan(tmp_path)
    assert r["dependencies"] == 1 and r["manifests"][0]["ecosystem"] == "npm"


def test_other_lockfiles_only(tmp_path):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.1"\n')
    (tmp_path / "go.sum").write_text("github.com/x/y v1.2.3 h1:abc=\ngithub.com/x/y v1.2.3/go.mod h1:def=\n")
    (tmp_path / "Pipfile.lock").write_text(json.dumps({"default": {"flask": {"version": "==2.0.0"}}}))
    (tmp_path / "yarn.lock").write_text('lodash@^4.0.0:\n  version "4.17.21"\n')
    assert _scan(tmp_path)["dependencies"] == 5


def test_lockfile_next_to_manifest_not_double_counted(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/a": {"version": "1.0.0"}}}))
    assert _scan(tmp_path)["dependencies"] == 1


def test_bom_package_json_and_requirements(tmp_path):
    (tmp_path / "package.json").write_bytes(b'\xef\xbb\xbf{"dependencies": {"a": "1.0.0", "b": "2.0.0"}}')
    (tmp_path / "requirements.txt").write_text("flask==2.0\n", encoding="utf-16")
    r = _scan(tmp_path)
    assert r["dependencies"] == 3 and not r["parse_errors"]


def test_malformed_package_json_reported(tmp_path):
    (tmp_path / "package.json").write_text("{not json")
    r = _scan(tmp_path)
    assert r["parse_errors"] and "package.json" in r["parse_errors"][0]["path"]


def test_cli_exit_code_matches_between_text_and_json(tmp_path, capsys):
    import pytest
    from prismor.runtime.cli import main
    (tmp_path / "package.json").write_text("{bad")
    for extra in ([], ["--json"]):
        with pytest.raises(SystemExit) as e:
            main(["deps", "--offline", "--workspace", str(tmp_path), *extra])
        assert e.value.code == 1
