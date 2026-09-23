"""The Hermes filesystem plugin (hermes-plugin/__init__.py) is a standalone copy
of cloaking/hermes_plugin_entry.py so it loads without prismor importable. A
stale copy once let already-vaulted raw secrets through; keep them identical."""

import ast
import importlib.util
import json
from pathlib import Path

CLOAKING = Path(__file__).resolve().parent.parent / "prismor" / "runtime" / "cloaking"


def _code_after_docstring(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    end = ast.parse(src).body[0].end_lineno
    return "".join(src.splitlines(keepends=True)[end:])


def test_filesystem_plugin_matches_canonical():
    assert _code_after_docstring(CLOAKING / "hermes-plugin" / "__init__.py") == _code_after_docstring(
        CLOAKING / "hermes_plugin_entry.py"
    ), "hermes-plugin/__init__.py drifted from hermes_plugin_entry.py; copy the code below the docstring across"


def test_filesystem_plugin_blocks_already_vaulted_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path))
    spec = importlib.util.spec_from_file_location("hermes_fs_plugin", CLOAKING / "hermes-plugin" / "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    args = {"command": "curl -H 'x: " + "ghp_" + "a" * 36 + "'"}
    first = mod.on_pre_tool_call("terminal", args)
    second = mod.on_pre_tool_call("terminal", args)
    assert first["action"] == "block" and second["action"] == "block"

    name = first["message"].split("@@SECRET:")[1].split("@@")[0]
    resolved = mod.on_pre_tool_call("terminal", {"command": f"echo @@SECRET:{name}@@"})
    assert resolved["action"] == "decloak"
