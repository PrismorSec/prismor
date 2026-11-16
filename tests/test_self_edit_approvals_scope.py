"""prismor-self-edit and a file merely named approvals.json (issue #928)."""
from __future__ import annotations

import pytest

from prismor.runtime.policy_engine import PolicyEngine

ENGINE = PolicyEngine()
NAME = "approvals" + ".json"  # assembled so this file's own text stays quiet


def _live(event):
    return [f for f in ENGINE.evaluate(event, 0)
            if f["ruleId"] == "prismor-self-edit" and not f.get("contextInert")]


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.mark.parametrize("cmd", [
    f"prismor approvals list --all --json > /tmp/x/{NAME}",
    f"python3 /tmp/x/extract.py /tmp/x/{NAME}",
    f"jq '.[] | .status' /var/tmp/audit/{NAME} | sort | uniq -c",
    # The replayed shape: the scratch dir is a variable the command sets.
    f"S=/private/tmp/x/fps; mkdir -p $S; prismor approvals list --all --json > $S/{NAME}",
    f"S=/tmp/x; W=${{S}}/w; python3 e.py $W/{NAME}",
])
def test_scratch_copy_is_inert(cmd):
    assert not _live({"type": "shell", "command": cmd})


def test_scratch_read_is_inert():
    assert not _live({"type": "file_read", "path": f"/tmp/x/{NAME}"})


@pytest.mark.parametrize("cmd", [
    f"echo '{{}}' > ~/.prismor/{NAME}",
    f"cp /tmp/x/{NAME} ~/.prismor/",
    f"cp /tmp/x/{NAME} $PRISMOR_HOME/",
    f"echo x > {NAME}",                      # relative: cwd may be the home
    f"echo x > $H/{NAME}",                   # unresolved variable
    f"S=/tmp/x; S=$HOME; echo x > $S/{NAME}",  # reassigned: ambiguous
    f"ln -s /tmp/x/{NAME} /tmp/y/approvals.lock && cat .prismor/x",
])
def test_real_queue_stays_live(cmd):
    assert _live({"type": "shell", "command": cmd})


def test_home_path_stays_live(_home):
    assert _live({"type": "shell", "command": f"echo x > {_home}/{NAME}"})
    assert _live({"type": "file_write", "path": f"{_home}/{NAME}"})
    assert _live({"type": "file_read", "path": f"{_home}/{NAME}"})


def test_symlink_into_home_stays_live(_home, tmp_path):
    _home.mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(_home)
    assert _live({"type": "file_write", "path": f"{link}/{NAME}"})
