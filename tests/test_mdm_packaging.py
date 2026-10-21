"""MDM installer sources: the cheap invariants that break a fleet rollout silently."""
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MDM = ROOT / "packaging" / "mdm"


def test_powershell_scripts_are_ascii():
    # Windows PowerShell 5.1 reads a BOM-less file as ANSI: one curly quote or
    # check mark and Intune's install fails with a parse error.
    for f in (MDM / "windows").glob("*.ps1"):
        f.read_bytes().decode("ascii")


def test_python_runtimes_are_pinned_with_checksums():
    lock = json.loads((MDM / "python.lock.json").read_text())
    assert set(lock["runtimes"]) == {"macos-arm64", "macos-x86_64", "windows-x64"}
    for rt in lock["runtimes"].values():
        assert re.fullmatch(r"[0-9a-f]{64}", rt["sha256"])
        assert lock["release"] in rt["asset"] and lock["python"] in rt["asset"]


def test_macos_scripts_are_executable_and_guard_removals():
    for name in ("prismor", "prismor-mdm-setup", "prismor-uninstall", "jamf-extension-attribute.sh",
                 "build_pkg.sh", "notarize.sh", "scripts/postinstall"):
        f = MDM / "macos" / name
        assert os.access(f, os.X_OK), name
        # A root postinstall must never be one empty variable away from rm -rf /.
        for line in f.read_text().splitlines():
            m = re.search(r"rm -rf (\S+)", line)
            if m and "$" in m.group(1):
                assert ":?" in m.group(1), f"{name}: unguarded {m.group(0)}"


def test_deploy_guides_ship_in_the_wheel():
    toml = (ROOT / "pyproject.toml").read_text()
    for doc in ("deploy-jamf.md", "deploy-intune.md", "system-install.md"):
        assert f'"docs/{doc}"' in toml
