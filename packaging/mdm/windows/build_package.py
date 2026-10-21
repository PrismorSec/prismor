"""Build the Prismor Windows MDM package (a folder and a .zip) on any host.

    python packaging/mdm/windows/build_package.py dist/prismor-X.whl out/ [--compile-with PY312]

The folder is what Intune's IntuneWinAppUtil wraps into a .intunewin
(setup file: install.ps1); see make_intunewin.ps1. SCCM and GPO deploy it
as-is.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = ("install.ps1", "uninstall.ps1", "detect.ps1", "remediation-detect.ps1",
           "remediation-fix.ps1", "prismor.cmd")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("wheel", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--compile-with")
    a = ap.parse_args()
    ver = a.wheel.name.split("-")[1]
    pkg = a.out / f"prismor-{ver}-windows"
    shutil.rmtree(pkg, ignore_errors=True)
    pkg.mkdir(parents=True)
    cmd = [sys.executable, str(HERE.parent / "build_runtime.py"), "--target", "windows-x64",
           "--wheel", str(a.wheel), "--out", str(pkg / "runtime")]
    if a.compile_with:
        cmd += ["--compile-with", a.compile_with]
    subprocess.run(cmd, check=True)
    for name in SCRIPTS:
        text = (HERE / name).read_text(encoding="utf-8").replace("__VERSION__", ver)
        # PowerShell 5.1 reads BOM-less files as ANSI; the scripts are ASCII.
        text.encode("ascii")
        (pkg / name).write_bytes(text.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii"))
    (pkg / "VERSION").write_text(ver, encoding="ascii")
    archive = shutil.make_archive(str(pkg), "zip", root_dir=pkg)
    print(f"built {pkg} and {archive}")


if __name__ == "__main__":
    main()
