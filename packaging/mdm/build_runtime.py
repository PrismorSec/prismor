"""Build a self-contained Prismor runtime for an MDM installer.

Downloads the pinned python-build-standalone build for ``--target`` (checked
against python.lock.json), unpacks it, and installs the Prismor wheel and its
dependencies into it as binary wheels for that platform, so the target
machine needs neither Python nor network access to install. Runs on any host:
``pip --platform`` picks the target's wheels.

    python packaging/mdm/build_runtime.py --target macos-arm64 --wheel dist/prismor-X.whl --out build/rt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = "https://github.com/astral-sh/python-build-standalone/releases/download"


def fetch(lock: dict, target: str, cache: Path) -> Path:
    rt = lock["runtimes"][target]
    path = cache / rt["asset"]
    if not path.exists():
        cache.mkdir(parents=True, exist_ok=True)
        url = f"{BASE}/{lock['release']}/{rt['asset'].replace('+', '%2B')}"
        with urllib.request.urlopen(url, timeout=300) as r, open(path, "wb") as f:  # pinned release URL  # nosec B310
            shutil.copyfileobj(r, f)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != rt["sha256"]:
        path.unlink()
        raise SystemExit(f"checksum mismatch for {rt['asset']}: {digest}")
    return path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, choices=["macos-arm64", "macos-x86_64", "windows-x64"])
    ap.add_argument("--wheel", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path, help="directory to create (the runtime root)")
    ap.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "prismor-pbs")
    ap.add_argument("--compile-with", help="a Python of the same minor version, for cross builds "
                    "(bytecode is platform-independent)")
    a = ap.parse_args()

    lock = json.loads((HERE / "python.lock.json").read_text())
    tarball = fetch(lock, a.target, a.cache)
    if a.out.exists():
        shutil.rmtree(a.out)
    staging = a.out.parent / (a.out.name + ".tmp")
    shutil.rmtree(staging, ignore_errors=True)
    with tarfile.open(tarball) as t:
        t.extractall(staging, filter="data") if sys.version_info >= (3, 12) else t.extractall(staging)  # nosec B202 - pinned, checksummed archive
    (staging / "python").rename(a.out)
    staging.rmdir()

    win = a.target.startswith("windows")
    site = a.out / ("Lib/site-packages" if win else f"lib/python{lock['python'].rsplit('.', 1)[0]}/site-packages")
    subprocess.run([
        sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
        "--target", str(site), "--upgrade",
        "--platform", lock["runtimes"][a.target]["pip_platform"],
        "--python-version", lock["python"].rsplit(".", 1)[0], "--implementation", "cp",
        "--only-binary=:all:", str(a.wheel),
    ], check=True)
    # pip --target drops console scripts into site-packages/bin; the installers
    # ship their own launcher, so these would only be dead, host-shaped files.
    shutil.rmtree(site / "bin", ignore_errors=True)

    # Nothing the hook or CLI runs needs these; they are a third of the size.
    stdlib = site.parent
    for name in ("test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "pydoc_data"):
        shutil.rmtree(stdlib / name, ignore_errors=True)
    for tcl in list(a.out.glob("lib/tcl*")) + list(a.out.glob("lib/tk*")) + list(a.out.glob("tcl")):
        shutil.rmtree(tcl, ignore_errors=True)
    # Precompile: the installed tree is admin-owned, so a user's hook can't
    # write __pycache__ and would recompile every module on every tool call.
    # Prefer the target's own interpreter (it runs whenever host OS = target
    # OS); else a host Python of the same minor version.
    target_py = a.out / ("python.exe" if win else "bin/python3")
    compilers = [str(target_py)] + ([a.compile_with] if a.compile_with else [])
    if sys.version_info[:2] == tuple(int(x) for x in lock["python"].split(".")[:2]):
        compilers.append(sys.executable)
    for py in compilers:
        try:
            r = subprocess.run([py, "-m", "compileall", "-q", "-j", "0",
                                "--invalidation-mode", "unchecked-hash", str(stdlib)], check=False)
        except OSError:
            continue
        if r.returncode in (0, 1):  # 1 = some files (e.g. py2-only test data) didn't compile
            break
    else:
        print(f"note: no Python {lock['python']} able to run here; bytecode not precompiled")
    print(f"built {a.target} runtime at {a.out}")


if __name__ == "__main__":
    main()
