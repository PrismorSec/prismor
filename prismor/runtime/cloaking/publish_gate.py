"""Publish gate: stop a command that would ship a secret.

The cloak hooks keep values out of the model context, but an image, package,
release asset, upload or push carries files, not context. This lists what a
publish command would ship and looks inside (archives too) for:

  * a dotenv-style file that holds a value,
  * a value registered in the cloak vault,
  * a string matching a built-in or custom secret pattern.

Called from env-guard.sh's Bash path through ``env_guard.bash_main``. Never
raises: anything it cannot list is skipped (the policy rules still apply).
"""
from __future__ import annotations

import fnmatch
import gzip
import io
import os
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

_MAX_FILES = 20000
_MAX_BYTES = 5 * 1024 * 1024
_SKIP_DIRS = {".git", "node_modules", "target", "__pycache__", ".venv", "venv"}

# Commands that cheaply could be publishing; env-guard.sh only calls Python when
# one of these words is present.
PUBLISH_HINT = re.compile(
    r"\b(?:docker|podman|buildah|npm|pnpm|yarn|bun|cargo|twine|gem|gh|git|aws|gsutil|gcloud|az|"
    r"curl|wget)\b")


def _patterns() -> List[re.Pattern]:
    try:
        from prismor.runtime.cloaking.patterns import all_patterns
        out = []
        for p in all_patterns():
            try:
                out.append(re.compile(p))
            except re.error:
                pass
        return out
    except Exception:  # noqa: BLE001
        return []


def _blobs(data: bytes, depth: int = 0) -> Iterable[Tuple[str, bytes]]:
    """(member name, bytes) for the data and anything packed inside it."""
    yield "", data
    if depth > 2:
        return
    try:
        if data[:2] == b"\x1f\x8b":
            yield from _blobs(gzip.decompress(data), depth + 1)
        elif len(data) > 262 and data[257:262] == b"ustar":
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers()[:_MAX_FILES]:
                    if m.isfile() and m.size <= _MAX_BYTES:
                        for n, b in _blobs(t.extractfile(m).read(), depth + 1):
                            yield (m.name + ("!" + n if n else "")), b
        elif data[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist()[:_MAX_FILES]:
                    for nn, b in _blobs(z.read(n), depth + 1):
                        yield (n + ("!" + nn if nn else "")), b
    except Exception:  # noqa: BLE001
        return


def scan_files(paths: Iterable[Path], vault: Set[str], label: str) -> Optional[str]:
    """Reason string for the first secret found in ``paths``, else None."""
    from prismor.runtime.cloaking.env_guard import MIN_VALUE_LEN, is_env_basename
    pats = _patterns()
    vals = [v for v in vault if len(v) >= MIN_VALUE_LEN]
    for i, p in enumerate(paths):
        if i >= _MAX_FILES:
            break
        try:
            if not p.is_file() or p.stat().st_size > _MAX_BYTES:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        for member, blob in _blobs(data):
            where = f"{p.name}{'!' + member if member else ''}"
            leaf = member.rsplit("/", 1)[-1] if member else p.name
            text = blob.decode("utf-8", "replace")
            if is_env_basename(leaf) and re.search(r"^\s*(?:export\s+)?[A-Za-z_][\w.]*\s*=\s*\S{%d,}" % MIN_VALUE_LEN, text, re.M):
                return f"{label} would ship the env file '{where}'"
            for v in vals:
                if v in text:
                    return f"{label} would ship a value from the cloak vault (in '{where}')"
            for rx in pats:
                if rx.search(text):
                    return f"{label} would ship a string that looks like a secret key (in '{where}')"
    return None


def _walk(root: Path, ignore: List[str]) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS
                       and not _ignored(os.path.normpath(os.path.join(rel_dir, d)), ignore)]
        for f in filenames:
            rel = os.path.normpath(os.path.join(rel_dir, f))
            if not _ignored(rel, ignore):
                out.append(Path(dirpath) / f)
            if len(out) >= _MAX_FILES:
                return out
    return out


def _ignored(rel: str, patterns: List[str]) -> bool:
    # ponytail: .dockerignore subset (globs, dir prefixes, ! negation); full Go-style matching if it misses real files
    hit = False
    for raw in patterns:
        pat = raw.strip()
        if not pat or pat.startswith("#"):
            continue
        neg = pat.startswith("!")
        pat = pat.lstrip("!").strip("/")
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*") or \
                fnmatch.fnmatch(os.path.basename(rel), pat) or rel.startswith(pat + "/"):
            hit = not neg
    return hit


def _dockerignore(ctx: Path) -> List[str]:
    f = ctx / ".dockerignore"
    return f.read_text(encoding="utf-8", errors="replace").splitlines() if f.is_file() else []


def _compose_contexts(base: Path, files: List[str]) -> List[Path]:
    """Build contexts of the services in the compose file(s) that have a `build:`."""
    import yaml
    paths = [Path(os.path.expanduser(f)) for f in files] or \
        [base / n for n in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")]
    out: List[Path] = []
    for p in paths:
        p = p if p.is_absolute() else base / p
        if not p.is_file():
            continue
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
        except Exception:  # noqa: BLE001
            continue
        for svc in (doc.get("services") or {}).values():
            b = (svc or {}).get("build") if isinstance(svc, dict) else None
            ctx = b if isinstance(b, str) else (b.get("context", ".") if isinstance(b, dict) else None)
            if ctx is not None:
                c = Path(os.path.expanduser(str(ctx)))
                out.append(c if c.is_absolute() else p.parent / c)
        if not files:
            break   # compose reads the first default file it finds
    return out


def _git(cwd: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=15).stdout
    except Exception:  # noqa: BLE001
        return ""


def _positional(args: List[str], takes_value: Set[str]) -> List[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in takes_value:
            skip = True
            continue
        if not a.startswith("-"):
            out.append(a)
    return out


def check(command: str, cwd: str, vault: Set[str]) -> Optional[str]:
    """Reason to deny ``command``, or None."""
    if not PUBLISH_HINT.search(command):
        return None
    from prismor.runtime.cloaking.env_guard import _cmd_name, _segments, _tokens
    tokens = _tokens(command)
    if tokens is None:
        return None
    base = Path(cwd)
    packed: List[str] = []   # inputs of archives built earlier in this command
    for seg in _segments(tokens):
        k, name = _cmd_name(seg["words"])
        a = seg["words"][k + 1:]
        if name in ("tar", "zip", "7z", "gzip"):
            packed += [x for x in _positional(a, {"-C", "-f", "--file", "-x"}) if not x.endswith((".tgz", ".tar", ".gz", ".zip", ".7z"))]
            for i, x in enumerate(a):   # tar -C dir . packs dir
                if x == "-C" and i + 1 < len(a):
                    packed.append(a[i + 1])
        reason = None
        try:
            reason = _check_one(name, a, base, vault, packed)
        except Exception:  # noqa: BLE001
            reason = None
        if reason:
            return reason
    return None


def _files(base: Path, names: Iterable[str]) -> List[Path]:
    out = []
    for n in names:
        p = Path(os.path.expanduser(n))
        p = p if p.is_absolute() else base / p
        if p.is_dir():
            out += _walk(p, [])
        elif p.is_file():
            out.append(p)
    return out


def _check_one(name: str, a: List[str], base: Path, vault: Set[str], packed: List[str] = ()) -> Optional[str]:
    sub = a[0] if a else ""
    # container images: the build context is what COPY . ships
    if name in ("docker", "podman", "buildah") and (sub in ("build", "bud") or a[:2] == ["buildx", "build"]):
        rest = a[2:] if sub == "buildx" else a[1:]
        pos = _positional(rest, {"-t", "--tag", "-f", "--file", "--build-arg", "--target", "--platform",
                                 "--secret", "--label", "--network", "-o", "--output", "--cache-from"})
        ctx = Path(os.path.expanduser(pos[-1])) if pos else Path(".")
        ctx = ctx if ctx.is_absolute() else base / ctx
        return scan_files(_walk(ctx, _dockerignore(ctx)), vault, f"`{name} build`")
    # compose builds every service that has a `build:` (build, up, create, run)
    if (name in ("docker", "podman") and sub == "compose") or name in ("docker-compose", "podman-compose"):
        ca = a[1:] if sub == "compose" else a
        pos = _positional(ca, {"-f", "--file", "-p", "--project-name", "--profile", "--env-file",
                               "--project-directory", "--ansi", "--progress"})
        if pos[:1] and pos[0] in ("build", "up", "create", "run"):
            files = [ca[i + 1] for i, x in enumerate(ca[:-1]) if x in ("-f", "--file")]
            for ctx in _compose_contexts(base, files):
                r = scan_files(_walk(ctx, _dockerignore(ctx)), vault, f"`{name} {' '.join(a[:1] + pos[:1])}`")
                if r:
                    return r
        return None
    # npm-style packages: ask the tool what it would pack
    if name in ("npm", "pnpm", "yarn", "bun") and sub in ("publish", "pack"):
        try:
            import json
            r = subprocess.run(["npm", "pack", "--dry-run", "--json", "--ignore-scripts"], cwd=base,
                               capture_output=True, text=True, timeout=30)
            files = [base / f["path"] for f in json.loads(r.stdout)[0]["files"]]
        except Exception:  # noqa: BLE001
            files = [base / f for f in _git(base, "ls-files", "-co", "--exclude-standard").splitlines()]
        return scan_files(files, vault, f"`{name} {sub}`")
    if name == "cargo" and sub in ("publish", "package"):
        files = [base / f for f in _git(base, "ls-files", "-co", "--exclude-standard").splitlines()]
        return scan_files(files, vault, f"`cargo {sub}`")
    # git: what `add` would stage, what `push` would send
    if name == "git" and sub == "add":
        listed = _git(base, "add", "--dry-run", *a[1:])
        files = [base / l.split("'", 2)[1] for l in listed.splitlines() if l.startswith("add '")]
        return scan_files(files, vault, "`git add`")
    if name == "git" and sub == "push":
        patch = _git(base, "log", "-p", "--format=", "HEAD", "--not", "--remotes")
        names = _git(base, "log", "--name-only", "--format=", "HEAD", "--not", "--remotes").split()
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            pf = Path(d) / "pushed.patch"
            pf.write_text(patch, encoding="utf-8")
            r = scan_files([pf], vault, "`git push`")
        if r:
            return r
        from prismor.runtime.cloaking.env_guard import is_env_basename
        env = [n for n in names if is_env_basename(n)]
        return f"`git push` would publish the env file '{env[0]}'" if env else None
    # uploads that name local files
    upload_args: List[str] = []
    if name == "twine" and sub == "upload":
        upload_args = _positional(a[1:], {"-r", "--repository", "--repository-url", "-u", "-p"})
    elif name == "gem" and sub == "push":
        upload_args = a[1:2]
    elif name == "gh" and a[:2] in (["release", "upload"], ["release", "create"]):
        upload_args = _positional(a[2:], {"-t", "--title", "-n", "--notes", "-F", "--notes-file", "--target", "-R", "--repo"})[1:]
    elif name == "gh" and a[:2] == ["gist", "create"]:
        upload_args = _positional(a[2:], {"-d", "--desc", "-f", "--filename"})
    elif name in ("aws", "gsutil") and sub in ("s3", "cp", "sync", "rsync") and \
            any(x.startswith("public-read") or x in ("--acl=public-read", "-a") for x in a):
        # Only public objects: a private bucket is storage, like copying to your own host.
        upload_args = [x for x in _positional(a[1:], {"--acl", "-a", "--profile", "--region", "--exclude", "--include"})
                       if "://" not in x and x not in ("cp", "sync", "mv", "rsync")][:1]
    # scp / rsync to a host is a private transfer (often the developer's own box),
    # governed by egress and the prod rules, not by this gate.
    elif name in ("curl", "wget"):
        for i, x in enumerate(a):
            v = None
            if x in ("-F", "--form", "-T", "--upload-file", "-d", "--data", "--data-binary", "--data-raw",
                     "--data-urlencode", "--post-file", "--body-file") and i + 1 < len(a):
                v = a[i + 1]
            elif x.startswith(("--post-file=", "--body-file=", "--upload-file=")):
                v = x.split("=", 1)[1]
            if v is None:
                continue
            m = re.search(r"@([^;,\s]+)", v) if x not in ("-T", "--upload-file", "--post-file", "--body-file") and \
                not x.startswith(("--post-file=", "--body-file=", "--upload-file=")) else None
            path = m.group(1) if m else (v if x in ("-T", "--upload-file", "--post-file", "--body-file") or "=" in x else None)
            if path and path != "-":
                upload_args.append(path)
    if upload_args:
        files = _files(base, upload_args)
        missing = [x for x in upload_args if not (base / os.path.expanduser(x)).exists()]
        if missing and packed:   # built in this same command: check what went into it
            files += _files(base, packed)
        return scan_files(files, vault, f"`{name} {sub}`".rstrip())
    return None
