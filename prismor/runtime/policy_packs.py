"""Shareable policy packs: rule sets fetched from a GitHub repo, pinned to a
commit SHA, hash-locked on disk, optionally Ed25519-signed.

A pack is a directory holding ``prismor-pack.yaml`` (name, version,
description, min_prismor, optional ``policies:`` list) and one or more policy
YAML files. Packs load as their own layer between the built-in defaults and
the user policy, and may only add rules or tighten built-in ones (see
``PolicyEngine._apply_packs``).

Store: ``<policy home>/packs/<name>/`` plus ``<policy home>/packs/packs.lock.json``
recording repo, ref, resolved sha, the sha256 of every file and the fetch
time. A pack whose files no longer match the lock is not loaded.

Signatures: a pack may ship ``SHA256SUMS`` (``sha256sum`` output over the pack
files) and ``SHA256SUMS.sig`` (base64 detached Ed25519 over SHA256SUMS). With a
key pinned at add time (``--key``) the signature is checked with the same
verifier the signed org policy uses.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

import yaml

MANIFEST = "prismor-pack.yaml"
SUMS = "SHA256SUMS"
SIG = "SHA256SUMS.sig"
LOCK = "packs.lock.json"
_MAX_FILE = 1 << 20  # 1 MiB per file; a policy pack is a few KB of YAML
_SPEC_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:@([^\s@]+))?$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class PackError(Exception):
    pass


def packs_dir() -> Path:
    from prismor.runtime import system_install
    return system_install.policy_home() / "packs"


def _lock_path() -> Path:
    return packs_dir() / LOCK


def read_lock() -> Dict[str, Any]:
    try:
        data = json.loads(_lock_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"packs": {}}
    return data if isinstance(data.get("packs"), dict) else {"packs": {}}


def _write_lock(lock: Dict[str, Any]) -> None:
    path = _lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── fetch ─────────────────────────────────────────────────────────────

def _http_get(url: str, accept: str = "*/*") -> bytes:
    """GET over HTTPS. The one network seam (tests replace it)."""
    if not url.startswith("https://"):
        raise PackError(f"refusing non-HTTPS URL: {url}")
    from prismor.runtime.http_ua import user_agent
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": user_agent()})
    try:
        # Scheme is pinned to https above, so B310 (file:/custom schemes) cannot apply.
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
            return resp.read(20 * _MAX_FILE + 1)
    except Exception as exc:
        raise PackError(f"fetch failed: {url}: {exc}") from exc


def parse_spec(spec: str) -> Tuple[str, str, Optional[str]]:
    m = _SPEC_RE.match(spec.strip())
    if not m:
        raise PackError(f"expected <owner>/<repo>[@<ref>], got {spec!r}")
    return m.group(1), m.group(2), m.group(3)


def resolve_sha(owner: str, repo: str, ref: Optional[str]) -> str:
    """Resolve a tag/branch (default: the repo's default branch) to a commit SHA."""
    if ref and _SHA_RE.match(ref):
        return ref
    from urllib.parse import quote
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{quote(ref or 'HEAD', safe='')}"
    sha = _http_get(url, accept="application/vnd.github.sha").decode("ascii", "replace").strip()
    if not _SHA_RE.match(sha):
        raise PackError(f"could not resolve {owner}/{repo}@{ref or 'HEAD'} to a commit")
    return sha


def _extract(tarball: bytes, subdir: str) -> Dict[str, bytes]:
    """Regular files under ``subdir`` of a codeload tarball, keyed by path
    relative to it. Links, devices and anything escaping the root are skipped."""
    sub = PurePosixPath(subdir.strip("/")) if subdir.strip("/") else None
    if sub is not None and (sub.is_absolute() or ".." in sub.parts):
        raise PackError(f"invalid --path {subdir!r}")
    out: Dict[str, bytes] = {}
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz")
    except tarfile.TarError as exc:
        raise PackError(f"not a tarball: {exc}") from exc
    with tf:
        for m in tf.getmembers():
            if not m.isfile() or m.size > _MAX_FILE:
                continue
            parts = PurePosixPath(m.name).parts[1:]  # drop the <repo>-<sha>/ prefix
            if not parts or ".." in parts:
                continue
            rel = PurePosixPath(*parts)
            if sub is not None:
                if rel.parts[:len(sub.parts)] != sub.parts:
                    continue
                rel = PurePosixPath(*rel.parts[len(sub.parts):])
            if len(rel.parts) != 1:
                continue  # a pack is one flat directory
            f = tf.extractfile(m)
            if f is not None:
                out[rel.name] = f.read()
    return out


def fetch(owner: str, repo: str, sha: str, subdir: str = "") -> Dict[str, bytes]:
    tarball = _http_get(f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}")
    files = _extract(tarball, subdir)
    if MANIFEST not in files:
        raise PackError(f"no {MANIFEST} in {owner}/{repo}@{sha[:12]}" + (f" --path {subdir}" if subdir else ""))
    return files


# ── validate ──────────────────────────────────────────────────────────

def _version_tuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])


def _policy_files(manifest: Dict[str, Any], files: Dict[str, bytes]) -> List[str]:
    listed = manifest.get("policies")
    if listed is None:
        return sorted(n for n in files if n != MANIFEST and n.endswith((".yaml", ".yml")))
    if not isinstance(listed, list) or not all(isinstance(x, str) for x in listed):
        raise PackError("manifest policies: must be a list of file names")
    missing = [x for x in listed if x not in files]
    if missing:
        raise PackError(f"manifest lists missing policy files: {', '.join(missing)}")
    return list(listed)


def validate(files: Dict[str, bytes]) -> Tuple[Dict[str, Any], List[str]]:
    """Check a fetched pack. Returns (manifest, policy file names); raises
    PackError listing every problem."""
    from prismor.runtime import __version__
    from prismor.runtime.policy_engine import (
        _DEFAULT_POLICY_PATH, _load_yaml, pack_rule_problem, validate_policy)
    try:
        manifest = yaml.safe_load(files[MANIFEST].decode("utf-8"))
    except Exception as exc:
        raise PackError(f"{MANIFEST}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise PackError(f"{MANIFEST}: expected a mapping")
    errors: List[str] = []
    for key in ("name", "version", "description"):
        if not manifest.get(key):
            errors.append(f"{MANIFEST}: missing {key}")
    if manifest.get("name") and not _NAME_RE.match(str(manifest["name"])):
        errors.append(f"{MANIFEST}: name must match {_NAME_RE.pattern}")
    if manifest.get("min_prismor") and _version_tuple(manifest["min_prismor"]) > _version_tuple(__version__):
        errors.append(f"pack needs prismor >= {manifest['min_prismor']} (this is {__version__})")
    policies = _policy_files(manifest, files)
    if not policies:
        errors.append("pack has no policy YAML files")
    builtin = {r["id"]: r for r in (_load_yaml(_DEFAULT_POLICY_PATH) or {}).get("rules", [])}
    schema = _schema()
    seen: Dict[str, str] = {}
    with tempfile.TemporaryDirectory() as td:
        for name in policies:
            path = Path(td) / name
            path.write_bytes(files[name])
            errors += [f"{name}: {e}" for e in validate_policy(path)]
            raw = _load_yaml(path)
            if not isinstance(raw, dict):
                continue
            if schema is not None:
                import jsonschema
                # New rules must be full schema rules; tighten entries on a
                # built-in are sparse by design and checked by pack_rule_problem.
                doc = {**raw, "rules": [r for r in raw.get("rules") or []
                                        if not (isinstance(r, dict) and r.get("id") in builtin)]}
                for e in jsonschema.Draft7Validator(schema).iter_errors(doc):
                    errors.append(f"{name}: schema: {e.message}")
            for key in sorted(set(raw) - {"version", "rules"}):
                errors.append(f"{name}: '{key}:' is not allowed in a pack (packs only add or tighten rules)")
            for rule in raw.get("rules") or []:
                rid = str(rule.get("id", ""))
                if rid in seen:
                    errors.append(f"{name}: rule '{rid}' also defined in {seen[rid]}")
                seen[rid] = name
                problem = pack_rule_problem(rule, builtin.get(rid))
                if problem:
                    errors.append(f"{name}: {problem}")
    if errors:
        raise PackError("invalid pack:\n  - " + "\n  - ".join(errors))
    return manifest, policies


def _schema() -> Optional[Dict[str, Any]]:
    """policy_schema.json when jsonschema is installed (it is not a runtime dep)."""
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return None
    return json.loads(Path(__file__).with_name("policy_schema.json").read_text(encoding="utf-8"))


def verify_signature(files: Dict[str, bytes], key_pem: str) -> None:
    """Raise unless SHA256SUMS is signed by ``key_pem`` and lists every pack file
    with a matching hash."""
    from prismor.runtime.feed_signature import verify_bytes
    if SUMS not in files or SIG not in files:
        raise PackError(f"pack is unsigned (no {SUMS} / {SIG})")
    result = verify_bytes(files[SUMS], files[SIG], key_pem.encode("ascii"))
    if not result.ok:
        raise PackError(f"signature check failed: {result.detail}")
    listed: Dict[str, str] = {}
    for line in files[SUMS].decode("utf-8", "replace").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            fname = parts[1].lstrip("*")
            listed[fname[2:] if fname.startswith("./") else fname] = parts[0].lower()
    for name, data in files.items():
        if name in (SUMS, SIG):
            continue
        if listed.get(name) != _sha256(data):
            raise PackError(f"{name} is not covered by the signed {SUMS}")


# ── install / remove ──────────────────────────────────────────────────

def prepare(spec: str, subdir: str = "", key_path: Optional[str] = None,
            require_signature: bool = False, pinned_key: Optional[str] = None) -> Dict[str, Any]:
    """Resolve, fetch, validate and verify a pack without touching the store."""
    owner, repo, ref = parse_spec(spec)
    sha = resolve_sha(owner, repo, ref)
    files = fetch(owner, repo, sha, subdir)
    manifest, policies = validate(files)
    key_pem = Path(key_path).expanduser().read_text(encoding="utf-8") if key_path else pinned_key
    if key_pem:
        verify_signature(files, key_pem)
    elif require_signature:
        raise PackError("--require-signature needs --key <public.pem> to verify against")
    ids = set()
    for n in policies:
        ids |= {str(r.get("id")) for r in (yaml.safe_load(files[n].decode("utf-8")) or {}).get("rules") or []}
    return {"name": str(manifest["name"]), "manifest": manifest, "policies": policies,
            "files": files, "rule_ids": sorted(ids), "key_pem": key_pem,
            "repo": f"{owner}/{repo}", "ref": ref, "path": subdir, "sha": sha,
            "require_signature": bool(require_signature or key_pem)}


def commit(p: Dict[str, Any]) -> Dict[str, Any]:
    """Write a prepared pack to the store and record it in the lockfile."""
    files, name = p["files"], p["name"]
    keep = [MANIFEST, *p["policies"]] + [n for n in (SUMS, SIG) if n in files]
    dest = packs_dir() / name
    stage = packs_dir() / f".{name}.new"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    for n in keep:
        (stage / n).write_bytes(files[n])
    shutil.rmtree(dest, ignore_errors=True)
    stage.replace(dest)
    entry = {
        "repo": p["repo"], "ref": p["ref"], "path": p["path"], "sha": p["sha"],
        "version": str(p["manifest"].get("version")),
        "description": str(p["manifest"].get("description")),
        "policies": p["policies"], "files": {n: _sha256(files[n]) for n in keep},
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "signed": bool(p["key_pem"]), "require_signature": p["require_signature"],
    }
    if p["key_pem"]:
        entry["key_pem"] = p["key_pem"]
    lock = read_lock()
    lock["packs"][name] = entry
    _write_lock(lock)
    return {"name": name, **entry}


def remove(name: str) -> bool:
    lock = read_lock()
    if name not in lock["packs"]:
        return False
    del lock["packs"][name]
    _write_lock(lock)
    shutil.rmtree(packs_dir() / name, ignore_errors=True)
    return True


def rule_ids(name: str) -> List[str]:
    """Rule ids the installed pack ships (empty when it is not loadable)."""
    packs, _ = load_all({name})
    return sorted({str(r.get("id")) for _, raw in packs for r in raw.get("rules") or []})


# ── load (hot path) ───────────────────────────────────────────────────

_WARNED: set = set()


def load_all(only: Optional[set] = None) -> Tuple[List[Tuple[str, Dict[str, Any]]], List[str]]:
    """Verified packs as ``[(name, policy_dict), ...]`` plus one error string
    per pack that failed verification. Cheap when no pack is installed."""
    root = packs_dir()
    if not (root / LOCK).exists():
        return [], []
    out: List[Tuple[str, Dict[str, Any]]] = []
    errors: List[str] = []
    for name, entry in sorted(read_lock()["packs"].items()):
        if only is not None and name not in only:
            continue
        try:
            loaded = []
            for fname, want in sorted((entry.get("files") or {}).items()):
                data = (root / name / fname).read_bytes()
                if _sha256(data) != want:
                    raise PackError(f"{fname} sha256 does not match the lockfile")
                if fname in (entry.get("policies") or []):
                    raw = yaml.safe_load(data.decode("utf-8"))
                    if isinstance(raw, dict):
                        loaded.append((name, raw))
            if entry.get("require_signature") and not entry.get("signed"):
                raise PackError("pack requires a signature but none was verified")
            out.extend(loaded)
        except (OSError, ValueError, PackError, yaml.YAMLError) as exc:
            msg = f"policy pack '{name}' failed verification and was not loaded: {exc}"
            errors.append(msg)
            if msg not in _WARNED:
                _WARNED.add(msg)
                sys.stderr.write(f"[prismor] {msg}. Reinstall with: prismor policy pack update {name}\n")
    return out, errors
