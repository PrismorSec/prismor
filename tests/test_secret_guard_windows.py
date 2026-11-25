"""secret-guard on Git Bash: no shasum, PEM keys, DB URLs, single-pass speed,
and benign look-alikes stay allowed. Skipped without bash + jq."""
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from prismor.runtime.cloaking import patterns

pytestmark = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("jq")), reason="needs bash + jq")
HOOKS = Path(patterns.__file__).parent / "hooks"


def run(tmp_path, tool_input, tool="Write", path=None):
    env = {**os.environ, "PRISMOR_HOME": str(tmp_path / "h"), "PRISMOR_SECRETS_DIR": str(tmp_path / "s"),
           "PRISMOR_CLOAK_PATTERNS": str(tmp_path / "none.txt")}
    if path:
        env["PATH"] = path
    p = subprocess.run(["bash", str(HOOKS / "secret-guard.sh")], capture_output=True, text=True, env=env,
                       input=json.dumps({"tool_name": tool, "tool_input": tool_input, "session_id": "t"}), timeout=60)
    return json.loads(p.stdout)["hookSpecificOutput"] if p.stdout.strip() else None


def denied(r):
    return bool(r) and r["permissionDecision"] == "deny"


PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA3Zq7" * 6 + "\n-----END RSA PRIVATE KEY-----\n"


def test_pem_private_key_blocked(tmp_path):
    assert denied(run(tmp_path, {"file_path": "k.pem", "content": PEM}))
    assert denied(run(tmp_path, {"command": "cat > k <<EOF\n" + PEM + "EOF"}, tool="Bash"))


@pytest.mark.parametrize("url", [
    "postgres://app:Xk29fLq8Vz@db.internal:5432/prod",
    "mongodb+srv://admin:s3cr3tPw0rd@cluster0.mongodb.net/db",
    "mysql://root:hunter2hunter@10.0.0.5/x",
    "redis://default:Zq81ngLmXp@cache.internal:6379",
])
def test_db_urls_blocked(tmp_path, url):
    assert denied(run(tmp_path, {"command": f"psql {url}"}, tool="Bash"))


@pytest.mark.parametrize("text", [
    "postgres://user:password@localhost/db",
    "postgresql://postgres:postgres@localhost:5432/app",
    "mongodb://user:<password>@host/db",
    "redis://:${REDIS_PW}@cache:6379",
    "mysql://root:changeme@127.0.0.1/db",
    "see -----BEGIN " "PRIVATE KEY----- header in the docs",
    "postgres://localhost:5432/mydb",
    'regex = "-----BEGIN (RSA )?PRIVATE ' 'KEY-----"',
])
def test_benign_samples_allowed(tmp_path, text):
    assert not denied(run(tmp_path, {"command": f"echo '{text}'"}, tool="Bash"))


def test_no_shasum_names_distinct_vault_entries(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for t in ["bash", "jq", "grep", "awk", "sed", "tr", "cut", "cat", "mkdir", "chmod", "dirname", "basename",
              "python3", "date", "head", "sort", "uniq", "wc", "mktemp", "rm", "env"]:
        w = shutil.which(t)
        if w:
            (bin_ / t).symlink_to(w)
    names = []
    for key in ("ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"):
        r = run(tmp_path, {"command": f"curl -H 'Authorization: {key}' x"}, tool="Bash", path=str(bin_))
        assert denied(r)
        import re
        names.append(re.search(r"auto_([0-9a-f]+)", r["permissionDecisionReason"]).group(1))
    assert len(names[0]) == 8 and names[0] != names[1]


def test_fails_closed_when_no_hash_tool(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for t in ["bash", "jq", "grep", "awk", "sed", "tr", "cut", "cat", "mkdir", "chmod", "dirname", "basename"]:
        (bin_ / t).symlink_to(shutil.which(t))
    r = run(tmp_path, {"command": "x ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}, tool="Bash", path=str(bin_))
    assert denied(r) and "sha256" in r["permissionDecisionReason"] and "auto_@@" not in r["permissionDecisionReason"]


def test_single_pass_is_fast(tmp_path):
    t = time.time()
    run(tmp_path, {"command": "echo hi " + "x" * 5000}, tool="Bash")
    assert time.time() - t < 5


def test_new_builtin_patterns_listed():
    joined = "\n".join(patterns.builtin_patterns())
    for needle in ("PRIVATE KEY-----", "mongodb", "pk_live_", "AccountKey="):
        assert needle in joined
