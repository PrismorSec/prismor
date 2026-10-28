"""Vendor key formats in builtin_patterns.txt: each one is caught by `grep -oE`
(the engine every cloaking hook uses), benign look-alikes are not, and the
UserPromptSubmit guard blocks and cloaks a pasted key end to end.

Samples are assembled at runtime so no literal key-shaped string lives in the repo.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from prismor.runtime.cloaking import patterns

_HOOKS = Path(patterns.__file__).parent / "hooks"
_HEX, _ALNUM, _LOW = "0123456789abcdef", "abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz"
_UP = _LOW.upper()


def f(chars: str, n: int) -> str:
    return (chars * (n // len(chars) + 1))[:n]


SAMPLES = {
    "nx": "nx_" + f(_HEX, 48),
    "elevenlabs": "sk_" + f(_HEX, 48),
    "openai-proj": "sk-proj-" + f(_ALNUM, 60),
    "openai-legacy": "sk-" + f(_ALNUM, 20) + "T3BlbkFJ" + f(_ALNUM, 20),
    "anthropic": "sk-ant-api03-" + f(_ALNUM, 90),
    "openrouter": "sk-or-v1-" + f(_HEX, 64),
    "groq": "gsk_" + f(_ALNUM, 52),
    "perplexity": "pplx-" + f(_ALNUM, 48),
    "xai": "xai-" + f(_ALNUM, 80),
    "replicate": "r8_" + f(_ALNUM, 37),
    "huggingface": "hf_" + f(_LOW, 34),
    "tavily": "tvly-" + f(_ALNUM, 32),
    "stripe-prod": "sk_prod_" + f(_ALNUM, 24),
    "stripe-webhook": "whsec_" + f(_ALNUM, 40),
    "shopify": "shpat_" + f(_HEX, 32),
    "github-refresh": "ghr_" + f(_ALNUM, 36),
    "gitlab-deploy": "gldt-" + f(_ALNUM, 20),
    "npm": "npm_" + f(_ALNUM, 36),
    "pypi": "pypi-AgEIcHlwaS5vcmc" + f(_ALNUM, 60),
    "docker": "dckr_pat_" + f(_ALNUM, 30),
    "digitalocean": "dop_v1_" + f(_HEX, 64),
    "heroku": "HRKU-AA" + f(_ALNUM, 58),
    "doppler": "dp.pt." + f(_ALNUM, 43),
    "tailscale": "tskey-auth-" + f(_ALNUM, 12) + "-" + f(_ALNUM, 24),
    "supabase": "sbp_" + f(_HEX, 40),
    "databricks": "dapi" + f(_HEX, 32),
    "google-oauth": "GOCSPX-" + f(_ALNUM, 28),
    "google-access": "ya29." + f(_ALNUM, 60),
    "slack-app": "xapp-1-A" + f(_UP, 10) + "-" + f("0123456789", 13) + "-" + f(_HEX, 64),
    "slack-webhook": "hooks.slack.com/services/T" + f(_UP, 8) + "/B" + f(_UP, 8) + "/" + f(_ALNUM, 24),
    "sendgrid": "SG." + f(_ALNUM, 22) + "." + f(_ALNUM, 43),
    "mailchimp": f(_HEX, 32) + "-us12",
    "twilio": "SK" + f(_HEX, 32),
    "telegram": "123456789:AA" + f(_ALNUM, 33),
    "linear": "lin_api_" + f(_ALNUM, 40),
    "postman": "PMAK-" + f(_HEX, 24) + "-" + f(_HEX, 34),
}

NOT_SECRETS = [
    "task-" + f(_ALNUM, 12),  # `sk-` inside an ordinary slug
    "sk-learn is a library",
    "nx_build_cache and nx_graph",
    "nx_" + f(_HEX, 12),  # too short to be a key
    "hf_dataset_loader",
    "dapi is the data API",
    "see https://hooks.slack.com/ for docs",
    "npm_config_registry",
    "git commit " + f(_HEX, 40),
    "cache-key-" + f(_HEX, 32),  # md5 cache keys are not Mailgun keys
]


def _matches(text: str) -> list[str]:
    out: list[str] = []
    for p in patterns.builtin_patterns():
        r = subprocess.run(["grep", "-oE", "--", p], input=text, capture_output=True, text=True)
        out += r.stdout.split()
    return out


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_vendor_key_is_detected(name):
    sample = SAMPLES[name]
    assert sample in _matches(f"export K={sample} # note")


@pytest.mark.parametrize("text", NOT_SECRETS)
def test_lookalike_is_ignored(text):
    assert _matches(text) == []


def test_every_pattern_is_valid_ere():
    for p in patterns.builtin_patterns():
        assert subprocess.run(["grep", "-E", "--", p], input="", capture_output=True, text=True).returncode in (0, 1), p


def test_prompt_guard_blocks_and_cloaks_nx_key(tmp_path):
    key = SAMPLES["nx"]
    env = {**os.environ, "PRISMOR_HOME": str(tmp_path), "PRISMOR_SECRETS_DIR": str(tmp_path / "secrets"),
           "PRISMOR_CLOAK_PATTERNS": str(tmp_path / "none.txt")}
    r = subprocess.run(["bash", str(_HOOKS / "userprompt-guard.sh")], capture_output=True, text=True, env=env,
                       input=json.dumps({"session_id": "t", "prompt": f"can u use {key} on the api"}))
    out = json.loads(r.stdout)
    assert out["decision"] == "block"
    assert key not in r.stdout
    assert re.search(r"@@SECRET:auto_\w+@@", r.stdout)
    assert any(key in p.read_text() for p in (tmp_path / "secrets").iterdir())
