"""Stdio MCP upstreams get a minimal environment, not the gateway's own."""
from __future__ import annotations

from prismor.runtime.mcp_gateway import _spec_from_entry, parse_inline_server, stdio_env

BASE = {"PATH": "/usr/bin", "HOME": "/h", "LC_ALL": "C", "npm_config_registry": "r",
        "HTTPS_PROXY": "p", "AWS_SECRET_ACCESS_KEY": "s", "GITHUB_TOKEN": "t",
        "OPENAI_API_KEY": "k"}


def _spec(**cfg):
    return _spec_from_entry("srv", {"command": "npx", "args": ["-y", "x"], **cfg})


def test_default_drops_credentials_keeps_runtime_vars():
    env = stdio_env(_spec(env={"FOO": "1"}), BASE)
    assert env == {"PATH": "/usr/bin", "HOME": "/h", "LC_ALL": "C",
                   "npm_config_registry": "r", "HTTPS_PROXY": "p", "FOO": "1"}


def test_passthrough_and_entry_env_win():
    env = stdio_env(_spec(envPassthrough=["GITHUB_TOKEN"], env={"PATH": "/x"}), BASE)
    assert env["GITHUB_TOKEN"] == "t" and env["PATH"] == "/x"
    assert "AWS_SECRET_ACCESS_KEY" not in env


def test_inherit_env_opt_out():
    env = stdio_env(_spec(inheritEnv=True), BASE)
    assert env["OPENAI_API_KEY"] == "k" and env["AWS_SECRET_ACCESS_KEY"] == "s"


def test_cli_named_servers_keep_full_env():
    # --server / --upstream have no config entry to name envPassthrough in,
    # and the host passes that server's env to the gateway process.
    env = stdio_env(parse_inline_server("gh=npx -y server-github"), BASE)
    assert env["GITHUB_TOKEN"] == "t"
