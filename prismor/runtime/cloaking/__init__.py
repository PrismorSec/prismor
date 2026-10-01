"""Prismor — cloaking subsystem.

Prevention layer that keeps real secret values out of AI coding agent
context, JSONL transcripts, and upstream API requests. Complements
``prismor sweep`` (post-hoc remediation) by providing realtime protection
at the tool boundary via Claude Code and Hermes Agent hooks.

Public entry points (imported by ``prismor/runtime/cli.py``):
  install    — merge cloaking hooks into .claude/settings.json (Claude Code)
  uninstall  — remove Claude Code cloaking hooks
  status     — check Claude Code cloaking installation state
  hermes_install   — install cloaking plugin for Hermes Agent
  hermes_uninstall — remove cloaking plugin from Hermes Agent
  hermes_status    — check Hermes cloaking installation state
  add_secret / list_secrets / remove_secret / secrets_dir
  add_pattern / remove_pattern / list_custom_patterns
"""

from __future__ import annotations

from prismor.runtime.cloaking.installer import install, uninstall, status
from prismor.runtime.cloaking.hermes_installer import (
    install as hermes_install,
    uninstall as hermes_uninstall,
    status as hermes_status,
)
from prismor.runtime.cloaking.patterns import (
    add_pattern,
    all_patterns,
    list_org_patterns,
    org_patterns_file,
    write_org_patterns,
    builtin_patterns,
    custom_patterns_file,
    list_custom_patterns,
    remove_pattern,
)
from prismor.runtime.cloaking.secrets_store import (
    add_env_secrets,
    add_secret,
    list_secrets,
    parse_env_file,
    remove_secret,
    secrets_dir,
)

__all__ = [
    "install",
    "uninstall",
    "status",
    "hermes_install",
    "hermes_uninstall",
    "hermes_status",
    "add_env_secrets",
    "add_secret",
    "list_secrets",
    "parse_env_file",
    "remove_secret",
    "secrets_dir",
    "add_pattern",
    "remove_pattern",
    "list_custom_patterns",
    "builtin_patterns",
    "all_patterns",
    "list_org_patterns",
    "org_patterns_file",
    "write_org_patterns",
    "custom_patterns_file",
]
