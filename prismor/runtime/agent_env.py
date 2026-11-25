"""Is this process running inside an AI coding agent's shell?

Kept free of side effects so status, cloak install and the version notice can
ask without importing the setup wizard (which owns the terminal on import).
"""
from __future__ import annotations

import os

# Env vars agent CLIs set on the shells they spawn. ponytail: a known-names
# list, not a general detector; add an agent here when it sets its own marker.
_AGENT_ENV = ("AI_AGENT", "CLAUDECODE", "CODEX_THREAD_ID", "CODEX_SANDBOX", "CURSOR_AGENT", "GEMINI_CLI")


def running_under_agent() -> bool:
    return any(os.environ.get(k) for k in _AGENT_ENV)


# Marker -> the agent name the store and dashboard use. Keep in step with
# the same list in cloaking/hooks/decloak-exec.sh.
_AGENT_NAMES = (("CLAUDECODE", "claude"), ("CODEX_THREAD_ID", "codex"), ("CODEX_SANDBOX", "codex"),
                ("CURSOR_AGENT", "cursor"), ("GEMINI_CLI", "gemini"))


def caller_agents() -> list:
    """Names this process runs as: the agent kind from its env marker and, if
    set, the PRISMOR_AGENT_ID identity. Used to scope cloaked secrets.
    ponytail: read from the environment, so the same trust boundary as
    PRISMOR_AGENT_ID (iam.py) -- an agent that rewrites its own env before a
    child resolves a secret can pose as another. Pass the identity from the
    hook itself if that matters."""
    out = [name for key, name in _AGENT_NAMES if os.environ.get(key)][:1]
    if os.environ.get("PRISMOR_AGENT_ID"):
        out.append(os.environ["PRISMOR_AGENT_ID"])
    return out
