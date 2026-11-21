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
