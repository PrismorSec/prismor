"""Per-agent transcript adapters."""

from __future__ import annotations

from typing import Dict, List

from prismor.runtime.transcripts.adapters.claude import ClaudeAdapter
from prismor.runtime.transcripts.adapters.codex import CodexAdapter
from prismor.runtime.transcripts.adapters.hermes import HermesAdapter

#: Registry consulted by the driver and by `--agent`. Adding an agent means
#: adding one module and one entry here.
ADAPTERS: Dict[str, object] = {
    ClaudeAdapter.agent: ClaudeAdapter,
    CodexAdapter.agent: CodexAdapter,
    HermesAdapter.agent: HermesAdapter,
}


def get_adapters(names: List[str] | None = None) -> List[object]:
    if not names or "all" in names:
        return [cls() for cls in ADAPTERS.values()]
    missing = [n for n in names if n not in ADAPTERS]
    if missing:
        raise KeyError(
            f"no transcript adapter for {', '.join(sorted(missing))} "
            f"(available: {', '.join(sorted(ADAPTERS))})"
        )
    return [ADAPTERS[n]() for n in names]


__all__ = ["ADAPTERS", "ClaudeAdapter", "CodexAdapter", "HermesAdapter", "get_adapters"]
