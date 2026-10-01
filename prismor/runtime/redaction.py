"""Result-side redaction, shared by every surface that can see tool output.

A pre-action hook can only refuse: it sees the request, never what comes back.
Surfaces that carry the *response* — the MCP gateway, the mirrored built-ins,
the evaluation server — can do better than refuse, by repairing the output so a
credential sitting in ordinary source never reaches the model's context. That
capability is the whole argument for the mirror, and it should not be
re-implemented once per surface.

Two passes, cheapest first: the cloak store is an exact-value substring swap,
the data-boundary classifier is pattern work over the same text.

Best-effort by contract
-----------------------
Redaction never raises and never fails a call closed. Pre-call policy has
already had its say, and the result scan still gets a vote; turning a masking
failure into a refusal would trade a small information leak for an outage,
which is the wrong trade for a tool that sits in the critical path of every
call an agent makes.

The bash twin
-------------
``cloaking/hooks/scrub-stream.sh`` does the equivalent job for Claude's
PostToolUse stream. It stays shell on purpose — that path is latency-critical
and cannot afford a Python start-up per call — so the two are kept in parity by
test, not by sharing code.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


_URL_PASSWORD = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)([^\s@/]+)(@)")


def redact_text(
    text: str,
    *,
    workspace: Optional[Path] = None,
    data_boundary: bool = True,
    engine: Any = None,
) -> Tuple[str, bool]:
    """Mask cloak secrets and classified data-boundary values in ``text``.

    Returns ``(text, changed)``. ``data_boundary=False`` runs cloak masking
    only — the split matters because ``prismor pause`` suspends *policy*
    (data boundary) while cloak masking keeps running: a paused agent must
    still not have raw secret values pushed into its context.

    ``engine`` is the ``PolicyEngine`` the caller already built for this call
    (every ``Decision`` carries one). Without it the classifier builds a fresh
    engine per string — 6.6 ms of rule construction on a 2-core box, which on
    a result-side path is paid once per tool call for nothing. Reusing the
    decision's engine took a 96-byte result from 9.5 ms to 0.17 ms, and is
    exactly as fresh as the decision that allowed the call.
    """
    if not isinstance(text, str) or not text:
        return text, False
    original = text

    try:
        from prismor.runtime.cloaking.runtime import scrub_text
        text = scrub_text(text)
    except Exception:
        pass

    # A password inside a connection URL (postgres://user:pass@host) is a
    # secret wherever it appears; the cloak vault only knows registered values
    # and the data-boundary classifier did not treat it as one (#542). Runs
    # with cloak masking, i.e. also while policy is paused.
    text = _URL_PASSWORD.sub(r"\1[REDACTED:secret]\3", text)

    if data_boundary:
        try:
            from prismor.runtime.data_boundary import redact_payload
            redacted = redact_payload(
                text, workspace=workspace,
                policy=getattr(engine, "data_boundary", None))
            if isinstance(redacted, str):
                text = redacted
        except Exception:
            pass

    return text, text != original


#: How far ``redact_payload_values`` descends. Framework result objects nest a
#: few levels (a result wrapper holding a list of models holding strings); past
#: that a payload is more likely a graph than a document, and a bounded walk is
#: what keeps a self-referencing result object from hanging the tool call.
_MAX_DEPTH = 8


def redact_payload_values(
    payload: Any,
    *,
    workspace: Optional[Path] = None,
    data_boundary: bool = True,
    engine: Any = None,
) -> Tuple[Any, bool]:
    """``redact_text`` over every string leaf of a dict/list/str payload.

    Objects carrying a ``__dict__`` (pydantic models, framework result
    wrappers) are redacted **in place** on their string attributes: once a
    framework has wrapped a tool result it is rarely a bare string any more,
    and rebuilding an arbitrary class from its fields is a guess this cannot
    afford to get wrong. An attribute that refuses assignment (frozen model,
    ``__slots__``, computed property) is left as it was rather than failing
    the call.
    """
    changed = False

    def _walk(x: Any, depth: int) -> Any:
        nonlocal changed
        if isinstance(x, str):
            out, hit = redact_text(x, workspace=workspace,
                                   data_boundary=data_boundary, engine=engine)
            changed = changed or hit
            return out
        if depth >= _MAX_DEPTH:
            return x
        if isinstance(x, dict):
            return {k: _walk(v, depth + 1) for k, v in x.items()}
        if isinstance(x, list):
            return [_walk(v, depth + 1) for v in x]
        if isinstance(x, tuple):
            return tuple(_walk(v, depth + 1) for v in x)
        attrs = getattr(x, "__dict__", None)
        if isinstance(attrs, dict) and not isinstance(x, type):
            for key, value in list(attrs.items()):
                if key.startswith("__"):
                    continue
                walked = _walk(value, depth + 1)
                if walked is value:
                    continue
                try:
                    setattr(x, key, walked)
                except Exception:
                    pass
        return x

    return _walk(payload, 0), changed


def redact_tool_result(
    result: Any,
    *,
    workspace: Optional[Path] = None,
    data_boundary: bool = True,
    engine: Any = None,
) -> Any:
    """Result-side redaction for an in-process SDK adapter. Never raises.

    An adapter holds the tool's return value before the framework hands it to
    the model — the one point in a framework agent where a credential sitting
    in ordinary source can still be masked. Adapters call this rather than
    :func:`redact_payload_values` directly so "best effort, never fail the call
    closed" is written once instead of once per adapter.
    """
    try:
        redacted, _ = redact_payload_values(
            result, workspace=workspace, data_boundary=data_boundary,
            engine=engine)
        return redacted
    except Exception:
        return result


def redact_mcp_result(
    result: Any,
    *,
    workspace: Optional[Path] = None,
    data_boundary: bool = True,
) -> Tuple[Any, bool]:
    """Redact the text blocks of an MCP ``tools/call`` result.

    Only ``content[].text`` and ``structuredContent`` are touched: other block
    kinds (images, resource links) are returned untouched rather than guessed
    at, and a result that is not shaped like an MCP result passes through
    unchanged.

    ``structuredContent`` matters as much as ``content``. Servers built on the
    MCP SDK's output schemas return the same payload twice, and a client that
    prefers the structured copy would be handed the very credential the text
    copy just had masked out.
    """
    if not isinstance(result, dict):
        return result, False
    content = result.get("content")
    structured = result.get("structuredContent")
    if not isinstance(content, list):
        if structured is None:
            return result, False
        content = []

    changed = False
    out: List[Any] = []
    for block in content:
        if not (isinstance(block, dict) and isinstance(block.get("text"), str)):
            out.append(block)
            continue
        text, hit = redact_text(
            block["text"], workspace=workspace, data_boundary=data_boundary)
        if hit:
            changed = True
            block = {**block, "text": text}
        out.append(block)

    structured_out = structured
    if structured is not None:
        structured_out, hit = _redact_tree(
            structured, workspace=workspace, data_boundary=data_boundary)
        changed = changed or hit

    if not changed:
        return result, False
    new = {**result}
    if result.get("content") is not None:
        new["content"] = out
    if structured is not None:
        new["structuredContent"] = structured_out
    return new, True


def _redact_tree(
    node: Any,
    *,
    workspace: Optional[Path] = None,
    data_boundary: bool = True,
) -> Tuple[Any, bool]:
    """Redact every string in a JSON tree. Keys are left alone — a credential
    lives in a value, and rewriting keys would break the schema the client is
    parsing against."""
    if isinstance(node, str):
        return redact_text(node, workspace=workspace, data_boundary=data_boundary)
    if isinstance(node, dict):
        out: Dict[str, Any] = {}
        changed = False
        for key, value in node.items():
            out[key], hit = _redact_tree(
                value, workspace=workspace, data_boundary=data_boundary)
            changed = changed or hit
        return (out, True) if changed else (node, False)
    if isinstance(node, list):
        items = []
        changed = False
        for value in node:
            item, hit = _redact_tree(
                value, workspace=workspace, data_boundary=data_boundary)
            items.append(item)
            changed = changed or hit
        return (items, True) if changed else (node, False)
    return node, False
