"""Tests for the _no_module_state_leaks fixture in conftest.py.

Verifies that bare module/class-level attribute modifications (lambdas,
MagicMocks, None, del) are detected at teardown, reported with the exact
attribute path, and restored to prevent contamination of subsequent tests.
"""
from __future__ import annotations

import unittest.mock as mock
import pytest

import prismor.runtime.enterprise.identity as ident
from prismor.runtime.policy_engine import PolicyEngine
from tests.conftest import _no_module_state_leaks


def test_leak_guard_detects_lambda_leak():
    orig = ident.load_identity
    gen = _no_module_state_leaks.__wrapped__()
    next(gen)
    ident.load_identity = lambda *a, **k: None
    with pytest.raises(pytest.fail.Exception, match=r"prismor\.runtime\.enterprise\.identity\.load_identity"):
        try:
            next(gen)
        except StopIteration:
            pass
    assert ident.load_identity is orig


def test_leak_guard_detects_magicmock_leak():
    orig = ident.load_identity
    gen = _no_module_state_leaks.__wrapped__()
    next(gen)
    ident.load_identity = mock.MagicMock(return_value=None)
    with pytest.raises(pytest.fail.Exception, match=r"prismor\.runtime\.enterprise\.identity\.load_identity"):
        try:
            next(gen)
        except StopIteration:
            pass
    assert ident.load_identity is orig


def test_leak_guard_detects_none_leak():
    orig = ident.load_identity
    gen = _no_module_state_leaks.__wrapped__()
    next(gen)
    ident.load_identity = None
    with pytest.raises(pytest.fail.Exception, match=r"prismor\.runtime\.enterprise\.identity\.load_identity"):
        try:
            next(gen)
        except StopIteration:
            pass
    assert ident.load_identity is orig


def test_leak_guard_detects_del_leak():
    orig = ident.load_identity
    gen = _no_module_state_leaks.__wrapped__()
    next(gen)
    del ident.load_identity
    with pytest.raises(pytest.fail.Exception, match=r"prismor\.runtime\.enterprise\.identity\.load_identity"):
        try:
            next(gen)
        except StopIteration:
            pass
    assert ident.load_identity is orig


def test_leak_guard_detects_class_method_leak():
    orig = PolicyEngine.__init__
    gen = _no_module_state_leaks.__wrapped__()
    next(gen)
    PolicyEngine.__init__ = mock.MagicMock(return_value=None)
    with pytest.raises(pytest.fail.Exception, match=r"PolicyEngine\.__init__"):
        try:
            next(gen)
        except StopIteration:
            pass
    assert PolicyEngine.__init__ is orig


def test_leak_guard_clean_run_passes():
    gen = _no_module_state_leaks.__wrapped__()
    next(gen)
    try:
        next(gen)
    except StopIteration:
        pass


def test_leak_guard_detects_class_object_mock_leak():
    import prismor.runtime.policy_engine as pe
    orig_pe = pe.PolicyEngine
    orig_init = pe.PolicyEngine.__init__
    gen = _no_module_state_leaks.__wrapped__()
    next(gen)
    pe.PolicyEngine = mock.MagicMock(return_value=None)
    with pytest.raises(pytest.fail.Exception, match=r"PolicyEngine"):
        try:
            next(gen)
        except StopIteration:
            pass
    assert pe.PolicyEngine is orig_pe
    assert pe.PolicyEngine.__init__ is orig_init


def test_leak_guard_unrestorable_leak_self_heals_without_poisoning_baseline():
    """Verify that an unrestorable leak self-heals its slot so subsequent tests
    do not suffer cascading teardown failures, while preserving the authentic
    baseline so that cleanly restoring the original function resets the slot."""
    import tests.conftest as tc
    orig_func = ident.load_identity
    gen1 = _no_module_state_leaks.__wrapped__()
    next(gen1)
    corrupted_mock = lambda *a, **k: "corrupted"
    ident.load_identity = corrupted_mock

    # Simulate an unrestorable leak where _restore cannot put the original back
    with mock.patch.object(tc, "_restore", side_effect=lambda key, orig: f"{key[1]}.{key[2]}"):
        with pytest.raises(pytest.fail.Exception, match=r"load_identity"):
            try:
                next(gen1)
            except StopIteration:
                pass

    # Baseline remains authentic; slot pristine self-healed to prevent cascading failure
    slot = [s for s in tc._SLOTS if s[2] == "load_identity"][0]
    assert tc._BASELINE[slot[5]] is orig_func, "Authentic baseline was overwritten!"
    assert slot[4] is corrupted_mock, "Slot failed to self-heal for subsequent tests!"

    # Subsequent clean test passes without cascading teardown failure
    gen2 = _no_module_state_leaks.__wrapped__()
    next(gen2)
    try:
        next(gen2)
    except StopIteration:
        pass

    # Clean up: restore authentic function; guard recognizes baseline and resets slot
    ident.load_identity = orig_func
    gen3 = _no_module_state_leaks.__wrapped__()
    next(gen3)
    try:
        next(gen3)
    except StopIteration:
        pass
    assert ident.load_identity is orig_func
    slot_after = [s for s in tc._SLOTS if s[2] == "load_identity"][0]
    assert slot_after[4] is orig_func, "Slot failed to reset back to authentic function!"
