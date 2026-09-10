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
