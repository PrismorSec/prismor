"""A custom rule pattern starting with `(?i)` used to crash the whole engine
("global flags not at the start of the expression") once joined with others —
agents write patterns this way, and policy validate still said VALID."""
import re

from prismor.runtime.policy_engine import _alternation


def test_leading_inline_flags_are_scoped_per_pattern():
    rx = re.compile(_alternation(["(?i)pastebin\\.com", "(?s)a.b", "plain"]))
    assert rx.search("curl https://PASTEBIN.com/x")
    assert rx.search("a\nb")
    assert rx.search("plain")
