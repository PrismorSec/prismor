"""The proxy must tell people to point Codex at it with -c openai_base_url.

Codex ignores OPENAI_BASE_URL, so the old banner hint sent its traffic straight
to OpenAI and the proxy saw nothing (see docs/llm-proxy.md).
"""
import inspect
import re
import unittest

from prismor.runtime import proxy


class CodexHintTest(unittest.TestCase):
    def test_no_hint_sets_openai_base_url_for_codex(self):
        src = inspect.getsource(proxy)
        self.assertIsNone(re.search(r"OPENAI_BASE_URL=\S+\s+codex", src))
        self.assertIn("codex -c openai_base_url=", inspect.getsource(proxy.run_proxy))


if __name__ == "__main__":
    unittest.main()
