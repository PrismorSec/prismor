"""Every urllib Request the runtime builds must set a User-Agent.

urllib's default ``Python-urllib/x.y`` is refused by Cloudflare (403, error
code 1010) before the request reaches the control plane, which is how
`prismor egress request` and `prismor exempt request` broke. A function that
builds a ``Request`` has to name the header itself, normally via
``prismor.runtime.http_ua.user_agent()``.
"""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent / "prismor"


def _missing_user_agent():
    bad = []
    for path in ROOT.rglob("*.py"):
        src = path.read_text(encoding="utf-8")
        for fn in ast.walk(ast.parse(src)):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            builds_request = any(
                isinstance(n, ast.Call) and ast.unparse(n.func) in ("Request", "urllib.request.Request")
                for n in ast.walk(fn)
            )
            body = ast.get_source_segment(src, fn) or ""
            if builds_request and "User-Agent" not in body and "user_agent" not in body:
                bad.append(f"{path.relative_to(ROOT.parent)}:{fn.lineno} {fn.name}")
    return sorted(bad)


class UserAgentTest(unittest.TestCase):
    def test_every_request_sets_a_user_agent(self):
        self.assertEqual(_missing_user_agent(), [])

    def test_control_plane_headers_carry_the_runtime_agent(self):
        from prismor.runtime.enterprise.approvals import _headers
        from prismor.runtime.http_ua import user_agent

        self.assertEqual(_headers({"device_key": "k"})["User-Agent"], user_agent())


if __name__ == "__main__":
    unittest.main()
