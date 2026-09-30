"""Audit P0 (#5): redacted telemetry must not leak raw paths/hosts/URLs/secrets
via the dynamic `title` field; assert_redacted must catch such leaks."""
import sys, os, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.enterprise.telemetry import build_record, assert_redacted, _safe_title, _title_has_leak


def _rec(title, **extra):
    return build_record(
        {"severity": "CRITICAL", "category": "secret_access", "ruleId": "x",
         "action": "block", "title": title, "evidence": "x", "mode": "enforce"},
        {"type": "file_read"}, extra=extra, full_capture=False,
    )


class TestTitleRedaction(unittest.TestCase):
    def test_strips_unix_path(self):
        self.assertEqual(_safe_title("token at /home/u/.aws/credentials", []),
                         "token at [path]")

    def test_strips_host(self):
        self.assertEqual(_safe_title("domain not allowed: evil-exfil.example.com", []),
                         "domain not allowed: [host]")

    def test_strips_url_and_embedded_secret(self):
        out = _safe_title("secret in URL: https://evil.com/?k=sk_live_abc", [])
        self.assertNotIn("evil.com", out)
        self.assertNotIn("sk_live_abc", out)
        self.assertIn("[url]", out)

    def test_static_title_survives(self):
        t = "Blocks rm -rf /, mkfs, dd to disk, shutdown, reboot"
        self.assertEqual(_safe_title(t, []), t)

    def test_redacted_record_has_no_leak_and_passes_guard(self):
        rec = _rec("Canarytoken accessed: token at /home/u/.ssh/id_rsa",
                   repo="github.com/acme/payments")
        self.assertNotIn("/home/u/.ssh/id_rsa", rec["title"])
        self.assertEqual(rec["repo"], "github.com/acme/payments")  # repo is org context, kept
        assert_redacted(rec)  # must not raise

    def test_guard_catches_raw_leak(self):
        with self.assertRaises(AssertionError):
            assert_redacted({"redacted": True, "title": "read /etc/shadow"})

    def test_guard_allows_repo_field(self):
        # repo looks host/path-like but is intentionally allowed
        assert_redacted({"redacted": True, "title": "clean static title",
                         "repo": "github.com/acme/x"})


if __name__ == "__main__":
    unittest.main()


# ── #278: bundled rule titles are policy text, never redacted ────────────────

def test_catalog_rule_titles_survive_redaction():
    from prismor.runtime.enterprise.telemetry import _catalog_titles, _safe_title, _title_has_leak
    titles = _catalog_titles()
    chmod = next(t for t in titles if "chmod/chown" in t)
    io = next(t for t in titles if "agent I/O" in t)
    for t in (chmod, io, f"Possible evasion of: {chmod}"):
        assert _safe_title(t, []) == t
        assert not _title_has_leak(t)


def test_dynamic_part_next_to_a_rule_title_is_still_scrubbed():
    from prismor.runtime.enterprise.telemetry import _catalog_titles, _safe_title, _title_has_leak
    rule = next(t for t in _catalog_titles() if "chmod/chown" in t)
    out = _safe_title(f"{rule} (in /home/alice/secret-project/run.sh)", [])
    assert out == f"{rule} (in [path])"
    assert _title_has_leak(f"{rule} (in /home/alice/x.sh)")
