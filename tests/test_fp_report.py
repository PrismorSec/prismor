"""Agent false-positive reports and the human-label learning loop.

A block names its event id and a console link; the agent may only ASK with
`prismor report-fp`; a reviewer's label comes back through
`prismor learn --console`, where a confirmed FP proposes a narrow allowlist
entry and a confirmed TP pins the rule against relaxing.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import learning, unblock
from prismor.runtime.enterprise import fp_report, identity, telemetry
from prismor.runtime.store import persist_runtime_findings

IDENT = {"device_key": "pk_test", "device_id": "d1", "api_base": "https://console.example"}


def _finding(**over):
    f = {"ruleId": "instruction-file-write", "severity": "HIGH", "category": "memory",
         "title": "Write to an instruction file", "evidence": "cat CLAUDE.md", "action": "block",
         "eventId": "evt_abc"}
    f.update(over)
    return f


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestBlockMessage(unittest.TestCase):
    def test_enrolled_block_links_the_event_and_offers_report_fp(self):
        with mock.patch.object(identity, "load_identity", return_value=IDENT):
            text = unblock.format_unblock(_finding(), session_id="s 1", enrolled=True)
        self.assertIn("prismor report-fp evt_abc --reason", text)
        self.assertIn("https://console.example/admin/sessions/s%201?event=evt_abc", text)

    def test_no_link_when_not_enrolled_or_no_event_id(self):
        with mock.patch.object(identity, "load_identity", return_value=None):
            self.assertNotIn("report-fp", unblock.format_unblock(_finding(), session_id="s1", enrolled=True))
        with mock.patch.object(identity, "load_identity", return_value=IDENT):
            self.assertNotIn("report-fp", unblock.format_unblock(_finding(eventId=None), session_id="s1", enrolled=True))
            self.assertNotIn("report-fp", unblock.format_unblock(_finding(), session_id="s1", enrolled=False))


class TestEventId(unittest.TestCase):
    def test_console_record_reuses_the_minted_event_id(self):
        rec = telemetry.build_record(_finding(), {"type": "shell", "command": "cat CLAUDE.md"}, extra={})
        self.assertEqual(rec["event_id"], "evt_abc")
        self.assertTrue(telemetry.build_record(_finding(eventId=None), {"type": "shell"}, extra={})["event_id"].startswith("evt_"))


class TestReport(unittest.TestCase):
    def test_report_posts_reason_to_its_event_and_returns_the_link(self):
        seen = {}

        def fake_urlopen(req, timeout=0):
            seen["url"], seen["method"] = req.full_url, req.get_method()
            seen["body"] = json.loads(req.data)
            seen["auth"] = req.get_header("Authorization")
            return _Resp(json.dumps({"ok": True, "reported": True, "sessionId": "s1"}).encode())

        with mock.patch.object(identity, "load_identity", return_value=IDENT), \
                mock.patch("urllib.request.urlopen", fake_urlopen):
            res = fp_report.report("evt_abc", "read, not a write")
        self.assertEqual(seen["url"], "https://console.example/api/devices/events/evt_abc/report-fp")
        self.assertEqual((seen["method"], seen["body"], seen["auth"]), ("POST", {"reason": "read, not a write"}, "Bearer pk_test"))
        self.assertTrue(res["reported"])
        self.assertEqual(res["url"], "https://console.example/admin/sessions/s1?event=evt_abc")

    def test_not_enrolled_is_a_clear_error(self):
        with mock.patch.object(identity, "load_identity", return_value=None):
            self.assertIn("not enrolled", fp_report.report("evt_abc", "x")["error"])


class TestLearnFromLabels(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _label(self, event_id, label, rule="instruction-file-write", at="2026-11-17T10:00:00.000Z"):
        return {"eventId": event_id, "ruleId": rule, "toolName": "Bash", "label": label, "at": at}

    def test_one_human_fp_is_reported_with_the_local_command(self):
        persist_runtime_findings(self.ws, "s1", [_finding(id="s1:f1")], 0)
        learning.save_console_labels(self.ws, [self._label("evt_abc", "false_positive")])
        fps = learning.track_false_positives(self.ws, threshold=5)
        self.assertEqual(len(fps), 1)
        r = fps[0]
        self.assertEqual((r["rule_id"], r["confirmed_fp"], r["pinned"]), ("instruction-file-write", 1, False))
        self.assertEqual(r["sample_evidence"], ["cat CLAUDE.md"])
        self.assertIn("allowlist", r["recommendation"])

    def test_a_true_positive_pins_the_rule(self):
        learning.save_console_labels(self.ws, [
            self._label("evt_1", "false_positive"), self._label("evt_2", "true_positive"),
        ])
        r = learning.track_false_positives(self.ws)[0]
        self.assertTrue(r["pinned"])
        self.assertIn("do not lower or allow", r["recommendation"])

    def test_only_true_positives_propose_nothing(self):
        learning.save_console_labels(self.ws, [self._label("evt_2", "true_positive")])
        self.assertEqual(learning.track_false_positives(self.ws), [])

    def test_relabel_replaces_and_cursor_tracks_newest(self):
        learning.save_console_labels(self.ws, [self._label("evt_1", "false_positive")])
        learning.save_console_labels(self.ws, [self._label("evt_1", "true_positive", at="2026-11-17T11:00:00.000Z")])
        self.assertEqual(learning.track_false_positives(self.ws), [])
        self.assertEqual(learning.console_labels_cursor(self.ws), "2026-11-17T11:00:00.000Z")

    def test_pull_pages_with_since_and_stores_labels(self):
        calls = []
        pages = [
            {"labels": [self._label("evt_1", "false_positive")], "hasMore": True},
            {"labels": [self._label("evt_1", "false_positive"), self._label("evt_2", "true_positive", at="2026-11-17T12:00:00.000Z")], "hasMore": False},
        ]

        def fake_urlopen(req, timeout=0):
            calls.append(req.full_url)
            return _Resp(json.dumps(pages[len(calls) - 1]).encode())

        with mock.patch.object(identity, "load_identity", return_value=IDENT), \
                mock.patch("urllib.request.urlopen", fake_urlopen):
            res = fp_report.pull_labels(self.ws)
        self.assertTrue(res["ok"])
        self.assertEqual(calls[0], "https://console.example/api/devices/labels")
        self.assertIn("since=2026-11-17T10%3A00%3A00.000Z", calls[1])
        self.assertEqual(learning.console_labels_cursor(self.ws), "2026-11-17T12:00:00.000Z")


if __name__ == "__main__":
    unittest.main()
