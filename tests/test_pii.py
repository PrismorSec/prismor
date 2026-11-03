"""Optional Presidio PII detection. The default policy must not import it."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.hooks import should_block
from prismor.runtime.pii import (
    PiiSettings,
    anonymize,
    detect,
    install_analyzer_for_tests,
    public_mask,
    reset_for_tests,
)
from prismor.runtime.policy_engine import PolicyEngine, validate_policy
from prismor.runtime.redaction import redact_mcp_result, redact_text
from prismor.runtime.transforms import apply_transform


_OVERLAY = """\
version: "1.0"
rules: []
settings:
  pii:
    enabled: true
    backend: regex
    action: {action}
    mode: {mode}
    mask_style: {style}
    entities:
      - EMAIL_ADDRESS
      - PHONE_NUMBER
      - CREDIT_CARD
      - IBAN_CODE
      - US_SSN
      - UK_NHS
      - IP_ADDRESS
      - PERSON
      - LOCATION
"""

_SAMPLE = (
    "email ada.lovelace@nhs.net ssn 578-12-4456 phone 202-418-1000 "
    "nhs 943 476 5919 ip 203.0.113.10 card 4000000000000002 "
    "iban FR1420041010050500013M02606"
)
_RAW = (
    "ada.lovelace@nhs.net",
    "578-12-4456",
    "202-418-1000",
    "943 476 5919",
    "203.0.113.10",
    "4000000000000002",
    "FR1420041010050500013M02606",
    "nhs.net",
)


class _Analyzer:
    def __init__(self):
        self.calls = 0
        self.languages = []
        self.entities = []

    def analyze(self, text, language, entities, score_threshold):
        self.calls += 1
        self.languages.append(language)
        self.entities.append(list(entities))
        hits = []
        needle = "Ada Lovelace"
        start = text.find(needle)
        if start >= 0 and (not entities or "PERSON" in entities) and score_threshold <= 0.9:
            hits.append(_Span("PERSON", start, start + len(needle), 0.91))
        low = "Bob"
        at = text.find(low)
        if at >= 0 and (not entities or "PERSON" in entities):
            hits.append(_Span("PERSON", at, at + len(low), 0.2))
        return hits


class _Span:
    def __init__(self, entity_type, start, end, score):
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = score


def _engine(tmp, action="observe", mode="observe", style="mask", extra=""):
    path = Path(tmp) / "policy.yaml"
    path.write_text(_OVERLAY.format(action=action, mode=mode, style=style) + extra)
    return PolicyEngine(policy_path=path)


class PiiDisabledTests(unittest.TestCase):
    def test_default_policy_does_not_scan_or_import(self):
        already = "presidio_analyzer" in sys.modules
        engine = PolicyEngine()
        self.assertFalse(engine.pii.enabled)
        self.assertEqual(engine.pii.backend, "presidio")
        self.assertIn("PERSON", engine.pii.entities)
        with patch("prismor.runtime.pii.detect", side_effect=AssertionError("detect called")):
            findings = engine.evaluate({
                "type": "prompt",
                "prompt": "Patient Ada Lovelace, NHS 943 476 5919, ada.lovelace@nhs.net",
                "agent_event": "prompt",
            }, 0)
        self.assertFalse(any(f.get("ruleId") == "pii-ner" for f in findings))
        if not already:
            self.assertNotIn("presidio_analyzer", sys.modules)

    def test_redact_text_unchanged_when_disabled(self):
        engine = PolicyEngine()
        text = "Patient Ada Lovelace was admitted"
        out, changed = redact_text(text, engine=engine)
        self.assertEqual(out, text)
        self.assertFalse(changed)

    def test_export_includes_pii_settings(self):
        from prismor.runtime.policy_engine import export_effective_policy
        exported = export_effective_policy(PolicyEngine())
        self.assertFalse(exported["settings"]["pii"]["enabled"])


class PiiRegexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(reset_for_tests)

    def _find(self, text, *, action="observe", mode="observe", event_type="prompt", field="prompt"):
        engine = _engine(self.tmp.name, action=action, mode=mode)
        event = {"type": event_type, field: text, "agent_event": "PreToolUse"}
        findings = [f for f in engine.evaluate(event, 3, session_id="s") if f.get("ruleId") == "pii-ner"]
        return engine, findings

    def test_regex_finds_structured_pii_and_hides_values(self):
        _engine, findings = self._find(_SAMPLE)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["piiBackend"], "regex")
        self.assertEqual(finding["action"], "warn")
        self.assertEqual(finding["mode"], "observe")
        self.assertEqual(finding["category"], "pii_exposure")
        self.assertIn("PERSON", finding["piiUnsupported"])
        self.assertIn("LOCATION", finding["piiUnsupported"])
        entities = set(finding["entities"])
        self.assertTrue({
            "EMAIL_ADDRESS", "US_SSN", "PHONE_NUMBER", "UK_NHS",
            "IP_ADDRESS", "CREDIT_CARD", "IBAN_CODE",
        } <= entities)
        blob = finding["title"] + finding["evidence"] + str(finding.get("remediation"))
        for raw in _RAW:
            self.assertNotIn(raw, blob)

    def test_fixtures_are_not_findings(self):
        _engine, findings = self._find(
            "user@example.com 202-555-0199 123-45-6789 4111111111111111"
        )
        self.assertEqual(findings, [])

    def test_tool_result_and_command_are_scanned(self):
        _, tool = self._find("ssn 578-12-4456", event_type="tool_result", field="response")
        _, shell = self._find("echo 578-12-4456", event_type="shell", field="command")
        self.assertEqual(tool[0]["entities"], ["US_SSN"])
        self.assertEqual(shell[0]["entities"], ["US_SSN"])
        self.assertEqual(shell[0]["severity"], "HIGH")

    def test_block_waits_for_enforce(self):
        event = {
            "type": "shell",
            "command": "echo 578-12-4456",
            "agent_event": "PreToolUse",
        }
        observing = _engine(self.tmp.name, action="block", mode="observe")
        found = [f for f in observing.evaluate(event, 0) if f.get("ruleId") == "pii-ner"]
        self.assertEqual(found[0]["mode"], "observe")
        self.assertIsNone(should_block(found, event))

        enforcing = _engine(self.tmp.name, action="block", mode="enforce")
        found = [f for f in enforcing.evaluate(event, 0) if f.get("ruleId") == "pii-ner"]
        self.assertEqual(found[0]["action"], "block")
        self.assertEqual(found[0]["mode"], "enforce")
        self.assertEqual(should_block(found, event)["ruleId"], "pii-ner")

    def test_redact_rewrites_and_records_a_modify(self):
        engine = _engine(self.tmp.name, action="redact", mode="enforce", style="replace")
        event = {"type": "prompt", "prompt": "ssn 578-12-4456", "agent_event": "prompt"}
        finding = next(f for f in engine.evaluate(event, 1) if f.get("ruleId") == "pii-ner")
        self.assertEqual(finding["action"], "modify")
        self.assertEqual(finding["transform"], "pii_ner_redact")
        # Unkeyed, so the data-boundary pass leaves it and the PII pass rewrites it.
        out, changed = redact_text("record 578-12-4456", engine=engine)
        self.assertTrue(changed)
        self.assertNotIn("578-12-4456", out)
        self.assertIn("<US_SSN>", out)

    def test_redact_off_while_policy_paused(self):
        engine = _engine(self.tmp.name, action="redact", mode="enforce", style="replace")
        out, changed = redact_text("ssn 578-12-4456", engine=engine, data_boundary=False)
        self.assertIn("578-12-4456", out)
        self.assertFalse(changed)

    def test_allowlist_suppresses_without_storing_the_value(self):
        extra = """
allowlists:
  - id: known-email
    rule_ids: ["pii-ner"]
    patterns: ["ada\\\\.lovelace@nhs\\\\.net"]
    reason: directory listing
"""
        path = Path(self.tmp.name) / "policy.yaml"
        path.write_text(_OVERLAY.format(action="observe", mode="observe", style="mask") + extra)
        engine = PolicyEngine(policy_path=path)
        findings = engine.evaluate({
            "type": "prompt",
            "prompt": "write to ada.lovelace@nhs.net",
            "agent_event": "prompt",
        }, 0)
        self.assertFalse(any(f.get("ruleId") == "pii-ner" for f in findings))

    def test_invalid_action_is_rejected(self):
        path = Path(self.tmp.name) / "bad.yaml"
        path.write_text(
            'version: "1.0"\nrules: []\nsettings:\n  pii:\n    enabled: true\n    action: delete\n'
        )
        errors = validate_policy(path)
        self.assertTrue(any("settings.pii.action" in e for e in errors))

    def test_partial_override_keeps_defaults(self):
        path = Path(self.tmp.name) / "policy.yaml"
        path.write_text(
            'version: "1.0"\nrules: []\nsettings:\n  pii:\n    enabled: true\n    action: block\n'
        )
        engine = PolicyEngine(policy_path=path)
        self.assertTrue(engine.pii.enabled)
        self.assertEqual(engine.pii.action, "block")
        self.assertEqual(engine.pii.mode, "observe")
        self.assertEqual(engine.pii.model, "en_core_web_sm")
        self.assertIn("UK_NHS", engine.pii.entities)

    def test_truncation_flag(self):
        path = Path(self.tmp.name) / "policy.yaml"
        path.write_text(
            _OVERLAY.format(action="observe", mode="observe", style="mask")
            + "    max_chars: 200\n"
        )
        engine = PolicyEngine(policy_path=path)
        text = "ssn 578-12-4456 " + ("x" * 400)
        finding = next(
            f for f in engine.evaluate(
                {"type": "prompt", "prompt": text, "agent_event": "prompt"}, 0,
            )
            if f.get("ruleId") == "pii-ner"
        )
        self.assertTrue(finding["piiTruncated"])
        self.assertNotIn("578-12-4456", finding["evidence"])

    def test_script_lines_are_not_scanned(self):
        engine = _engine(self.tmp.name)
        findings = engine.evaluate({
            "type": "shell",
            "command": "echo 578-12-4456",
            "agent_event": "PreToolUse",
            "_script_line": True,
        }, 0)
        self.assertFalse(any(f.get("ruleId") == "pii-ner" for f in findings))


class PiiMaskTests(unittest.TestCase):
    def test_public_mask_hides_the_value(self):
        self.assertEqual(public_mask("ada.lovelace@nhs.net"), "•••@••••")
        self.assertNotIn("lovelace", public_mask("Ada Lovelace").lower())
        self.assertNotIn("578", public_mask("578-12-4456"))

    def test_styles(self):
        from prismor.runtime.pii import PiiHit
        hit = PiiHit("US_SSN", 0.9, 4, 15, "578-12-4456")
        text = "ssn 578-12-4456"
        masked = anonymize(text, [hit], "mask", prefer_presidio=False)
        replaced = anonymize(text, [hit], "replace", prefer_presidio=False)
        hashed = anonymize(text, [hit], "hash", prefer_presidio=False)
        redacted = anonymize(text, [hit], "redact", prefer_presidio=False)
        for out in (masked, replaced, hashed, redacted):
            self.assertNotIn("578-12-4456", out)
        self.assertIn("<US_SSN>", replaced)
        self.assertIn("[REDACTED]", redacted)
        self.assertEqual(len(hashed.split()[-1]), 16)


class PiiPresidioDoubleTests(unittest.TestCase):
    def setUp(self):
        reset_for_tests()
        self.analyzer = _Analyzer()
        install_analyzer_for_tests(lambda settings: self.analyzer)
        self.addCleanup(reset_for_tests)

    def _settings(self, **overrides):
        raw = {
            "enabled": True,
            "backend": "presidio",
            "action": "redact",
            "mode": "enforce",
            "mask_style": "replace",
            "entities": ["PERSON"],
        }
        raw.update(overrides)
        return PiiSettings.from_mapping(raw)

    def test_analyzer_is_cached_and_threshold_applied(self):
        settings = self._settings()
        built = {"n": 0}
        analyzer = self.analyzer

        def factory(settings):
            built["n"] += 1
            return analyzer

        install_analyzer_for_tests(factory)
        first = detect("Ada Lovelace met Bob", settings)
        second = detect("Ada Lovelace met Bob", settings)
        self.assertEqual(built["n"], 1)
        self.assertEqual(analyzer.calls, 2)
        self.assertEqual(analyzer.languages, ["en", "en"])
        self.assertEqual([h.entity for h in first.hits], ["PERSON"])
        self.assertEqual(first.hits[0].value, "Ada Lovelace")
        self.assertEqual(len(second.hits), 1)
        self.assertEqual(first.backend, "presidio")

    def test_entity_filter(self):
        settings = self._settings(entities=["EMAIL_ADDRESS"])
        result = detect("Ada Lovelace", settings)
        self.assertEqual(result.hits, ())
        self.assertEqual(self.analyzer.entities, [["EMAIL_ADDRESS"]])

    def test_redact_mcp_result_masks_and_notes_without_the_name(self):
        from prismor.runtime.pii import PiiNotes
        settings = self._settings()

        class Engine:
            pii = settings

        notes = PiiNotes()
        out, changed = redact_mcp_result(
            {"content": [{"type": "text", "text": "Patient Ada Lovelace was admitted"}]},
            engine=Engine(),
            pii_notes=notes,
        )
        self.assertTrue(changed)
        rendered = out["content"][0]["text"]
        self.assertNotIn("Ada Lovelace", rendered)
        self.assertIn("<PERSON>", rendered)
        self.assertTrue(notes.scanned)
        self.assertEqual(notes.backend, "presidio")
        blob = " ".join(n.value for n in notes)  # in-memory only; the finding must not keep it
        self.assertIn("Ada Lovelace", blob)
        from prismor.runtime.pii import finding_from_hits
        finding = finding_from_hits(notes, index=0, settings=settings, backend=notes.backend)
        self.assertNotIn("Ada Lovelace", str(finding))
        self.assertNotIn("Lovelace", finding["evidence"])

    def test_fallback_when_presidio_fails(self):
        reset_for_tests()
        def _boom(settings):
            raise ImportError("presidio_analyzer")
        install_analyzer_for_tests(_boom)
        settings = PiiSettings.from_mapping({
            "enabled": True,
            "backend": "presidio",
            "entities": ["EMAIL_ADDRESS", "PERSON"],
        })
        with patch("sys.stderr") as err:
            result = detect("write ada.lovelace@nhs.net", settings)
            result2 = detect("write ada.lovelace@nhs.net", settings)
        self.assertEqual(result.backend, "regex")
        self.assertIn("not installed", result.fallback_reason)
        self.assertIn("PERSON", result.unsupported)
        self.assertEqual(result.hits[0].entity, "EMAIL_ADDRESS")
        self.assertEqual(result2.backend, "regex")
        written = "".join(str(c.args[0]) for c in err.write.call_args_list)
        self.assertEqual(written.count("not installed"), 1)
        self.assertNotIn("ada.lovelace@nhs.net", written)


class PiiTransformTests(unittest.TestCase):
    def test_transform_rewrites_tool_input(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(reset_for_tests)
        home = Path(tmp.name) / "home"
        ws = Path(tmp.name) / "ws"
        home.mkdir()
        (ws / ".prismor").mkdir(parents=True)
        (ws / ".prismor" / "policy.yaml").write_text(
            _OVERLAY.format(action="redact", mode="enforce", style="replace")
        )
        with patch.dict(os.environ, {"PRISMOR_HOME": str(home)}):
            out = apply_transform(
                "pii_ner_redact",
                payload={"tool_input": {"command": "echo 578-12-4456"}},
                workspace=ws,
                mode="enforce",
            )
        self.assertIsNotNone(out)
        command = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn("578-12-4456", command)
        self.assertIn("<US_SSN>", command)
        self.assertNotIn("578-12-4456", out["systemMessage"])


class PiiRealPresidioTests(unittest.TestCase):
    def setUp(self):
        reset_for_tests()
        self.addCleanup(reset_for_tests)
        try:
            import presidio_analyzer  # noqa: F401
            import presidio_anonymizer  # noqa: F401
            import spacy
            spacy.load("en_core_web_sm")
        except Exception as exc:
            self.skipTest(f"prismor[pii] extra not available: {exc}")

    def test_presidio_detects_email_and_redacts_with_anonymizer(self):
        settings = PiiSettings.from_mapping({
            "enabled": True,
            "backend": "presidio",
            "action": "redact",
            "mode": "enforce",
            "mask_style": "replace",
            "entities": ["EMAIL_ADDRESS", "PERSON"],
            "score_threshold": 0.4,
        })
        text = "Please email Ada Lovelace at ada.lovelace@nhs.net today."
        first = detect(text, settings)
        second = detect(text, settings)
        entities = {h.entity for h in first.hits}
        self.assertIn("EMAIL_ADDRESS", entities)
        self.assertEqual(first.backend, "presidio")
        self.assertLess(second.latency_ms, first.latency_ms + 50)
        rendered = anonymize(text, first.hits, "replace", prefer_presidio=True)
        self.assertNotIn("ada.lovelace@nhs.net", rendered)
        self.assertIn("<EMAIL_ADDRESS>", rendered)


if __name__ == "__main__":
    unittest.main()
