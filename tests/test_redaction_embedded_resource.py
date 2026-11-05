"""An embedded MCP resource keeps its text under ``resource.text``, not ``text``.

A filesystem-style server that returns a file as ``type: "resource"`` has no
top-level ``text`` field on the block, so masking only ``content[].text`` hands
the raw credential to the model and the transcript.
"""
import pytest

from prismor.runtime.redaction import redact_mcp_result

SECRET = "sk_live_" + "0123456789abcdefXYZ"
CLOAKED = "tok_9fQ2xLmZ4pR7vB1c"


def _resource(text):
    return {"type": "resource",
            "resource": {"uri": "file:///workspace/.env",
                         "mimeType": "text/plain", "text": text}}


@pytest.fixture()
def cloak(monkeypatch, tmp_path):
    sdir = tmp_path / "secrets"
    sdir.mkdir()
    (sdir / "deploy_token").write_text(CLOAKED)
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(sdir))


def test_embedded_resource_text_is_redacted():
    block = _resource(f"STRIPE_SECRET_KEY={SECRET}")
    out, changed = redact_mcp_result({"content": [block]}, data_boundary=True)
    assert changed
    assert SECRET not in str(out)
    # Only the text is rewritten; the rest of the block is what the server sent.
    redacted = out["content"][0]
    assert redacted["type"] == "resource"
    assert redacted["resource"]["uri"] == block["resource"]["uri"]
    assert redacted["resource"]["mimeType"] == "text/plain"
    # The server's own result object is not mutated.
    assert SECRET in block["resource"]["text"]


def test_registered_cloak_secret_in_embedded_resource_is_masked(cloak):
    out, changed = redact_mcp_result(
        {"content": [_resource(f"DEPLOY_TOKEN={CLOAKED}")]})
    assert changed
    assert CLOAKED not in str(out)
    assert "@@SECRET:deploy_token@@" in out["content"][0]["resource"]["text"]


def test_text_and_resource_blocks_are_both_redacted():
    result = {"content": [
        {"type": "text", "text": f"key: {SECRET}"},
        _resource(f"key: {SECRET}"),
    ]}
    out, changed = redact_mcp_result(result, data_boundary=True)
    assert changed
    assert SECRET not in str(out)


def test_clean_or_textless_resources_pass_through_untouched():
    result = {"content": [
        _resource("no secrets here"),
        {"type": "resource",
         "resource": {"uri": "file:///workspace/logo.png",
                      "mimeType": "image/png", "blob": "aGVsbG8="}},
        {"type": "resource", "resource": "not a dict"},
    ]}
    out, changed = redact_mcp_result(result, data_boundary=True)
    assert not changed and out is result
