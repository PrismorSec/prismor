"""Windows-hardening helpers: BOM-aware reads, UTF-8 stdin, replace retry."""
from __future__ import annotations

import codecs

import pytest

from prismor.runtime import winutil


@pytest.mark.parametrize("enc", ["utf-8", "utf-8-sig", "utf-16"])
def test_read_text_file_bom_aware(tmp_path, enc):
    f = tmp_path / "x.jsonl"
    f.write_bytes('{"a":"café"}\n'.encode(enc))
    assert winutil.read_text_file(f).strip() == '{"a":"café"}'


def test_read_text_file_missing_is_clear_error(tmp_path):
    with pytest.raises(ValueError, match="file not found"):
        winutil.read_text_file(tmp_path / "nope.json")


def test_decode_bytes_never_raises():
    assert winutil.decode_bytes(b"\xff\xfeA") is not None
    assert winutil.decode_bytes(codecs.BOM_UTF8 + b"hi") == "hi"


def test_replace_retries_on_permission_error(tmp_path, monkeypatch):
    src, dst = tmp_path / "a", tmp_path / "b"
    src.write_text("1")
    real, calls = winutil.os.replace, []

    def flaky(a, b):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError("WinError 32")
        real(a, b)

    monkeypatch.setattr(winutil.os, "replace", flaky)
    winutil.replace_retry(src, dst, delay=0)
    assert dst.read_text() == "1" and len(calls) == 3


def test_analyze_missing_input_is_clean_exit(tmp_path):
    from prismor.runtime import cli
    with pytest.raises(SystemExit) as e:
        cli.read_text(str(tmp_path / "missing.jsonl"))
    assert "not found" in str(e.value)


def test_analyze_utf16_input(tmp_path):
    from prismor.runtime import cli
    f = tmp_path / "e.jsonl"
    f.write_bytes('{"type":"shell"}\n'.encode("utf-16"))
    assert cli.parse_jsonl(cli.read_text(str(f))) == [{"type": "shell"}]


def test_stdin_decoded_as_utf8_not_locale(monkeypatch):
    import io
    import sys
    raw = '{"cmd":"echo café 🚀"}'.encode("utf-8")
    fake = io.TextIOWrapper(io.BytesIO(codecs.BOM_UTF8 + raw), encoding="cp1252")
    monkeypatch.setattr(sys, "stdin", fake)
    assert winutil.read_stdin_text() == '{"cmd":"echo café 🚀"}'


def test_hook_dispatch_stdin_utf8(tmp_path):
    """End to end: UTF-8 bytes piped to hook-dispatch under a cp1252 locale."""
    import os
    import subprocess
    import sys
    code = (
        "import io,sys,json;"
        "sys.stdin=io.TextIOWrapper(sys.stdin.buffer,encoding='cp1252');"
        "from prismor.runtime.winutil import read_stdin_text as r;"
        "print(json.dumps(json.loads(r()),ensure_ascii=True))"
    )
    out = subprocess.run([sys.executable, "-c", code], input='{"c":"café"}'.encode(),
                         capture_output=True, env=dict(os.environ, PYTHONUTF8="0"),
                         cwd=os.path.dirname(os.path.dirname(__file__)))
    assert out.stdout.decode().strip() == '{"c": "caf\\u00e9"}'


def test_quote_path_and_learn_plain_when_piped(monkeypatch):
    from prismor.runtime import cli
    assert cli._quote_path("/tmp/a b/x.json") == "'/tmp/a b/x.json'"
    assert cli._quote_path("/tmp/x.json") == "/tmp/x.json"
    import subprocess, sys, os
    out = subprocess.run([sys.executable, "-c", "from prismor.runtime import learning as l;print(repr(l._BOLD))"],
                         capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
    assert out.stdout.strip() == "''"
