"""Windows-found cloak bugs that are testable anywhere: reserved names, BOM /
UTF-16 inputs, huge values, CRLF fidelity, UTF-16 output scrubbing, CLI errors."""
import subprocess
import sys

import pytest

from prismor.runtime.cloaking import runtime, secrets_store as ss


@pytest.fixture()
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path / "v"))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "h"))
    return tmp_path


def cli(vault, *args, stdin=""):
    import os
    env = {**os.environ, "PRISMOR_SECRETS_DIR": str(vault / "v"), "PRISMOR_HOME": str(vault / "h")}
    return subprocess.run([sys.executable, "-m", "prismor.runtime.cli", *args], input=stdin,
                          capture_output=True, text=True, env=env, timeout=60)


@pytest.mark.parametrize("name", ["CON", "nul", "Com1", "lpt9"])
def test_reserved_device_names_rejected(vault, name):
    with pytest.raises(ValueError, match="reserved"):
        ss.add_secret(name, "value-12345")


def test_huge_secret_refused_and_never_scrubbed(vault):
    with pytest.raises(ValueError, match="bytes"):
        ss.add_secret("big", "x" * (ss.MAX_SECRET_BYTES + 1))
    assert not runtime.is_scrubbable_secret("Ab1" * 50000)


def test_crlf_value_stored_exactly(vault):
    p = ss.add_secret("K", "line1\r\nline2-secret")
    assert p.read_bytes() == b"line1\r\nline2-secret"
    assert ss.strip_one_newline("abc\r\n") == "abc" and ss.strip_one_newline("abc\n\n") == "abc\n"


@pytest.mark.parametrize("enc", ["utf-8-sig", "utf-16"])
def test_env_file_bom_and_utf16(vault, enc):
    f = vault / ".env"
    f.write_bytes("BOM_KEY=abcdef123456\r\nOTHER=zzzzzzzz9999\r\n".encode(enc))
    assert ss.parse_env_file(f) == {"BOM_KEY": "abcdef123456", "OTHER": "zzzzzzzz9999"}


def test_utf16_output_is_scrubbed():
    secrets = {"TOK": "sk-live-ABCDEF123456"}
    for codec in ("utf-16-le", "utf-16-be", "utf-16"):
        out = runtime.scrub_bytes(("tok=" + secrets["TOK"] + "\n").encode(codec), secrets)
        assert "ABCDEF123456" not in out.replace("\x00", "")
    assert "sk-live" not in runtime.scrub_bytes(b"x sk-live-ABCDEF123456", secrets)


def test_cloak_run_missing_command_is_clean_error(vault):
    r = cli(vault, "cloak", "run", "--", "definitely-not-a-real-binary-xyz")
    assert r.returncode == 127 and "Traceback" not in r.stderr


def test_cloak_remove_traversal_name_is_clean_error(vault):
    r = cli(vault, "cloak", "remove", "../../x")
    assert r.returncode == 1 and "Invalid secret name" in r.stderr and "Traceback" not in r.stderr


def test_cloak_add_warns_on_lossy_pipe_and_reports_bytes(vault):
    r = cli(vault, "cloak", "add", "LOSSY", stdin="pa????ss12345\r\n")
    assert "re-encoded" in r.stderr
    r = cli(vault, "cloak", "add", "CRLF", stdin="abcdefgh1234\r\n")
    assert "(12 bytes)" in r.stdout


def test_is_console_false_for_devnull():
    with open("/dev/null" if sys.platform != "win32" else "NUL") as f:
        assert ss.is_console(f) is False


def test_install_reads_bom_settings(vault, tmp_path):
    from prismor.runtime.cloaking import installer
    s = tmp_path / "s.json"
    s.write_bytes(b"\xef\xbb\xbf{\"a\": 1}")
    assert installer._read_json(s) == {"a": 1}
