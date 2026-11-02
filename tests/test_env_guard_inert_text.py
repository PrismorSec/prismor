"""The env guard reads files, not text that merely names one.

From the false-positive catalog: a grep pattern and a heredoc being written
to a file were both treated as reading the workspace dotenv file.
"""
import os

from prismor.runtime.cloaking.env_guard import candidate_paths, local_text

ENV = "." + "env"


def _names(command, cwd="/w"):
    return {os.path.basename(p) for p in candidate_paths(local_text(command), cwd)}


def test_grep_pattern_is_not_a_file():
    assert ENV not in _names(f"grep -rn '\\{ENV}' src/")
    assert ENV not in _names(f"rg -n -g '*.ts' '{ENV}' src")
    assert ENV not in _names(f"git grep -e '{ENV}' -- src")


def test_grep_reading_the_file_is_still_seen():
    assert ENV in _names(f"grep KEY {ENV}")
    assert ENV in _names(f"grep -f patterns.txt {ENV}")


def test_heredoc_written_to_a_file_is_not_a_read():
    assert ENV not in _names(f"cat > notes.md <<'EOF'\nnever cat {ENV}\nEOF")


def test_heredoc_run_by_an_interpreter_is_still_seen():
    assert ENV in _names(f"python3 - <<'EOF'\nprint(open('{ENV}').read())\nEOF")


def test_plain_read_is_seen():
    assert ENV in _names(f"cat {ENV}")
