"""PEP 508 extras and PEP 440 specifiers in pip manifests (issue #391).

A dependency declared with extras must still reach vulnerability and
supply-chain scanning, and its version specifier must survive intact: an
advisory range like ``== 41.0.0rc1`` cannot be matched against a version that
was silently truncated to ``41.0.0``.
"""
from __future__ import annotations

from pathlib import Path

from prismor.runtime.deps import parse_dependencies


def _write(ws: Path, name: str, body: str) -> Path:
    path = ws / name
    path.write_text(body, encoding="utf-8")
    return path


def _by_name(deps: list[dict[str, str]]) -> dict[str, str]:
    return {d["name"]: d["version"] for d in deps}


# --- pyproject.toml ---------------------------------------------------------


def test_pyproject_extras_dependency_is_not_dropped(tmp_path: Path) -> None:
    """A package declared with extras must still be reported."""
    manifest = _write(
        tmp_path,
        "pyproject.toml",
        '[project]\ndependencies = [\n'
        '    "requests[security]>=2.28",\n'
        '    "urllib3[socks,brotli]>=1.26.5",\n'
        ']\n',
    )
    found = _by_name(parse_dependencies(manifest, "pip"))
    assert found == {"requests": ">=2.28", "urllib3": ">=1.26.5"}


def test_pyproject_plain_dependency_still_parses(tmp_path: Path) -> None:
    """The benign lookalike: no extras, unchanged behaviour."""
    manifest = _write(
        tmp_path,
        "pyproject.toml",
        '[project]\ndependencies = [\n    "flask",\n    "cryptography==41.0.0rc1",\n]\n',
    )
    found = _by_name(parse_dependencies(manifest, "pip"))
    assert found == {"flask": "", "cryptography": "==41.0.0rc1"}


# --- requirements.txt ------------------------------------------------------


def test_requirements_extras_keep_their_version(tmp_path: Path) -> None:
    """Extras must not blank out the specifier, or the range check is skipped."""
    manifest = _write(
        tmp_path,
        "requirements.txt",
        "requests[security]>=2.28\nurllib3[socks]>=1.26.5\n",
    )
    found = _by_name(parse_dependencies(manifest, "pip"))
    assert found == {"requests": ">=2.28", "urllib3": ">=1.26.5"}


def test_requirements_pep440_prerelease_and_postrelease_survive(tmp_path: Path) -> None:
    """rc/post tags are part of the version; truncating them corrupts matching."""
    manifest = _write(
        tmp_path,
        "requirements.txt",
        "cryptography==41.0.0rc1\ndjango>=4.2.0.post1\n",
    )
    found = _by_name(parse_dependencies(manifest, "pip"))
    assert found == {"cryptography": "==41.0.0rc1", "django": ">=4.2.0.post1"}


def test_requirements_environment_marker_is_not_part_of_the_version(tmp_path: Path) -> None:
    """A marker after ';' must not leak into the version specifier."""
    manifest = _write(
        tmp_path,
        "requirements.txt",
        "tomli>=1.1.0; python_version < '3.11'\n",
    )
    found = _by_name(parse_dependencies(manifest, "pip"))
    assert found == {"tomli": ">=1.1.0"}


def test_requirements_comments_and_flags_are_still_skipped(tmp_path: Path) -> None:
    """Unchanged behaviour: comment lines and '-r'/'-e' flags are not packages."""
    manifest = _write(
        tmp_path,
        "requirements.txt",
        "# pinned for CI\n-r base.txt\n-e .\n\nflask==3.0.0\n",
    )
    found = _by_name(parse_dependencies(manifest, "pip"))
    assert found == {"flask": "==3.0.0"}


def test_requirements_spaced_operator_keeps_its_version(tmp_path: Path) -> None:
    """pip accepts whitespace around the operator; the version must survive it.

    Without the ``\\s*`` after the operator the capture stops at the space and
    the version becomes a bare ``"=="``, which drops an exact IOC match down to
    a name-only verdict.
    """
    manifest = _write(
        tmp_path,
        "requirements.txt",
        "flask == 2.0\nrequests [security] >= 2.28\nnumpy== 1.26.0\n",
    )
    found = _by_name(parse_dependencies(manifest, "pip"))
    assert found == {
        "flask": "== 2.0",
        "requests": ">= 2.28",
        "numpy": "== 1.26.0",
    }
