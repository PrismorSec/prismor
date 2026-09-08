from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

try:  # POSIX advisory locks; absent on Windows.
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]


@contextmanager
def _locked(handle) -> Iterator[None]:
    """Hold an exclusive advisory lock on an open file for the block.

    Best effort: on a platform without fcntl, or a filesystem that refuses the
    lock (some network mounts), the write still proceeds unserialized rather
    than failing the caller. Logging an event must never break the tool call it
    is recording.
    """
    if fcntl is None:
        yield
        return
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except OSError:
        yield
        return
    try:
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Exclusive advisory lock for ``path``, keyed on a sibling ``.lock`` file.

    Same best-effort contract as :func:`_locked`: where the lock cannot be
    taken — Windows, which has no ``fcntl``, or a network mount that refuses
    it — the body still runs, just unserialized. Losing serialization on a
    telemetry write is survivable; failing the tool call that triggered it is
    not.

    The telemetry chain, audit trail and heartbeat all serialize through this.
    They each used to ``import fcntl`` directly inside the lock helper, so on
    Windows every single tool call surfaced ``audit trail error: No module
    named 'fcntl'`` and the record was dropped.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(path.suffix + ".lock")
    with open(lock, "a+", encoding="utf-8") as handle:
        with _locked(handle):
            yield


@contextmanager
def locked_json_update(path: Path) -> Iterator[Dict[str, Any]]:
    """Read-modify-write a small JSON state file atomically, under a lock.

    Yields the decoded dict; whatever the caller leaves in it is written back on
    a clean exit. The read happens *inside* the lock, so a caller's in-memory
    copy can never clobber a concurrent writer's committed change — the classic
    lost update. Subagents make this the common case, not the rare one: every
    hook invocation is a separate process, and Claude runs subagents
    concurrently, so several processes race on one session's state file.

    Two properties matter for security state:

    * **No lost updates.** A dropped tag record silently un-taints a session —
      ``TagLedger.completes`` then sees a clean slate and the forbidden
      combination is never blocked. That is a fail-*open*.
    * **No torn reads.** The write goes to a sibling temp file and lands via
      ``os.replace`` (atomic on POSIX and Windows), so a reader either sees the
      whole previous version or the whole new one — never a half-written file
      that ``json.loads`` rejects. Callers treat a corrupt file as empty state,
      which is also a fail-open, so tearing must be impossible rather than rare.

    The lock is held on a sibling ``.lock`` file rather than on ``path`` itself:
    ``os.replace`` swaps the inode, so a lock taken on the data file would be
    dropped by the very write it is meant to serialize.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with open(lock_path, "a+") as lock_handle:
        with _locked(lock_handle):
            state: Dict[str, Any] = {}
            if path.exists():
                try:
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        state = loaded
                except (json.JSONDecodeError, OSError):
                    state = {}
            yield state
            tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
            try:
                tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
                os.replace(tmp, path)
            except OSError:
                try:
                    tmp.unlink()
                except OSError:
                    pass
                raise


def prismor_home() -> Path:
    """Return Prismor's state directory, honoring $PRISMOR_HOME (default ~/.prismor).

    Single source of truth for the "home" half of state resolution (secrets
    have their own further override, $PRISMOR_SECRETS_DIR). iam.py, canary.py,
    and agents.py all import this instead of hardcoding Path.home() — see
    PrismorSec/prismor#131 for the inconsistency this replaces.
    """
    return Path(os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor")))


# ── Re-cloaking: never persist a raw secret value to the audit store ─────────
#
# A decloak hook substitutes the real secret into a command for execution. The
# PostToolUse event therefore carries the resolved command (and possibly the
# command's stdout/stderr). Storing that verbatim would leak the secret into the
# session log and SQLite store — defeating the whole cloaking guarantee. We scrub
# every registered secret value back to its @@SECRET:name@@ placeholder at the
# single persistence choke point, so no event can ever land a raw value on disk.

def _secrets_dir() -> Path:
    env = os.environ.get("PRISMOR_SECRETS_DIR")
    if env:
        return Path(env)
    return prismor_home() / "secrets"


def _load_secret_map() -> List[tuple[str, str]]:
    """Return [(real_value, placeholder), …], longest value first so that a
    value which is a substring of another is replaced after the longer one.
    Only values of length >= 8 are considered, to avoid over-eager replacement
    of short, low-entropy strings."""
    sdir = _secrets_dir()
    if not sdir.is_dir():
        return []
    pairs: List[tuple[str, str]] = []
    for f in sdir.iterdir():
        if not f.is_file():
            continue
        try:
            value = f.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            continue
        if len(value) >= 8:
            pairs.append((value, f"@@SECRET:{f.name}@@"))
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs


def _recloak_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Replace any raw secret value with its placeholder across all string
    fields of an event (recursively). Returns a scrubbed copy; the input is not
    mutated. A no-op when the vault is empty or no value appears in the event."""
    secret_map = _load_secret_map()
    if not secret_map:
        return event

    def scrub(obj: Any) -> Any:
        if isinstance(obj, str):
            s = obj
            for real, placeholder in secret_map:
                if real in s:
                    s = s.replace(real, placeholder)
            return s
        if isinstance(obj, list):
            return [scrub(x) for x in obj]
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        return obj

    return scrub(event)


# ── Global workspace registry ────────────────────────────────────────────────

def _registry_path() -> Path:
    return prismor_home() / "workspaces.json"


def register_workspace(workspace: Path) -> None:
    """Add a workspace to the global registry (idempotent)."""
    ws = str(workspace.resolve())
    reg = _registry_path()
    paths: List[str] = []
    if reg.exists():
        try:
            paths = json.loads(reg.read_text(encoding="utf-8"))
        except Exception:
            paths = []
    if ws not in paths:
        paths.append(ws)
        reg.parent.mkdir(parents=True, exist_ok=True)
        reg.write_text(json.dumps(paths, indent=2), encoding="utf-8")


def list_registered_workspaces() -> List[Path]:
    """Return registered workspace paths that still exist and have Prismor state.

    Runtime state is canonicalized under ``~/.prismor``. Older installs wrote
    per-workspace DBs under ``~/.prismor/workspaces/<id>/`` or inside the
    project; those workspaces are still returned so dashboard reads can merge
    them into the global runtime DB.
    """
    reg = _registry_path()
    if not reg.exists():
        return []
    try:
        paths = json.loads(reg.read_text(encoding="utf-8"))
    except Exception:
        return []
    result = []
    for p in paths:
        ws = Path(p)
        if not ws.exists():
            continue
        # Current layout: one shared DB under $PRISMOR_HOME — every registered
        # workspace that still exists counts. Older layouts kept a DB per
        # workspace; those still qualify so their history can be merged in.
        shared_db = prismor_home() / "prismor.db"
        central_db = _workspace_state_dir(ws) / "prismor.db"
        legacy_db = ws / ".prismor" / "prismor.db"
        legacy_warden_db = ws / _LEGACY_DATA_DIR / _LEGACY_DB_NAME
        if shared_db.exists() or central_db.exists() or legacy_db.exists() or legacy_warden_db.exists():
            result.append(ws)
    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def infer_default_workspace(cwd: Path) -> Path:
    resolved = cwd.resolve()
    # Standing inside the runtime package checkout (prismor/runtime): the
    # workspace is the repo root two levels up.
    if resolved.name == "runtime" and resolved.parent.name == "prismor":
        return resolved.parent.parent
    return resolved


_LEGACY_DATA_DIR = ".prismor-warden"
_LEGACY_DB_NAME = "warden.db"


def _workspace_state_id(workspace: Path) -> str:
    resolved = str(workspace.resolve())
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", workspace.name).strip("-._") or "workspace"
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:12]
    return f"{name}-{digest}"


def _workspace_state_dir(workspace: Path) -> Path:
    return prismor_home() / "workspaces" / _workspace_state_id(workspace)


def _copy_path_once(src: Path, dst: Path) -> None:
    if not src.exists() or dst.exists():
        return
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    except OSError:
        pass


def _copy_tree_contents_once(src: Path, dst: Path) -> None:
    if not src.is_dir():
        return
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            _copy_path_once(item, target)


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _insert_missing_rows_sql(table: str, cols: List[str]) -> str:
    quoted_cols = ", ".join(_quote_ident(c) for c in cols)
    source_cols = ", ".join(f"s.{_quote_ident(c)}" for c in cols)
    row_match = " AND ".join(f"d.{_quote_ident(c)} IS s.{_quote_ident(c)}" for c in cols)
    return (
        f"INSERT INTO {_quote_ident(table)} ({quoted_cols}) "
        f"SELECT {source_cols} FROM src.{_quote_ident(table)} AS s "
        f"WHERE NOT EXISTS ("
        f"SELECT 1 FROM main.{_quote_ident(table)} AS d WHERE {row_match}"
        f")"
    )


def _merge_sqlite_db_once(src_db: Path, dst_db: Path) -> None:
    if not src_db.exists() or src_db.resolve() == dst_db.resolve():
        return
    try:
        dst_db.parent.mkdir(parents=True, exist_ok=True)
        if not dst_db.exists():
            shutil.copy2(src_db, dst_db)
            return
        dst = sqlite3.connect(dst_db)
        try:
            _migrate_schema(dst)
            dst.execute("ATTACH DATABASE ? AS src", (str(src_db),))
            for table in ("sessions", "events", "findings", "supply_chain_events"):
                dst_cols = [row[1] for row in dst.execute(f"PRAGMA table_info({table})")]
                src_cols = [row[1] for row in dst.execute(f"PRAGMA src.table_info({table})")]
                cols = [c for c in dst_cols if c in src_cols and c != "id"]
                if not cols:
                    continue
                quoted = ", ".join(_quote_ident(c) for c in cols)
                source = ", ".join(f"s.{_quote_ident(c)}" for c in cols)
                if table in {"sessions", "findings"}:
                    dst.execute(
                        f"INSERT OR REPLACE INTO {_quote_ident(table)} ({quoted}) "
                        f"SELECT {source} FROM src.{_quote_ident(table)} AS s"
                    )
                else:
                    dst.execute(_insert_missing_rows_sql(table, cols))
            dst.commit()
            try:
                dst.execute("DETACH DATABASE src")
            except sqlite3.Error:
                pass
        finally:
            dst.close()
    except Exception:
        pass


def _migrate_workspace_runtime_state(workspace: Path, data_dir: Path) -> None:
    """Merge legacy runtime state into Prismor home without moving project config."""
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            data_dir.chmod(0o700)
        except OSError:
            pass
    except OSError:
        return

    project_dir = workspace / ".prismor"
    legacy_dir = workspace / _LEGACY_DATA_DIR
    previous_central_dir = _workspace_state_dir(workspace)
    source_paths = [
        project_dir / "prismor.db",
        legacy_dir / _LEGACY_DB_NAME,
        previous_central_dir / "prismor.db",
        project_dir / "sessions",
        legacy_dir / "sessions",
        previous_central_dir / "sessions",
        project_dir / "scoped",
        legacy_dir / "scoped",
        previous_central_dir / "scoped",
        project_dir / "taint",
        legacy_dir / "taint",
        previous_central_dir / "taint",
    ]

    marker_dir = data_dir / "migrations" / "runtime-state"
    marker = marker_dir / f"{_workspace_state_id(workspace)}.json"
    source_mtimes: Dict[str, float] = {}
    for source_path in source_paths:
        try:
            if source_path.exists():
                source_mtimes[str(source_path)] = source_path.stat().st_mtime
        except OSError:
            pass

    if marker.exists():
        try:
            marker_data = json.loads(marker.read_text(encoding="utf-8"))
            verified_mtimes = marker_data.get("source_mtimes") or {}
            if marker_data.get("verified") and all(
                verified_mtimes.get(path, 0) >= mtime
                for path, mtime in source_mtimes.items()
            ):
                return
        except (OSError, ValueError, TypeError):
            pass

    for src_db in (
        project_dir / "prismor.db",
        legacy_dir / _LEGACY_DB_NAME,
        previous_central_dir / "prismor.db",
    ):
        _merge_sqlite_db_once(src_db, data_dir / "prismor.db")

    for child in ("sessions", "scoped", "taint"):
        _copy_tree_contents_once(project_dir / child, data_dir / child)
        _copy_tree_contents_once(legacy_dir / child, data_dir / child)
        _copy_tree_contents_once(previous_central_dir / child, data_dir / child)

    try:
        marker_dir.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            json.dumps(
                {
                    "workspace": str(workspace.resolve()),
                    "verified": True,
                    "source_mtimes": source_mtimes,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def get_data_dir(workspace: Path) -> Path:
    data_dir = prismor_home()
    _migrate_workspace_runtime_state(workspace, data_dir)
    return data_dir


def get_db_path(workspace: Path) -> Path:
    data_dir = get_data_dir(workspace)
    new = data_dir / "prismor.db"
    legacy = data_dir / _LEGACY_DB_NAME
    if legacy.exists() and not new.exists():
        # Rename the sqlite db and its WAL/SHM siblings together. Done before the
        # connection is opened (get_db_path is the pre-open resolver), so the
        # files are not held by this process.
        try:
            for suffix in ("", "-wal", "-shm"):
                sib = data_dir / f"{_LEGACY_DB_NAME}{suffix}"
                if sib.exists():
                    sib.rename(data_dir / f"prismor.db{suffix}")
        except OSError:
            return legacy  # fall back to the legacy filename if the rename fails
    return new


def get_sessions_dir(workspace: Path) -> Path:
    return get_data_dir(workspace) / "sessions"




def ensure_data_dirs(workspace: Path) -> None:
    get_sessions_dir(workspace).mkdir(parents=True, exist_ok=True)


def session_log_path(workspace: Path, session_id: str) -> Path:
    safe = "".join(character if character.isalnum() or character in "._-" else "_" for character in session_id)
    return get_sessions_dir(workspace) / f"{safe}.jsonl"


def append_session_event(workspace: Path, session_id: str, event: Dict[str, Any]) -> Path:
    ensure_data_dirs(workspace)
    event = _recloak_event(event)
    log_path = session_log_path(workspace, session_id)
    # One record = one write, under an exclusive lock.
    #
    # Several hook processes can fire for the same event (a hook registered in
    # both user and project settings, parallel agents sharing a session id) and
    # all append here at once. Writing the JSON and the "\n" as two calls let a
    # second writer slip in between them, welding two records onto one line
    # ({"a":1}{"b":2}) and corrupting the log for every later reader. Records
    # routinely exceed the pipe-buffer size below which O_APPEND writes are
    # atomic, so the payload alone can also tear. Build the line first, then
    # take an advisory lock so cooperating writers serialize.
    payload = json.dumps(event) + "\n"
    with log_path.open("a", encoding="utf-8") as handle:
        with _locked(handle):
            handle.write(payload)
            handle.flush()
    return log_path


def _decode_welded_line(line: str) -> List[Dict[str, Any]]:
    """Split a line holding several concatenated JSON objects.

    Recovers logs written before appends were locked, where interleaved writes
    produced `{"a":1}{"b":2}` on one line. Junk between objects is skipped
    rather than raising: a torn record must not cost us the whole session.
    """
    decoder = json.JSONDecoder()
    events: List[Dict[str, Any]] = []
    idx, end = 0, len(line)
    while idx < end:
        try:
            obj, idx = decoder.raw_decode(line, idx)
        except json.JSONDecodeError:
            nxt = line.find("{", idx + 1)
            if nxt == -1:
                break
            idx = nxt
            continue
        if isinstance(obj, dict):
            events.append(obj)
        while idx < end and line[idx] in " \t\r\n":
            idx += 1
    return events


def read_session_events(workspace: Path, session_id: str) -> List[Dict[str, Any]]:
    log_path = session_log_path(workspace, session_id)
    with log_path.open("r", encoding="utf-8") as handle:
        raw = handle.read()
    events: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            # A pre-existing welded or truncated line. Salvage what parses:
            # this runs inside the hook path, so raising here would fail the
            # tool call and leave the agent unguarded for the rest of the
            # session.
            events.extend(_decode_welded_line(line))
    return events


# Expected column set per managed table. NOT NULL is intentionally omitted —
# SQLite can't ADD COLUMN NOT NULL without a default, and fresh DBs already get
# the constraint via CREATE TABLE.
_EXPECTED_COLUMNS: Dict[str, List[tuple]] = {
    "sessions": [
        ("session_id", "TEXT"), ("agent", "TEXT"), ("agent_name", "TEXT"),
        ("source", "TEXT"), ("workspace_path", "TEXT"), ("repo_url", "TEXT"),
        ("started_at", "TEXT"), ("updated_at", "TEXT"),
        ("risk_score", "INTEGER"), ("findings_count", "INTEGER"),
        ("summary_json", "TEXT"),
    ],
    "events": [
        ("session_id", "TEXT"), ("ts", "TEXT"), ("type", "TEXT"),
        ("agent_event", "TEXT"), ("command_text", "TEXT"),
        ("path_text", "TEXT"), ("url_text", "TEXT"),
        ("content_text", "TEXT"), ("raw_json", "TEXT"),
    ],
    "findings": [
        ("session_id", "TEXT"), ("event_index", "INTEGER"),
        ("severity", "TEXT"), ("category", "TEXT"), ("title", "TEXT"),
        ("evidence", "TEXT"), ("enrichment_json", "TEXT"),
    ],
    "supply_chain_events": [
        ("ts", "TEXT"), ("workspace_path", "TEXT"), ("ecosystem", "TEXT"),
        ("package_name", "TEXT"), ("package_version", "TEXT"),
        ("install_cmd", "TEXT"), ("verdict", "TEXT"), ("score", "INTEGER"),
        ("signals_json", "TEXT"), ("ioc_id", "TEXT"),
        ("recommended_version", "TEXT"), ("session_id", "TEXT"),
    ],
}


def _migrate_schema(connection) -> None:
    """Add any missing columns to managed tables. Idempotent."""
    for table, cols in _EXPECTED_COLUMNS.items():
        try:
            existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        except sqlite3.OperationalError:
            continue  # table doesn't exist yet; CREATE TABLE will handle it
        if not existing:
            continue
        for name, sqltype in cols:
            if name in existing:
                continue
            try:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}")
            except sqlite3.OperationalError:
                pass


def _dedupe_runtime_events_once(connection: sqlite3.Connection, db_path: Path) -> None:
    """Remove duplicate event rows left by older workspace-state migrations."""
    marker = db_path.parent / "migrations" / "runtime-state" / "dedupe-events-v1.json"
    if marker.exists():
        return
    try:
        connection.execute(
            """
            DELETE FROM events
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM events
                GROUP BY session_id, ts, type, agent_event, command_text,
                         path_text, url_text, content_text, raw_json
            )
            """
        )
        connection.execute(
            """
            DELETE FROM supply_chain_events
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM supply_chain_events
                GROUP BY ts, workspace_path, ecosystem, package_name,
                         package_version, install_cmd, verdict, score,
                         signals_json, ioc_id, recommended_version, session_id
            )
            """
        )
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({"version": 1}, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


def initialize_database(workspace: Path) -> Path:
    ensure_data_dirs(workspace)
    db_path = get_db_path(workspace)
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent TEXT,
                agent_name TEXT,
                source TEXT,
                workspace_path TEXT,
                repo_url TEXT,
                started_at TEXT,
                updated_at TEXT,
                risk_score INTEGER,
                findings_count INTEGER,
                summary_json TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ts TEXT,
                type TEXT,
                agent_event TEXT,
                command_text TEXT,
                path_text TEXT,
                url_text TEXT,
                content_text TEXT,
                raw_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                event_index INTEGER,
                severity TEXT,
                category TEXT,
                title TEXT,
                evidence TEXT,
                enrichment_json TEXT
            );
            CREATE TABLE IF NOT EXISTS supply_chain_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                workspace_path TEXT,
                ecosystem TEXT,
                package_name TEXT,
                package_version TEXT,
                install_cmd TEXT,
                verdict TEXT,
                score INTEGER,
                signals_json TEXT,
                ioc_id TEXT,
                recommended_version TEXT,
                session_id TEXT
            );
            CREATE TABLE IF NOT EXISTS token_usage (
                message_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                workspace_path TEXT,
                ts TEXT,
                model TEXT,
                input_tokens INTEGER,
                output_tokens INTEGER,
                cache_read_tokens INTEGER,
                cache_creation_tokens INTEGER
            );
            CREATE TABLE IF NOT EXISTS tool_output_size (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                workspace_path TEXT,
                ts TEXT,
                agent TEXT,
                tool_name TEXT,
                label TEXT,
                size_chars INTEGER,
                approx_tokens INTEGER
            );
            """
        )
        # Migrate before creating indexes — old DBs may be missing columns the
        # indexes reference (e.g. supply_chain_events.session_id).
        _migrate_schema(connection)
        _dedupe_runtime_events_once(connection, db_path)
        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_events_session_id_id ON events(session_id, id);
            CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_findings_session_event ON findings(session_id, event_index);
            CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sc_ts ON supply_chain_events(ts);
            CREATE INDEX IF NOT EXISTS idx_sc_verdict ON supply_chain_events(verdict);
            CREATE INDEX IF NOT EXISTS idx_sc_session ON supply_chain_events(session_id);
            CREATE INDEX IF NOT EXISTS idx_token_usage_ts ON token_usage(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_token_usage_workspace ON token_usage(workspace_path);
            CREATE INDEX IF NOT EXISTS idx_tool_output_size_ts ON tool_output_size(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_tool_output_size_workspace ON tool_output_size(workspace_path);
            """
        )
        from prismor.runtime.learning import initialize_learning_tables
        initialize_learning_tables(connection)

        connection.commit()
    finally:
        connection.close()
    return db_path


def save_session_snapshot(
    *,
    workspace: Path,
    session_id: str,
    agent: str,
    source: str,
    repo_url: Optional[str],
    events: List[Dict[str, Any]],
    analysis: Dict[str, Any],
    agent_name: str = "",
) -> Path:
    db_path = initialize_database(workspace)
    # Defense in depth: ensure no raw secret value reaches the SQLite store,
    # even if a caller passes events that did not pass through append_session_event.
    events = [_recloak_event(e) for e in events]
    timestamps = sorted(event.get("ts") for event in events if event.get("ts"))
    started_at = timestamps[0] if timestamps else None
    updated_at = timestamps[-1] if timestamps else None

    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, agent, agent_name, source, workspace_path, repo_url,
                started_at, updated_at, risk_score, findings_count, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                agent,
                agent_name or agent,
                source,
                str(workspace),
                repo_url,
                started_at,
                updated_at,
                analysis["summary"]["riskScore"],
                analysis["summary"]["totalFindings"],
                json.dumps(analysis["summary"]),
            ),
        )
        cursor.execute("DELETE FROM events WHERE session_id = ?", (session_id,))
        # Re-derive analysis findings, but KEEP runtime findings (scoped-agent,
        # IAM, kill-switch, org denies — persisted by persist_runtime_findings
        # with source=runtime). They are per-event enforcement decisions, not
        # something whole-session re-analysis can reproduce; wiping them here
        # made every block vanish from `prismor status` on the next tool call.
        cursor.execute(
            "DELETE FROM findings WHERE session_id = ? "
            "AND (enrichment_json IS NULL OR enrichment_json NOT LIKE '%\"source\": \"runtime\"%')",
            (session_id,),
        )
        runtime_row = cursor.execute(
            "SELECT COUNT(*), MAX(CASE lower(severity) WHEN 'critical' THEN 90 WHEN 'high' THEN 70 "
            "WHEN 'medium' THEN 45 WHEN 'low' THEN 15 ELSE 0 END) FROM findings WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        runtime_count = int((runtime_row or [0])[0] or 0)
        runtime_risk = int((runtime_row or [0, 0])[1] or 0)
        if runtime_count:
            summary = dict(analysis["summary"])
            summary["totalFindings"] = int(summary.get("totalFindings") or 0) + runtime_count
            summary["riskScore"] = max(int(summary.get("riskScore") or 0), runtime_risk)
            cursor.execute(
                "UPDATE sessions SET findings_count = ?, risk_score = ?, summary_json = ? WHERE session_id = ?",
                (summary["totalFindings"], summary["riskScore"], json.dumps(summary), session_id),
            )

        cursor.executemany(
            """
            INSERT INTO events (
                session_id, ts, type, agent_event, command_text, path_text, url_text, content_text, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    session_id,
                    event.get("ts"),
                    event.get("type"),
                    event.get("agent_event"),
                    event.get("command"),
                    event.get("path"),
                    event.get("url"),
                    _truncate(
                        event.get("content")
                        or event.get("response")
                        or event.get("prompt")
                        or ""
                    ),
                    json.dumps(event),
                )
                for event in events
            ],
        )

        # OR IGNORE, not a bare INSERT (issue #345). finding_id is derived
        # ("<session>:<rule>-<eventIndex>"), not random, and persist_runtime_findings
        # stores the very same id for a finding it has already enforced on. The
        # DELETE above spares those runtime rows on purpose, so re-analysing a
        # session re-derives ids that are still present -- a UNIQUE violation.
        # Being an executemany, that aborted the WHOLE batch, so one duplicate
        # silently dropped every other finding with it, surfacing only as
        # "[prismor] analysis error: UNIQUE constraint failed: findings.finding_id".
        #
        # IGNORE rather than REPLACE: the surviving row is the runtime one, and
        # replacing it would overwrite its `source: runtime` enrichment, putting
        # it back in scope for the next snapshot's DELETE -- reintroducing the
        # vanishing-blocks bug that DELETE's carve-out exists to prevent.
        cursor.executemany(
            """
            INSERT OR IGNORE INTO findings (
                finding_id, session_id, event_index, severity, category, title, evidence, enrichment_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    finding["id"],
                    session_id,
                    finding.get("eventIndex"),
                    finding.get("severity"),
                    finding.get("category"),
                    finding.get("title"),
                    _truncate(finding.get("evidence", "")),
                    json.dumps(
                        {
                            "feedMatches": analysis.get("feedMatches", []),
                        }
                    ),
                )
                for finding in analysis["findings"]
            ],
        )
        connection.commit()
    finally:
        connection.close()
    return db_path


def persist_runtime_findings(
    workspace: Path,
    session_id: str,
    findings: List[Dict[str, Any]],
    event_index: int,
) -> None:
    """Persist post-analysis enforcement findings for the current event.

    ``save_session_snapshot`` stores findings produced by whole-session
    analysis. Real-time enforcement layers such as scoped-agent, IAM, and
    kill-switch rules are added later in the evaluation pipeline, so they need a
    lightweight upsert here. This keeps blocked hook decisions visible in the
    dashboard event feed and session drawer.
    """
    if not findings:
        return
    db_path = initialize_database(workspace)
    connection = sqlite3.connect(db_path)
    try:
        cursor = connection.cursor()
        rows = []
        for i, finding in enumerate(findings):
            idx = finding.get("eventIndex")
            if idx is None:
                idx = event_index
            fid = str(finding.get("id") or finding.get("finding_id") or f"{session_id}:runtime-{idx}-{i}")
            for singleton in ("scoped-agent", "codex-cloak-placeholder", "codex-cloak-read-guard"):
                if fid == f"{session_id}:{singleton}":
                    fid = f"{session_id}:{singleton}-{idx}"
                    break
            rows.append((
                fid,
                session_id,
                idx,
                finding.get("severity"),
                finding.get("category"),
                finding.get("title"),
                _truncate(finding.get("evidence", "")),
                json.dumps({
                    "ruleId": finding.get("ruleId") or finding.get("rule_id"),
                    "action": finding.get("action"),
                    "mode": finding.get("mode"),
                    "remediation": finding.get("remediation"),
                    "source": "runtime",
                }),
            ))
        cursor.executemany(
            """
            INSERT OR REPLACE INTO findings (
                finding_id, session_id, event_index, severity, category,
                title, evidence, enrichment_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        row = cursor.execute(
            "SELECT COUNT(*) as cnt, MAX(CASE lower(severity) "
            "WHEN 'critical' THEN 90 WHEN 'high' THEN 70 "
            "WHEN 'medium' THEN 45 WHEN 'low' THEN 15 ELSE 0 END) as risk "
            "FROM findings WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        count = int(row[0] or 0)
        risk = int(row[1] or 0)
        summary_raw = cursor.execute(
            "SELECT summary_json FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        summary: Dict[str, Any] = {}
        if summary_raw and summary_raw[0]:
            try:
                summary = json.loads(summary_raw[0])
            except Exception:
                summary = {}
        summary["totalFindings"] = count
        summary["riskScore"] = max(int(summary.get("riskScore") or 0), risk)
        cursor.execute(
            """
            UPDATE sessions
            SET findings_count = ?, risk_score = ?, summary_json = ?
            WHERE session_id = ?
            """,
            (count, summary["riskScore"], json.dumps(summary), session_id),
        )
        connection.commit()
    finally:
        connection.close()


def list_sessions(workspace: Path, limit: int = 20, *, all_workspaces: bool = False) -> List[Dict[str, Any]]:
    """Sessions for ``workspace`` (newest first). The runtime DB is shared by
    every workspace on the machine, so this filters on ``workspace_path``;
    pass ``all_workspaces=True`` for the machine-wide view (`sessions --global`,
    `status --all`). Rows with no recorded workspace are always included."""
    db_path = initialize_database(workspace)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        if all_workspaces:
            rows = connection.execute(
                """
                SELECT session_id, agent, source, workspace_path, repo_url, started_at, updated_at, risk_score, findings_count, summary_json
                FROM sessions
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            try:
                ws_key = str(workspace.resolve())
            except OSError:
                ws_key = str(workspace)
            rows = connection.execute(
                """
                SELECT session_id, agent, source, workspace_path, repo_url, started_at, updated_at, risk_score, findings_count, summary_json
                FROM sessions
                WHERE workspace_path = ? OR workspace_path = ? OR workspace_path IS NULL OR workspace_path = ''
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (ws_key, str(workspace), limit),
            ).fetchall()
    finally:
        connection.close()
    return [_session_from_row(row) for row in rows]


def get_session(workspace: Path, session_id: str) -> Optional[Dict[str, Any]]:
    db_path = initialize_database(workspace)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        session_row = connection.execute(
            """
            SELECT session_id, agent, source, workspace_path, repo_url, started_at, updated_at, risk_score, findings_count, summary_json
            FROM sessions
            WHERE session_id = ?
            LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        if session_row is None:
            return None

        event_rows = connection.execute(
            """
            SELECT ts, type, agent_event, command_text, path_text, url_text, content_text, raw_json
            FROM events
            WHERE session_id = ?
            ORDER BY id ASC
            """,
            (session_id,),
        ).fetchall()

        finding_rows = connection.execute(
            """
            SELECT finding_id, event_index, severity, category, title, evidence, enrichment_json
            FROM findings
            WHERE session_id = ?
            ORDER BY
              CASE severity
                WHEN 'CRITICAL' THEN 5
                WHEN 'HIGH' THEN 4
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 2
                ELSE 1
              END DESC,
              event_index ASC
            """,
            (session_id,),
        ).fetchall()
    finally:
        connection.close()

    session = _session_from_row(session_row)
    session["events"] = [
        {
            "ts": row["ts"],
            "type": row["type"],
            "agentEvent": row["agent_event"],
            "command": row["command_text"],
            "path": row["path_text"],
            "url": row["url_text"],
            "content": row["content_text"],
            "raw": json.loads(row["raw_json"]),
        }
        for row in event_rows
    ]
    session["findings"] = [
        {
            "id": row["finding_id"],
            "eventIndex": row["event_index"],
            "severity": row["severity"],
            "category": row["category"],
            "title": row["title"],
            "evidence": row["evidence"],
            "enrichment": json.loads(row["enrichment_json"]) if row["enrichment_json"] else None,
        }
        for row in finding_rows
    ]
    return session


def _session_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "sessionId": row["session_id"],
        "agent": row["agent"],
        "source": row["source"],
        "workspacePath": row["workspace_path"],
        "repoUrl": row["repo_url"],
        "startedAt": row["started_at"],
        "updatedAt": row["updated_at"],
        "riskScore": row["risk_score"],
        "findingsCount": row["findings_count"],
        "summary": json.loads(row["summary_json"]) if row["summary_json"] else None,
    }


def _truncate(value: str, max_length: int = 4000) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."


# ── Dashboard aggregate stats ─────────────────────────────────────────────────

_CATEGORY_MAP: Dict[str, str] = {
    "prompt_injection":        "prompt_injection",
    "jailbreak":               "jailbreak_attempt",
    "remote_execution":        "tool_call_abuse",
    "privilege_escalation":    "tool_call_abuse",
    "db_modification":         "tool_call_abuse",
    "rce_canary":              "tool_call_abuse",
    "secret_exfiltration":     "secret_exfil",
    "secret_access":           "secret_exfil",
    "skill_risk":              "malicious_mcp",
    "malicious_mcp":           "malicious_mcp",
    "destructive_command":     "dangerous_command",
    "dos_resource_exhaustion": "dangerous_command",
    "persistence":             "dangerous_command",
    "security_bypass":         "dangerous_command",
    "dependency_risk":         "dangerous_command",
}

_DASH_CATEGORIES = [
    "prompt_injection", "jailbreak_attempt", "tool_call_abuse",
    "secret_exfil", "malicious_mcp", "dangerous_command",
]

_TYPE_LABEL: Dict[str, str] = {
    "shell":        "bash",
    "file_read":    "file_read",
    "file_write":   "file_write",
    "network":      "network",
    "prompt":       "prompt",
    "tool_result":  "tool_result",
}


# ── Session trail artefacts ──────────────────────────────────────────────────
#: How much of any one captured string the trail carries. The session view is a
#: reading surface, not the audit trail -- the full record is the event log, and
#: shipping an unbounded stdout to the browser makes the page the slow part.
_ARTIFACT_CHARS = 4000
_ARTIFACT_LIST = 40

#: Event type -> the lane it belongs to in the session tree. Anything unmapped
#: lands in "other" rather than being dropped, so a new event type shows up in
#: the UI the day it is emitted instead of the day someone updates this table.
_EVENT_LANES = {
    "prompt": "prompt",
    "memory": "context",
    "shell": "shell",
    "file_read": "files",
    "file_write": "files",
    "network": "network",
    "tool_result": "tools",
    "mcp_call": "mcp",
}


def _clip(value: Any, limit: int = _ARTIFACT_CHARS) -> str:
    """One captured string, bounded, with the truncation made visible."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [{len(text) - limit} more characters]"


def event_lane(event_type: str, meta: Optional[Dict[str, Any]] = None) -> str:
    """Which lane of the session tree an event belongs to."""
    if (meta or {}).get("subagent_id"):
        # A subagent's work is still shown in its own lane's tree; the caller
        # groups by subagent first, so this only decides the inner lane.
        pass
    return _EVENT_LANES.get(str(event_type or ""), "other")


def event_artifacts(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Everything a session view can show about one event.

    The event log has always held far more than the trail exposed -- the prompt
    text, a command's stdout and stderr, the path written, the instruction
    files read at session start -- and the session view rendered a type name
    and nothing else, so "what did this agent actually do" could only be
    answered by reading JSONL by hand.
    """
    if not isinstance(raw, dict):
        return {}
    meta = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    out: Dict[str, Any] = {}

    for key in ("prompt", "command", "stdout", "stderr", "response", "content", "path", "url"):
        value = raw.get(key)
        if value not in (None, "", [], {}):
            out[key] = _clip(value)

    for key in ("mcp_server", "mcp_tool"):
        if raw.get(key):
            out[key] = str(raw[key])[:200]

    for key in ("model", "provider", "surface", "cwd", "subagent_id", "subagent_type",
                "agent_name", "tool_name"):
        if meta.get(key):
            out[key] = str(meta[key])[:200]

    # SessionStart carries the instruction files that were already in context
    # before the agent did anything -- the "what was here already" half.
    files = meta.get("memory_files")
    if isinstance(files, list) and files:
        out["memory_files"] = [str(f)[:300] for f in files[:_ARTIFACT_LIST]]
    findings = raw.get("integrity_findings")
    if isinstance(findings, list) and findings:
        out["integrity_findings"] = [
            {"title": str(f.get("title") or "")[:200], "severity": str(f.get("severity") or "")}
            for f in findings[:_ARTIFACT_LIST] if isinstance(f, dict)
        ]
    if meta.get("has_invisible_controls"):
        out["has_invisible_controls"] = True
    if meta.get("truncated"):
        out["truncated"] = True
    return out


def _relative_time_store(ts: str) -> str:
    """Return a human-readable relative time string from an ISO timestamp."""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = int((now - dt).total_seconds())
        if diff < 60:
            return f"{diff}s ago"
        if diff < 3600:
            return f"{diff // 60}m ago"
        if diff < 86400:
            return f"{diff // 3600}h ago"
        return f"{diff // 86400}d ago"
    except Exception:
        return ts


def _absolute_time_store(ts: str) -> str:
    """Return a compact absolute UTC timestamp (YYYY-MM-DD HH:MM:SS) for tooltips."""
    if not ts:
        return ""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


def _ts_pair(ts: str) -> Dict[str, str]:
    """Return ``{"rel": "2h ago", "abs": "2026-06-06 14:23:05 UTC"}`` for a ts."""
    return {"rel": _relative_time_store(ts) if ts else "", "abs": _absolute_time_store(ts)}


def _extract_mcp_or_tool(raw_json: str) -> Optional[Dict[str, str]]:
    """Identify whether an event was an MCP server call or a skill/tool call.

    Returns ``None`` for hook-event noise (Pre/PostToolUse without an MCP
    server or a recognised tool name).  Otherwise returns
    ``{"kind": "mcp"|"skill"|"tool", "name": str}``.
    """
    if not raw_json:
        return None
    try:
        raw = json.loads(raw_json)
    except Exception:
        return None
    meta = raw.get("metadata") or {}

    mcp_server = raw.get("mcp_server") or meta.get("mcp_server")
    if mcp_server:
        return {"kind": "mcp", "name": str(mcp_server)}

    tool_name = meta.get("tool_name") or (raw.get("metadata", {}) or {}).get("tool_name") or ""
    if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
        server = tool_name[len("mcp__"):].split("__", 1)[0]
        return {"kind": "mcp", "name": server}
    if tool_name == "Skill":
        # The skill name lives inside the raw payload's tool_input.
        skill_name = ""
        try:
            skill_name = (raw.get("metadata", {}).get("raw", {})
                          .get("tool_input", {}).get("skill", ""))
        except Exception:
            pass
        return {"kind": "skill", "name": skill_name or "Skill"}
    if tool_name in {"Bash", "Read", "Edit", "MultiEdit", "Write",
                     "WebFetch", "WebSearch", "Grep", "Glob", "Task"}:
        return {"kind": "tool", "name": tool_name}
    return None


# Tracks DBs already migrated this process, so the read-paths only pay the
# write-open cost on first touch.
_MIGRATED_PATHS: set = set()


def _connect_ro(db_path: Path):
    """Open a SQLite DB read-only; returns None if unavailable.

    On first touch per process, opens a write connection to apply any pending
    column migrations so stale v1.5.8-era DBs don't crash read queries.
    """
    p = str(db_path)
    if p not in _MIGRATED_PATHS and db_path.exists():
        try:
            wc = sqlite3.connect(db_path)
            try:
                _migrate_schema(wc)
                wc.commit()
            finally:
                wc.close()
        except Exception:
            pass
        _MIGRATED_PATHS.add(p)
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def _state_query_workspaces() -> List[Path]:
    """Return a single logical source for dashboard queries.

    Queries read ``~/.prismor/prismor.db`` exactly once. Migration from older
    per-workspace stores happens at write/startup time, not in request handlers,
    so dashboard reads stay fast and independent of launch directory.
    """
    home = prismor_home()
    if (home / "prismor.db").exists():
        return [home]
    return []


def get_aggregate_stats(hours: int = 24) -> Dict[str, Any]:
    """Query all registered workspace DBs and return dashboard-shaped data.

    Returns empty/zero structures if no workspaces are registered or all DBs
    are unavailable.
    """
    from collections import Counter
    from datetime import datetime, timezone, timedelta

    workspaces = _state_query_workspaces()

    # Accumulators
    active_sessions = 0
    tool_calls_24h = 0
    dangerous_prevented_24h = 0
    tool_calls_prev = 0      # prior 24h window (for delta)
    dangerous_prev = 0
    active_prev = 0

    threats_by_category: Counter = Counter()
    threats_prev_acc = [0]  # boxed so nested scopes can mutate
    agent_blocks: Counter = Counter()
    tool_breakdown: Counter = Counter()
    mcp_acc: Dict[str, Dict[str, Any]] = {}    # real MCP servers
    skill_acc: Dict[str, Dict[str, Any]] = {}  # claude skills

    # keyed by date string → [total, flagged]
    timeseries_acc: Dict[str, List[int]] = {}

    patterns_acc: Dict[str, Dict[str, Any]] = {}  # key = title

    live_events_raw: List[Dict[str, Any]] = []
    top_users_acc: Dict[str, Dict[str, Any]] = {}
    top_mcp_acc: Dict[str, Dict[str, Any]] = {}
    severity_breakdown: Counter = Counter()

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            # ── KPIs ──────────────────────────────────────────────────────
            row = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE updated_at >= datetime('now', ?)",
                (f"-{hours} hours",),
            ).fetchone()
            active_sessions += (row[0] or 0)

            row = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE updated_at >= datetime('now', ?) "
                "AND updated_at < datetime('now', ?)",
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ).fetchone()
            active_prev += (row[0] or 0)

            row = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= datetime('now', ?)",
                (f"-{hours} hours",),
            ).fetchone()
            tool_calls_24h += (row[0] or 0)

            row = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= datetime('now', ?) "
                "AND ts < datetime('now', ?)",
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ).fetchone()
            tool_calls_prev += (row[0] or 0)

            row = conn.execute(
                """
                SELECT COUNT(*) FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                WHERE f.category IN ('destructive_command','dos_resource_exhaustion')
                  AND s.updated_at >= datetime('now', ?)
                """,
                (f"-{hours} hours",),
            ).fetchone()
            dangerous_prevented_24h += (row[0] or 0)

            row = conn.execute(
                """
                SELECT COUNT(*) FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                WHERE f.category IN ('destructive_command','dos_resource_exhaustion')
                  AND s.updated_at >= datetime('now', ?)
                  AND s.updated_at < datetime('now', ?)
                """,
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ).fetchone()
            dangerous_prev += (row[0] or 0)

            # ── Threats by category (24h) ─────────────────────────────────
            # Join findings to their triggering event so we filter on the
            # event's actual timestamp.  For supply-chain findings (which
            # have no event_index), fall back to the session's updated_at.
            for row in conn.execute(
                """
                SELECT f.category, COUNT(*) as cnt
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                WHERE s.updated_at >= datetime('now', ?)
                GROUP BY f.category
                """,
                (f"-{hours} hours",),
            ):
                dash_cat = _CATEGORY_MAP.get(row["category"] or "", "dangerous_command")
                threats_by_category[dash_cat] += row["cnt"]

            # Prior 24h window — for delta calculation.
            for row in conn.execute(
                """
                SELECT COUNT(*) as cnt
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                WHERE s.updated_at >= datetime('now', ?)
                  AND s.updated_at <  datetime('now', ?)
                """,
                (f"-{hours * 2} hours", f"-{hours} hours"),
            ):
                threats_prev_acc[0] += row["cnt"] or 0

            # ── Block rate timeseries (30 days) ───────────────────────────
            for row in conn.execute(
                """
                SELECT date(ts) as day, COUNT(*) as total_events
                FROM events e
                WHERE e.ts >= datetime('now', '-30 days')
                GROUP BY day
                """
            ):
                day = row["day"] or ""
                if day not in timeseries_acc:
                    timeseries_acc[day] = [0, 0]
                timeseries_acc[day][0] += row["total_events"] or 0
            for row in conn.execute(
                """
                SELECT date(s.updated_at) as day, COUNT(*) as flagged_events
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                WHERE s.updated_at >= datetime('now', '-30 days')
                GROUP BY day
                """
            ):
                day = row["day"] or ""
                if day not in timeseries_acc:
                    timeseries_acc[day] = [0, 0]
                timeseries_acc[day][1] += row["flagged_events"] or 0

            # ── Agent blocked commands (24h, per-finding event) ───────────
            # Counts each finding once by joining to its specific event via
            # event_index — older join double-counted across the session.
            for row in conn.execute(
                """
                SELECT s.agent, COUNT(*) as blocked
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                WHERE s.updated_at >= datetime('now', ?)
                GROUP BY s.agent
                """,
                (f"-{hours} hours",),
            ):
                agent = row["agent"] or "unknown"
                agent_blocks[agent] += row["blocked"] or 0

            # ── Tool call breakdown (built-in tools only; MCP/skills below) ──
            # Skip supply_chain events so they don't show up next to Bash/Read.
            for row in conn.execute(
                "SELECT type, COUNT(*) as count FROM events "
                "WHERE type != 'supply_chain' GROUP BY type"
            ):
                label = _TYPE_LABEL.get(row["type"] or "", row["type"] or "other")
                tool_breakdown[label] += row["count"] or 0

            # ── Top patterns (last_seen = finding's specific event) ──────
            # Use event_index to find the finding's event, then read its ts.
            for row in conn.execute(
                """
                SELECT f.title, f.category, f.severity,
                       COUNT(*) as count,
                       MAX(s.updated_at) as last_seen_ts
                FROM findings f
                LEFT JOIN sessions s ON s.session_id = f.session_id
                GROUP BY f.title, f.category, f.severity
                ORDER BY count DESC LIMIT 30
                """
            ):
                title = row["title"] or "Unknown"
                if title not in patterns_acc:
                    patterns_acc[title] = {
                        "pattern": title,
                        "category": _CATEGORY_MAP.get(row["category"] or "", "dangerous_command"),
                        "severity": (row["severity"] or "low").lower(),
                        "count": 0,
                        "lastSeen": "",
                        "lastSeenAbs": "",
                        "lastSeenTs": "",
                    }
                patterns_acc[title]["count"] += row["count"] or 0
                ts = row["last_seen_ts"] or ""
                if ts > patterns_acc[title]["lastSeenTs"]:
                    patterns_acc[title]["lastSeenTs"] = ts
                    patterns_acc[title]["lastSeen"] = _relative_time_store(ts) if ts else ""
                    patterns_acc[title]["lastSeenAbs"] = _absolute_time_store(ts) if ts else ""

            # ── Live events ───────────────────────────────────────────────
            for row in conn.execute(
                """
                SELECT e.ts, s.agent, e.type as action_type,
                       e.command_text, e.path_text, e.url_text,
                       f.severity,
                       CASE WHEN f.finding_id IS NOT NULL THEN 'blocked' ELSE 'allowed' END as verdict
                FROM events e
                JOIN sessions s ON s.session_id = e.session_id
                LEFT JOIN findings f ON f.session_id = e.session_id
                                    AND f.event_index = (
                                      SELECT COUNT(*) FROM events e2
                                      WHERE e2.session_id = e.session_id
                                        AND e2.id < e.id
                                    )
                WHERE e.ts >= datetime('now', '-24 hours')
                ORDER BY e.ts DESC LIMIT 100
                """
            ):
                action_parts = []
                if row["action_type"]:
                    action_parts.append(row["action_type"])
                detail = row["command_text"] or row["path_text"] or row["url_text"] or ""
                if detail:
                    action_parts.append(detail[:60])
                ts_raw = row["ts"] or ""
                live_events_raw.append({
                    "ts": _relative_time_store(ts_raw) or "—",
                    "tsAbs": _absolute_time_store(ts_raw),
                    "agent": row["agent"] or "unknown",
                    "action": ": ".join(action_parts) if action_parts else "event",
                    "verdict": row["verdict"] or "allowed",
                    "severity": (row["severity"] or "low").lower(),
                })

            # ── Top sessions by blocks (full ID, agent, source) ──────────
            for row in conn.execute(
                """
                SELECT f.session_id as sid, s.agent, s.source,
                       COUNT(f.finding_id) as blocked,
                       MAX(s.updated_at) as last_seen_ts
                FROM findings f
                LEFT JOIN sessions s ON s.session_id = f.session_id
                GROUP BY f.session_id
                ORDER BY blocked DESC LIMIT 10
                """
            ):
                sid = row["sid"] or "unknown"
                if sid not in top_users_acc:
                    top_users_acc[sid] = {
                        "sessionId": sid,
                        "agent": row["agent"] or "unknown",
                        "source": row["source"] or "agent",
                        "blocked": 0,
                        "lastSeen": "", "lastSeenAbs": "", "lastSeenTs": "",
                    }
                top_users_acc[sid]["blocked"] += row["blocked"] or 0
                ts = row["last_seen_ts"] or ""
                if ts > top_users_acc[sid]["lastSeenTs"]:
                    top_users_acc[sid]["lastSeenTs"] = ts
                    top_users_acc[sid]["lastSeen"] = _relative_time_store(ts) if ts else ""
                    top_users_acc[sid]["lastSeenAbs"] = _absolute_time_store(ts) if ts else ""

            # ── Top MCP servers + skills (parse raw_json — hook events
            #    like Pre/PostToolUse are filtered out so the chart shows
            #    real server / skill names instead of hook noise) ────────
            for row in conn.execute(
                """
                SELECT e.raw_json, s.agent, f.finding_id IS NOT NULL as blocked
                FROM events e
                JOIN sessions s ON s.session_id = e.session_id
                LEFT JOIN findings f ON f.session_id = e.session_id
                                    AND f.event_index = (
                                      SELECT COUNT(*) FROM events e2
                                      WHERE e2.session_id = e.session_id
                                        AND e2.id < e.id
                                    )
                WHERE e.type != 'supply_chain'
                  AND e.ts >= datetime('now', ?)
                LIMIT 5000
                """,
                (f"-{hours} hours",),
            ):
                info = _extract_mcp_or_tool(row["raw_json"] or "")
                if info is None or info["kind"] == "tool":
                    continue
                acc = mcp_acc if info["kind"] == "mcp" else skill_acc
                key = info["name"]
                if key not in acc:
                    acc[key] = {"name": key, "type": info["kind"], "calls": 0, "blocked": 0}
                acc[key]["calls"] += 1
                if row["blocked"]:
                    acc[key]["blocked"] += 1

            # ── Severity breakdown (24h, gated on the finding's event ts) ─
            for row in conn.execute(
                """
                SELECT f.severity, COUNT(*) as cnt
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                WHERE s.updated_at >= datetime('now', ?)
                GROUP BY f.severity
                """,
                (f"-{hours} hours",),
            ):
                sev = (row["severity"] or "low").lower()
                severity_breakdown[sev] += row["cnt"]

        except Exception:
            pass
        finally:
            conn.close()

    # ── Deltas ────────────────────────────────────────────────────────────────
    def _pct_delta(current: int, prior: int) -> float:
        if prior == 0:
            return 0.0
        return round((current - prior) / prior * 100, 1)

    # ── Block rate timeseries — fill 30-day window ────────────────────────────
    today = datetime.now(timezone.utc).date()
    timeseries: List[Dict[str, Any]] = []
    for i in range(29, -1, -1):
        day_date = today - timedelta(days=i)
        day_str = day_date.isoformat()
        total, flagged = timeseries_acc.get(day_str, [0, 0])
        timeseries.append({
            "date": day_str,
            "intercepted": flagged,
            "passed": max(0, total - flagged),
        })

    # ── Assemble threatsByCategory with all 6 keys always present ────────────
    threats_out = {cat: threats_by_category.get(cat, 0) for cat in _DASH_CATEGORIES}

    # ── Sort and trim ─────────────────────────────────────────────────────────
    top_patterns = sorted(patterns_acc.values(), key=lambda x: x["count"], reverse=True)[:20]
    for p in top_patterns:
        p.pop("lastSeenTs", None)

    top_users = sorted(top_users_acc.values(), key=lambda x: x["blocked"], reverse=True)[:10]
    for u in top_users:
        u.pop("lastSeenTs", None)

    # MCP + skills merged for the chart — MCP first (typically higher signal),
    # then skills, capped at 15 entries.
    combined = (
        sorted(mcp_acc.values(),   key=lambda x: x["calls"], reverse=True) +
        sorted(skill_acc.values(), key=lambda x: x["calls"], reverse=True)
    )
    top_mcp_and_skills = combined[:15]

    # Deduplicate live events (same ts+agent+action), keep 50
    seen = set()
    live_events_deduped = []
    for ev in live_events_raw:
        key = (ev["ts"], ev["agent"], ev["action"][:30])
        if key not in seen:
            seen.add(key)
            live_events_deduped.append(ev)
        if len(live_events_deduped) >= 50:
            break

    now_utc = datetime.now(timezone.utc)
    window_from = now_utc - timedelta(hours=hours)
    return {
        "window": {
            "from": window_from.isoformat(),
            "to": now_utc.isoformat(),
            "hours": hours,
        },
        "kpis": {
            "activeSessions": active_sessions,
            "toolCallsInspected24h": tool_calls_24h,
            "dangerousCommandsPrevented24h": dangerous_prevented_24h,
            "deltas": {
                "threats": _pct_delta(sum(threats_out.values()), threats_prev_acc[0]),
                "tools": _pct_delta(tool_calls_24h, tool_calls_prev),
                "dangerous": _pct_delta(dangerous_prevented_24h, dangerous_prev),
            },
        },
        "threatsByCategory": threats_out,
        "blockRateTimeseries": timeseries,
        "agentBlockedCommands": [
            {"agent": agent, "blocked": count}
            for agent, count in agent_blocks.most_common(10)
        ],
        "toolCallBreakdown": [
            {"tool": tool, "count": count}
            for tool, count in tool_breakdown.most_common(10)
        ],
        "topPatterns": top_patterns,
        "liveEvents": live_events_deduped,
        "topSessionsByBlocks": top_users,
        "topMcpAndSkills": top_mcp_and_skills,
        "severityBreakdown": {
            "critical": severity_breakdown.get("critical", 0),
            "high": severity_breakdown.get("high", 0),
            "medium": severity_breakdown.get("medium", 0),
            "low": severity_breakdown.get("low", 0),
        },
    }


# ── Reverse category map (dashboard cat → list of raw DB cats) ────────────────
_REVERSE_CATEGORY_MAP: Dict[str, List[str]] = {}
for _raw_cat, _dash_cat in _CATEGORY_MAP.items():
    _REVERSE_CATEGORY_MAP.setdefault(_dash_cat, []).append(_raw_cat)

_VALID_SESSION_SORTS: Dict[str, str] = {
    "sessionId": "session_id",
    "agent": "agent",
    "workspace": "workspace_path",
    "riskScore": "risk_score",
    "findingsCount": "findings_count",
    "startedAt": "started_at",
    "updatedAt": "updated_at",
}


def get_sessions_page(
    page: int = 1,
    limit: int = 20,
    sort: str = "updatedAt",
    direction: str = "desc",
) -> Dict[str, Any]:
    """Return a paginated list of sessions across all registered workspaces."""
    sort_col = _VALID_SESSION_SORTS.get(sort, "updated_at")
    reverse = direction.lower() != "asc"
    workspaces = _state_query_workspaces()
    rows: List[Dict[str, Any]] = []

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
            name_col = "agent_name" if "agent_name" in cols else "agent"
            for row in conn.execute(
                f"SELECT session_id, agent, {name_col} as agent_name, source, risk_score, findings_count, "
                "started_at, updated_at, workspace_path FROM sessions LIMIT 5000"
            ):
                workspace_path = row["workspace_path"] or str(ws)
                rows.append({
                    "sessionId": row["session_id"] or "",
                    "agent": row["agent"] or "unknown",
                    "agentName": row["agent_name"] or row["agent"] or "unknown",
                    "source": row["source"] or "agent",
                    "riskScore": row["risk_score"] or 0,
                    "findingsCount": row["findings_count"] or 0,
                    "startedAt": _relative_time_store(row["started_at"]) if row["started_at"] else "",
                    "startedAtAbs": _absolute_time_store(row["started_at"] or ""),
                    "updatedAt": _relative_time_store(row["updated_at"]) if row["updated_at"] else "",
                    "updatedAtAbs": _absolute_time_store(row["updated_at"] or ""),
                    "_sortRaw": row[sort_col] or "",
                    "workspace": workspace_path,
                    "workspaceName": Path(workspace_path).name if workspace_path else "",
                })
        except Exception:
            pass
        finally:
            conn.close()

    rows.sort(key=lambda x: x["_sortRaw"] or "", reverse=reverse)
    total = len(rows)
    limit = max(1, min(limit, 200))
    pages = max(1, (total + limit - 1) // limit)
    page = max(1, min(page, pages))
    offset = (page - 1) * limit
    items = rows[offset: offset + limit]
    for r in items:
        r.pop("_sortRaw", None)

    return {"items": items, "total": total, "page": page, "pages": pages, "limit": limit}


def get_findings_page(
    page: int = 1,
    limit: int = 25,
    agent: str = "",
    severity: str = "",
    category: str = "",
    search: str = "",
) -> Dict[str, Any]:
    """Return a paginated, filtered list of findings across all registered workspaces."""
    severity_filter = severity.lower() if severity else ""
    raw_cats = _REVERSE_CATEGORY_MAP.get(category, []) if category else []
    workspaces = _state_query_workspaces()
    rows: List[Dict[str, Any]] = []

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            where_clauses: List[str] = []
            params: List[Any] = []
            if severity_filter:
                where_clauses.append("LOWER(f.severity) = ?")
                params.append(severity_filter)
            if raw_cats:
                placeholders = ",".join("?" * len(raw_cats))
                where_clauses.append(f"f.category IN ({placeholders})")
                params.extend(raw_cats)
            if agent:
                where_clauses.append("s.agent = ?")
                params.append(agent)
            if search:
                where_clauses.append("(LOWER(f.title) LIKE ? OR LOWER(COALESCE(f.evidence,'')) LIKE ?)")
                params.extend([f"%{search.lower()}%"] * 2)
            where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            # The triggering event for a finding is identified by event_index
            # (its 0-based position in the session's event list). SQLite does
            # not support correlating an outer column inside a subquery's
            # OFFSET clause (`OFFSET COALESCE(f.event_index, 0)` errors with
            # "no such column: f.event_index" even though the column exists),
            # so number each session's events with ROW_NUMBER() and join on
            # equality instead — see PrismorSec/prismor#129.
            for row in conn.execute(
                f"""
                WITH numbered_events AS (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY session_id ORDER BY id
                    ) - 1 AS rn
                    FROM events
                )
                SELECT f.finding_id, f.session_id, f.title, f.category,
                       f.severity, f.evidence, f.event_index, s.agent,
                       te.ts          as trig_ts,
                       te.type        as trig_type,
                       te.command_text as trig_cmd,
                       te.path_text    as trig_path,
                       te.url_text     as trig_url,
                       te.content_text as trig_content,
                       te.agent_event  as trig_hook,
                       s.updated_at    as session_updated
                FROM findings f
                JOIN sessions s ON s.session_id = f.session_id
                LEFT JOIN numbered_events te
                    ON te.session_id = f.session_id
                    AND te.rn = COALESCE(f.event_index, 0)
                {where}
                ORDER BY COALESCE(te.ts, s.updated_at) DESC
                LIMIT 5000
                """,
                params,
            ):
                ts_raw = row["trig_ts"] or row["session_updated"] or ""
                trig_kind = (row["trig_type"] or "").strip() or row["trig_hook"] or ""
                trig_detail = (row["trig_cmd"] or row["trig_path"] or row["trig_url"]
                              or row["trig_content"] or "")
                rows.append({
                    "id": (row["finding_id"] or "")[:20],
                    "sessionId": row["session_id"] or "",
                    "title": row["title"] or "Unknown",
                    "category": _CATEGORY_MAP.get(row["category"] or "", "dangerous_command"),
                    "severity": (row["severity"] or "low").lower(),
                    "evidence": (row["evidence"] or "")[:800],
                    "agent": row["agent"] or "unknown",
                    "ts": _relative_time_store(ts_raw) if ts_raw else "",
                    "tsAbs": _absolute_time_store(ts_raw),
                    "_tsRaw": ts_raw,
                    "trigger": {
                        "kind": trig_kind,
                        "detail": (trig_detail or "")[:1200],
                    },
                })
        except Exception:
            pass
        finally:
            conn.close()

    rows.sort(key=lambda x: x["_tsRaw"] or "", reverse=True)
    all_agents = sorted({r["agent"] for r in rows})
    all_cats = sorted({r["category"] for r in rows})
    total = len(rows)
    limit = max(1, min(limit, 200))
    pages = max(1, (total + limit - 1) // limit)
    page = max(1, min(page, pages))
    offset = (page - 1) * limit
    items = rows[offset: offset + limit]
    for r in items:
        r.pop("_tsRaw", None)

    return {
        "items": items, "total": total, "page": page, "pages": pages, "limit": limit,
        "agents": all_agents, "categories": all_cats,
    }


def get_events_page(
    page: int = 1,
    limit: int = 30,
    verdict: str = "",
    agent: str = "",
) -> Dict[str, Any]:
    """Return a paginated, filtered list of events across all registered workspaces."""
    workspaces = _state_query_workspaces()
    rows: List[Dict[str, Any]] = []

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            where_clauses: List[str] = []
            params: List[Any] = []
            limit = max(1, min(limit, 200))
            page = max(1, page)
            if verdict == "blocked":
                fetch_limit = max(300, page * limit * 12)
            elif verdict == "allowed" or agent:
                fetch_limit = max(300, page * limit * 5)
            else:
                fetch_limit = max(200, page * limit * 3)
            fetch_limit = min(fetch_limit, 1200)
            if agent:
                where_clauses.append("s.agent = ?")
                params.append(agent)
            where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            # verdict/severity must reflect THIS event, not the session as a
            # whole — the previous `s.findings_count > 0` check plus an
            # unscoped `LEFT JOIN findings ON session_id` marked every event
            # in a flagged session as "blocked", including ones that were
            # actually allowed. Number events per session and join findings
            # on the matching event_index instead — see PrismorSec/prismor#130.
            for row in conn.execute(
                f"""
                WITH recent_events AS (
                    SELECT *
                    FROM events
                    ORDER BY ts DESC
                    LIMIT ?
                ),
                numbered_events AS (
                    SELECT re.*,
                           (
                               SELECT COUNT(*)
                               FROM events e2
                               WHERE e2.session_id = re.session_id
                                 AND e2.id < re.id
                           ) AS rn
                    FROM recent_events re
                )
                SELECT e.ts, e.session_id, s.agent, s.workspace_path,
                       e.rn as event_index,
                       e.type as action_type,
                       e.command_text, e.path_text, e.url_text, e.raw_json,
                       f.finding_id, f.severity, f.category, f.title,
                       f.evidence, f.enrichment_json,
                       CASE WHEN f.finding_id IS NOT NULL THEN 'blocked' ELSE 'allowed' END as verdict
                FROM numbered_events e
                JOIN sessions s ON s.session_id = e.session_id
                LEFT JOIN findings f ON f.session_id = e.session_id AND f.event_index = e.rn
                {where}
                ORDER BY e.ts DESC LIMIT 5000
                """,
                [fetch_limit] + params,
            ):
                action_parts = []
                if row["action_type"]:
                    action_parts.append(row["action_type"])
                detail = row["command_text"] or row["path_text"] or row["url_text"] or ""
                tool_tag = ""
                raw_json = row["raw_json"] or ""
                raw = {}
                if raw_json:
                    try:
                        raw = json.loads(raw_json)
                    except Exception:
                        raw = {}
                    meta = raw.get("metadata", {}) if isinstance(raw, dict) else {}
                    tag = meta.get("tool_name")
                    if isinstance(tag, str) and tag.strip():
                        tool_tag = tag.strip()
                finding_id = row["finding_id"]
                severity = row["severity"]
                category = row["category"]
                title = row["title"]
                evidence = row["evidence"]
                enrichment = {}
                if row["enrichment_json"]:
                    try:
                        enrichment = json.loads(row["enrichment_json"])
                    except Exception:
                        enrichment = {}
                verdict_value = row["verdict"] or "allowed"
                if not finding_id and isinstance(raw, dict):
                    try:
                        from prismor.runtime.scoped_agent import load_scoped_rules, check_scoped_rules
                        scoped = load_scoped_rules(Path(row["workspace_path"] or str(ws)), row["session_id"] or "")
                        if scoped:
                            inferred = check_scoped_rules(scoped, raw, session_id=row["session_id"] or "")
                            if inferred:
                                finding_id = inferred.get("id") or "scoped-agent"
                                severity = inferred.get("severity") or "HIGH"
                                category = inferred.get("category") or "scoped_agent"
                                title = inferred.get("title") or "Scoped agent policy blocked this event"
                                evidence = inferred.get("evidence") or ""
                                enrichment = {
                                    "ruleId": inferred.get("ruleId"),
                                    "action": inferred.get("action"),
                                    "mode": inferred.get("mode"),
                                    "source": "inferred-scoped",
                                }
                                verdict_value = "blocked"
                    except Exception:
                        pass
                if detail:
                    action_parts.append(detail[:80])
                ts_raw = row["ts"] or ""
                rows.append({
                    "ts": _relative_time_store(ts_raw) if ts_raw else "",
                    "tsAbs": _absolute_time_store(ts_raw),
                    "_tsRaw": ts_raw,
                    "agent": row["agent"] or "unknown",
                    "action": ": ".join(action_parts) if action_parts else "event",
                    "toolTag": tool_tag,
                    "actionType": row["action_type"] or "",
                    "verdict": verdict_value,
                    "severity": (severity or "low").lower(),
                    "sessionId": row["session_id"] or "",
                    "workspace": row["workspace_path"] or str(ws),
                    "eventIndex": row["event_index"],
                    "policy": {
                        "id": finding_id or "",
                        "ruleId": enrichment.get("ruleId") or finding_id or "",
                        "category": category or "",
                        "title": title or "",
                        "evidence": evidence or "",
                        "action": enrichment.get("action") or ("block" if verdict_value == "blocked" else ""),
                        "mode": enrichment.get("mode") or "",
                        "source": enrichment.get("source") or ("finding" if finding_id else ""),
                    },
                })
        except Exception:
            pass
        finally:
            conn.close()

    # Deduplicate then sort
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for ev in rows:
        key = (ev["_tsRaw"], ev["agent"], ev["action"][:40])
        if key not in seen:
            seen.add(key)
            deduped.append(ev)
    deduped.sort(key=lambda x: x["_tsRaw"] or "", reverse=True)
    if verdict == "blocked":
        deduped = [ev for ev in deduped if ev.get("verdict") == "blocked"]
    elif verdict == "allowed":
        deduped = [ev for ev in deduped if ev.get("verdict") != "blocked"]

    all_agents = sorted({ev["agent"] for ev in deduped})
    total = len(deduped)
    pages = max(1, (total + limit - 1) // limit)
    page = max(1, min(page, pages))
    offset = (page - 1) * limit
    items = deduped[offset: offset + limit]
    for r in items:
        r.pop("_tsRaw", None)

    return {
        "items": items, "total": total, "page": page, "pages": pages, "limit": limit,
        "agents": all_agents,
    }


# ── Supply chain store ────────────────────────────────────────────────────────

def write_supply_chain_event(
    *,
    workspace: Path,
    session_id: str,
    ts: str,
    ecosystem: str,
    install_cmd: str,
    verdicts: list,
    recommendations: Optional[Dict[str, str]] = None,
) -> None:
    """Record prismor CLI scoring results into the prismor DB. Fail-open.

    ``recommendations`` maps ``spec.raw`` → safe version string so the
    dashboard can show "blocked X, suggested Y" instead of just "blocked X".
    """
    import uuid as _uuid
    recommendations = recommendations or {}
    try:
        db_path = initialize_database(workspace)
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.cursor()

            n_blocked = sum(1 for v in verdicts if v.verdict == "block")
            n_warned = sum(1 for v in verdicts if v.verdict == "warn")
            n_allowed = sum(1 for v in verdicts if v.verdict == "allow")
            n_findings = n_blocked + n_warned
            max_score = max((v.score for v in verdicts), default=0)
            cursor.execute(
                """
                INSERT OR IGNORE INTO sessions (
                    session_id, agent, source, workspace_path,
                    started_at, updated_at, risk_score, findings_count, summary_json
                ) VALUES (?, 'immunity-cli', 'supply_chain', ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id, str(workspace), ts, ts,
                    max_score, n_findings,
                    json.dumps({
                        "ecosystem": ecosystem,
                        "installCmd": install_cmd,
                        "allowed": n_allowed,
                        "blocked": n_blocked,
                        "warned": n_warned,
                    }),
                ),
            )

            for event_index, v in enumerate(verdicts):
                ioc_id = next(
                    (s.id[len("ioc_"):] for s in v.signals if s.id.startswith("ioc_")),
                    None,
                )
                recommended = recommendations.get(v.spec.raw, "") or ""
                cursor.execute(
                    """
                    INSERT INTO events (
                        session_id, ts, type, agent_event, command_text, raw_json
                    ) VALUES (?, ?, 'supply_chain', ?, ?, ?)
                    """,
                    (
                        session_id, ts, ecosystem, install_cmd,
                        json.dumps({
                            "package": v.spec.raw,
                            "ecosystem": ecosystem,
                            "verdict": v.verdict,
                            "score": v.score,
                            "recommended": recommended,
                        }),
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO supply_chain_events (
                        ts, workspace_path, ecosystem, package_name, package_version,
                        install_cmd, verdict, score, signals_json, ioc_id,
                        recommended_version, session_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts, str(workspace), ecosystem,
                        v.spec.name,
                        getattr(v.spec, "version", None) or getattr(v.meta, "version", None) or "",
                        install_cmd,
                        v.verdict,
                        v.score,
                        json.dumps([
                            {"id": s.id, "points": s.points, "description": s.description}
                            for s in v.signals
                        ]),
                        ioc_id,
                        recommended,
                        session_id,
                    ),
                )

                if v.verdict in ("block", "warn"):
                    has_ioc = any(s.id.startswith("ioc_") for s in v.signals)
                    severity = "CRITICAL" if has_ioc else ("HIGH" if v.score >= 60 else "MEDIUM")
                    title = f"{v.verdict.upper()}: {v.spec.raw} [{ecosystem}] score {v.score}"
                    evidence_parts = ["; ".join(s.description for s in v.signals[:3])]
                    if recommended:
                        evidence_parts.append(f"Suggested safe version: {recommended}")
                    evidence_parts.append(f"Triggered by: {install_cmd}")
                    cursor.execute(
                        """
                        INSERT INTO findings (
                            finding_id, session_id, event_index, severity, category, title, evidence
                        ) VALUES (?, ?, ?, ?, 'supply_chain_block', ?, ?)
                        """,
                        (
                            str(_uuid.uuid4()),
                            session_id,
                            event_index,
                            severity,
                            title,
                            " | ".join(evidence_parts),
                        ),
                    )

            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


_ADVISORY_RE = re.compile(r"(GHSA-[0-9a-z-]+|CVE-\d{4}-\d{4,}|MAL-\d{4}-\d+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)", re.IGNORECASE)


def _extract_advisory_ids(signals_json: str) -> List[str]:
    """Pull GHSA/CVE/MAL/PYSEC/RUSTSEC IDs out of a signals_json blob."""
    if not signals_json:
        return []
    ids: List[str] = []
    seen: set = set()
    try:
        for sig in json.loads(signals_json) or []:
            for match in _ADVISORY_RE.findall(str(sig.get("description", ""))):
                up = match.upper()
                if up not in seen:
                    seen.add(up)
                    ids.append(up)
    except Exception:
        pass
    return ids


def get_supply_chain_stats(hours: int = 24) -> Dict[str, Any]:
    """Aggregate supply chain enforcement data across all registered workspaces."""
    from collections import Counter

    workspaces = _state_query_workspaces()

    checked_24h = 0
    allowed_24h = 0
    blocked_24h = 0
    warned_24h = 0
    ecosystem_total: Counter = Counter()
    ecosystem_blocked: Counter = Counter()
    pkg_blocks: Counter = Counter()
    pkg_ecosystem: Dict[str, str] = {}
    pkg_ioc: Dict[str, str] = {}
    recent_rows: List[Dict[str, Any]] = []   # raw rows for later sort/format
    session_acc: Dict[str, Dict[str, Any]] = {}

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            for row in conn.execute(
                "SELECT verdict, COUNT(*) as cnt FROM supply_chain_events "
                "WHERE ts >= datetime('now', ?) GROUP BY verdict",
                (f"-{hours} hours",),
            ):
                v = row["verdict"] or "allow"
                if v == "block":
                    blocked_24h += row["cnt"]
                elif v == "warn":
                    warned_24h += row["cnt"]
                elif v == "allow":
                    allowed_24h += row["cnt"]
                checked_24h += row["cnt"]

            for row in conn.execute(
                "SELECT ecosystem, verdict, COUNT(*) as cnt "
                "FROM supply_chain_events GROUP BY ecosystem, verdict"
            ):
                eco = row["ecosystem"] or "unknown"
                ecosystem_total[eco] += row["cnt"]
                if row["verdict"] == "block":
                    ecosystem_blocked[eco] += row["cnt"]

            for row in conn.execute(
                "SELECT package_name, ecosystem, ioc_id, COUNT(*) as cnt "
                "FROM supply_chain_events WHERE verdict='block' "
                "GROUP BY package_name ORDER BY cnt DESC LIMIT 20"
            ):
                name = row["package_name"] or ""
                pkg_blocks[name] += row["cnt"]
                pkg_ecosystem[name] = row["ecosystem"] or ""
                if row["ioc_id"] and name not in pkg_ioc:
                    pkg_ioc[name] = row["ioc_id"]

            # Recent blocks + warnings with full enrichment.
            for row in conn.execute(
                """
                SELECT ts, package_name, package_version, ecosystem, score,
                       signals_json, verdict, install_cmd,
                       COALESCE(recommended_version, '') as recommended,
                       COALESCE(session_id, '') as session_id, ioc_id
                FROM supply_chain_events
                WHERE verdict IN ('block','warn')
                ORDER BY ts DESC
                LIMIT 60
                """
            ):
                try:
                    sigs = json.loads(row["signals_json"] or "[]")
                except Exception:
                    sigs = []
                # The "reason" is the highest-impact signal — the original
                # code just took sigs[0] which often was a low-weight
                # informational signal like "maintainer data unavailable".
                top_sig = max(sigs, key=lambda s: s.get("points", 0), default=None)
                recent_rows.append({
                    "tsRaw": row["ts"] or "",
                    "package": row["package_name"] or "",
                    "version": row["package_version"] or "",
                    "ecosystem": row["ecosystem"] or "",
                    "score": row["score"] or 0,
                    "verdict": row["verdict"] or "block",
                    "reason": (top_sig.get("description", "")[:120] if top_sig else ""),
                    "installCmd": row["install_cmd"] or "",
                    "recommended": row["recommended"] or "",
                    "advisoryIds": _extract_advisory_ids(row["signals_json"] or ""),
                    "iocId": row["ioc_id"] or "",
                    "sessionId": row["session_id"] or "",
                })

            # Per-session install activity in the 24h window.
            for row in conn.execute(
                """
                SELECT session_id,
                       ecosystem,
                       MAX(install_cmd) as install_cmd,
                       MIN(ts) as started,
                       MAX(ts) as last_seen,
                       SUM(CASE WHEN verdict='allow' THEN 1 ELSE 0 END) as allowed,
                       SUM(CASE WHEN verdict='block' THEN 1 ELSE 0 END) as blocked,
                       SUM(CASE WHEN verdict='warn'  THEN 1 ELSE 0 END) as warned,
                       COUNT(*) as total
                FROM supply_chain_events
                WHERE ts >= datetime('now', ?)
                  AND session_id IS NOT NULL AND session_id != ''
                GROUP BY session_id, install_cmd
                ORDER BY last_seen DESC
                LIMIT 25
                """,
                (f"-{hours} hours",),
            ):
                sid = row["session_id"] or "—"
                key = (sid, row["install_cmd"] or "")
                if key in session_acc:
                    continue
                session_acc[key] = {
                    "sessionId": sid,
                    "ecosystem": row["ecosystem"] or "",
                    "installCmd": row["install_cmd"] or "",
                    "allowed": row["allowed"] or 0,
                    "blocked": row["blocked"] or 0,
                    "warned": row["warned"] or 0,
                    "total": row["total"] or 0,
                    "lastSeen": _relative_time_store(row["last_seen"]) if row["last_seen"] else "",
                    "lastSeenAbs": _absolute_time_store(row["last_seen"] or ""),
                    "_tsRaw": row["last_seen"] or "",
                }
        except Exception:
            pass
        finally:
            conn.close()

    # Sort recent rows by raw ts (the old code sorted by relative-time string
    # which interleaved "12m ago" with "2h ago" arbitrarily) then format.
    recent_rows.sort(key=lambda r: r["tsRaw"], reverse=True)
    recent_blocks = [
        {
            "ts": _relative_time_store(r["tsRaw"]) if r["tsRaw"] else "",
            "tsAbs": _absolute_time_store(r["tsRaw"]),
            "package": r["package"],
            "version": r["version"],
            "ecosystem": r["ecosystem"],
            "score": r["score"],
            "verdict": r["verdict"],
            "reason": r["reason"],
            "installCmd": r["installCmd"],
            "recommended": r["recommended"],
            "advisoryIds": r["advisoryIds"],
            "iocId": r["iocId"],
            "sessionId": r["sessionId"],
        }
        for r in recent_rows[:30]
    ]

    by_session = sorted(
        session_acc.values(),
        key=lambda s: s.get("_tsRaw") or "",
        reverse=True,
    )[:15]
    for s in by_session:
        s.pop("_tsRaw", None)

    top_blocked = sorted(pkg_blocks, key=lambda k: pkg_blocks[k], reverse=True)[:10]

    return {
        "kpis": {
            "checkedPackages24h": checked_24h,
            "allowedPackages24h": allowed_24h,
            "blockedPackages24h": blocked_24h,
            "warnedPackages24h": warned_24h,
        },
        "ecosystemBreakdown": [
            {
                "ecosystem": eco,
                "total": ecosystem_total[eco],
                "blocked": ecosystem_blocked.get(eco, 0),
            }
            for eco in sorted(ecosystem_total, key=lambda k: ecosystem_total[k], reverse=True)
        ],
        "topBlockedPackages": [
            {
                "name": name,
                "ecosystem": pkg_ecosystem.get(name, ""),
                "count": pkg_blocks[name],
                "iocId": pkg_ioc.get(name, ""),
            }
            for name in top_blocked
        ],
        "recentBlocks": recent_blocks,
        "installsBySession": by_session,
    }


def _insert_fail_open(workspace: Path, sql: str, params: tuple) -> None:
    try:
        connection = sqlite3.connect(initialize_database(workspace))
        try:
            connection.execute(sql, params)
            connection.commit()
        finally:
            connection.close()
    except Exception:
        pass


def record_token_usage(
    *,
    workspace: Path,
    session_id: str,
    ts: str,
    message_id: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int,
    cache_creation_tokens: int,
) -> None:
    """Record one assistant turn's real Anthropic token usage. Fail-open.

    Deduped on ``message_id`` — a single assistant turn can trigger several
    PostToolUse hooks (parallel tool calls), which would otherwise count the
    same turn's usage multiple times.
    """
    if not message_id:
        return
    _insert_fail_open(
        workspace,
        """
        INSERT OR IGNORE INTO token_usage (
            message_id, session_id, workspace_path, ts, model,
            input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            message_id, session_id, str(workspace), ts, model,
            input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
        ),
    )


def record_tool_output_size(
    *,
    workspace: Path,
    session_id: str,
    ts: str,
    agent: str,
    tool_name: str,
    label: str,
    size_chars: int,
) -> None:
    """Record the size of one tool call's output, as a proxy for context cost.

    Works for every agent — unlike real usage, this needs nothing beyond what
    is already in the normalized hook event. Fail-open.
    """
    _insert_fail_open(
        workspace,
        """
        INSERT INTO tool_output_size (
            session_id, workspace_path, ts, agent, tool_name, label, size_chars, approx_tokens
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, str(workspace), ts, agent, tool_name, label, size_chars, size_chars // 4),
    )


def get_token_stats(workspace: Optional[Path] = None, hours: int = 24, limit: int = 8) -> Dict[str, Any]:
    """Token-usage summary + tool-output breakdown, dashboard-shaped.

    Every workspace writes to the single home DB, so scoping is just a
    ``workspace_path`` filter — ``workspace=None`` aggregates everything.
    """
    db_path = get_db_path(workspace) if workspace else prismor_home() / "prismor.db"
    conn = _connect_ro(db_path)
    if conn is None:
        return {
            "inputTokens": 0, "outputTokens": 0, "cacheReadTokens": 0,
            "cacheCreationTokens": 0, "cacheHitRate": 0.0, "totalTokens": 0,
            "byTool": [], "topOffenders": [],
        }
    scope_sql = " AND workspace_path = ?" if workspace else ""
    window_args = [f"-{hours} hours"] + ([str(workspace)] if workspace else [])
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(input_tokens),0) as inp,"
            "       COALESCE(SUM(output_tokens),0) as out,"
            "       COALESCE(SUM(cache_read_tokens),0) as cread,"
            "       COALESCE(SUM(cache_creation_tokens),0) as ccreate"
            "  FROM token_usage WHERE ts >= datetime('now', ?)" + scope_sql,
            window_args,
        ).fetchone()
        by_tool = [
            {"tool": r["tool_name"] or "unknown", "approxTokens": r["tok"] or 0, "calls": r["cnt"] or 0}
            for r in conn.execute(
                "SELECT tool_name, SUM(approx_tokens) as tok, COUNT(*) as cnt"
                "  FROM tool_output_size WHERE ts >= datetime('now', ?)" + scope_sql +
                "  GROUP BY tool_name ORDER BY tok DESC LIMIT ?",
                window_args + [limit],
            )
        ]
        top_offenders = [
            {"tool": r["tool_name"] or "unknown", "label": r["label"] or "", "approxTokens": r["approx_tokens"] or 0}
            for r in conn.execute(
                "SELECT tool_name, label, approx_tokens FROM tool_output_size"
                "  WHERE ts >= datetime('now', ?) AND label != ''" + scope_sql +
                "  ORDER BY approx_tokens DESC LIMIT ?",
                window_args + [limit],
            )
        ]
    finally:
        conn.close()
    inp, out, cread, ccreate = row["inp"], row["out"], row["cread"], row["ccreate"]
    input_side = inp + cread + ccreate
    return {
        "inputTokens": inp, "outputTokens": out,
        "cacheReadTokens": cread, "cacheCreationTokens": ccreate,
        "cacheHitRate": round(cread / input_side * 100, 1) if input_side else 0.0,
        "totalTokens": inp + out + cread + ccreate,
        "byTool": by_tool, "topOffenders": top_offenders,
    }


def get_agents_overview() -> List[Dict[str, Any]]:
    """Return per-agent-name stats: framework, last_seen, total_calls, blocked_calls.

    Groups across all registered workspace DBs. Falls back gracefully when
    the agent_name column doesn't exist yet (pre-migration DBs).
    """
    from collections import Counter
    workspaces = _state_query_workspaces()

    # agent_name → {framework, last_seen, total_calls, blocked_calls}
    acc: Dict[str, Dict[str, Any]] = {}

    for ws in workspaces:
        db_path = get_db_path(ws)
        conn = _connect_ro(db_path)
        if conn is None:
            continue
        try:
            # Check column exists (pre-migration DBs won't have it)
            cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
            # Most adapters (codex, cursor, copilot, …) only set ``agent``;
            # ``agent_name`` is the optional instance label. Group on the
            # label when present, falling back to the framework id, so
            # sessions without a label still show up in the overview.
            name_expr = (
                "COALESCE(NULLIF(agent_name, ''), agent)"
                if "agent_name" in cols
                else "agent"
            )

            for row in conn.execute(
                f"""
                SELECT
                    COALESCE({name_expr}, 'unknown') as agent_name,
                    agent as framework,
                    MAX(updated_at) as last_seen,
                    COUNT(*) as total_calls,
                    SUM(CASE WHEN findings_count > 0 THEN 1 ELSE 0 END) as blocked_calls
                FROM sessions
                WHERE {name_expr} IS NOT NULL AND {name_expr} != ''
                GROUP BY {name_expr}
                """
            ):
                name = row["agent_name"] or "unknown"
                existing = acc.get(name)
                if existing is None:
                    acc[name] = {
                        "name": name,
                        "framework": row["framework"] or "",
                        "last_seen": row["last_seen"] or "",
                        "total_calls": row["total_calls"] or 0,
                        "blocked_calls": row["blocked_calls"] or 0,
                    }
                else:
                    existing["total_calls"] += row["total_calls"] or 0
                    existing["blocked_calls"] += row["blocked_calls"] or 0
                    if (row["last_seen"] or "") > existing["last_seen"]:
                        existing["last_seen"] = row["last_seen"] or ""
                    if row["framework"] and not existing["framework"]:
                        existing["framework"] = row["framework"]
        except Exception:
            pass
        finally:
            conn.close()

    return sorted(acc.values(), key=lambda x: x["last_seen"] or "", reverse=True)
# ── Policy management helpers ─────────────────────────────────────────────────

def _global_policy_path() -> Path:
    return prismor_home() / "policy.yaml"


def _project_policy_path(workspace: Path) -> Path:
    return workspace / ".prismor" / "policy.yaml"


def get_enrollment() -> Optional[Dict[str, Any]]:
    """Return active enterprise enrollment info, or None if unenrolled/revoked."""
    from prismor.runtime.enterprise import identity as _identity
    if _identity.revoked_info():
        return None
    identity = prismor_home() / "identity.json"
    if not identity.exists():
        return None
    try:
        data = json.loads(identity.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data.get("device_key"):
            return None
        return {
            "enrolled": True,
            "org_id": data.get("org_id"),
            "device_id": data.get("device_id"),
            "api_base": data.get("api_base", "https://www.prismor.dev"),
        }
    except Exception:
        return None


def _enterprise_remote_cache() -> Optional[str]:
    cache = prismor_home() / "remote_policy_cache.json"
    if not cache.exists():
        return None
    try:
        d = json.loads(cache.read_text(encoding="utf-8"))
        return d.get("yaml") or d.get("policy_yaml")
    except Exception:
        return None


def read_policy_layer(scope: str, workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Read one policy layer.  scope: 'global' | 'project' | 'enterprise'"""
    if scope == "global":
        path = _global_policy_path()
        if not path.exists():
            return {"exists": False, "yaml": "", "path": str(path)}
        try:
            return {
                "exists": True,
                "yaml": path.read_text(encoding="utf-8"),
                "path": str(path),
                "mtime": path.stat().st_mtime,
            }
        except Exception as exc:
            return {"exists": False, "yaml": "", "path": str(path), "error": str(exc)}

    if scope == "project":
        if not workspace:
            return {"exists": False, "yaml": "", "path": ""}
        path = _project_policy_path(workspace)
        if not path.exists():
            return {"exists": False, "yaml": "", "path": str(path)}
        try:
            return {
                "exists": True,
                "yaml": path.read_text(encoding="utf-8"),
                "path": str(path),
                "mtime": path.stat().st_mtime,
            }
        except Exception as exc:
            return {"exists": False, "yaml": "", "path": str(path), "error": str(exc)}

    if scope == "enterprise":
        if get_enrollment() is None:
            return {"exists": False, "yaml": "", "enrollment": None, "readonly": False}
        yaml_content = _enterprise_remote_cache()
        enrollment = get_enrollment()
        return {
            "exists": yaml_content is not None,
            "yaml": yaml_content or "",
            "enrollment": enrollment,
            "readonly": True,
        }

    return {"exists": False, "yaml": "", "error": "unknown scope"}


def _policy_default_mode(yaml_text: str) -> str:
    """The mode badge for a policy layer.

    `default_mode` is the fallback for rules that do not set their own, so on a
    policy that names its blocking set rule by rule it describes the rules
    nobody selected — reading "observe" beside a summary saying three rules
    enforce. Any rule pinned to enforce makes the layer an enforcing one.
    """
    text = yaml_text or ""
    if re.search(r"^\s*mode\s*:\s*enforce\s*$", text, re.MULTILINE):
        return "enforce"
    match = re.search(r"^\s*default_mode\s*:\s*([A-Za-z0-9_-]+)\s*$", text, re.MULTILINE)
    return (match.group(1).strip().lower() if match else "observe")


def _policy_rule_override_count(yaml_text: str) -> int:
    return len(re.findall(r"^\s*-\s*id\s*:\s*.+$", yaml_text or "", re.MULTILINE))


def _session_scope_summary(scoped: Dict[str, Any]) -> str:
    if not scoped:
        return "No session scope. This session follows the base policy chain below."
    if scoped.get("paused"):
        return "Prismor is paused for this session. No tool calls are blocked or flagged until resumed."
    parts: List[str] = []
    allowed = scoped.get("allowed_tools") or []
    denied = scoped.get("deny_tools") or []
    if allowed:
        parts.append(f"{len(allowed)} allowed tool tag{'s' if len(allowed) != 1 else ''}")
    if denied:
        parts.append(f"{len(denied)} denied tool tag{'s' if len(denied) != 1 else ''}")
    if scoped.get("deny_network"):
        parts.append("network denied")
    if scoped.get("allowed_paths"):
        parts.append("path allowlist active")
    if not parts:
        return "Session scope file exists but does not override tools or network."
    return "Session scope overlays the base policy with " + ", ".join(parts) + "."


def _policy_layer_summary(scope: str, layer: Dict[str, Any]) -> str:
    if scope == "default":
        return "Built-in Prismor defaults apply when no higher layer overrides them."
    if scope == "enterprise":
        if layer.get("exists"):
            return (
                f"Org-managed policy is active. Default mode: {_policy_default_mode(layer.get('yaml') or '')}. "
                f"{_policy_rule_override_count(layer.get('yaml') or '')} explicit rule override(s)."
            )
        if layer.get("enrollment"):
            return "This device is enrolled, but no enterprise policy has been pushed yet."
        return "No enterprise policy. Enroll this device to receive org-managed controls."
    if scope == "project":
        if layer.get("exists"):
            text = layer.get("yaml") or ""
            # An explicit-selection policy names its blocking set rule by rule,
            # so quoting `default_mode` alone would describe it as "observe"
            # while it blocks — the same confusion the header chip had.
            if re.search(r"^\s*selection\s*:\s*explicit\s*$", text, re.MULTILINE):
                # Count rules, not every `mode: enforce` in the file —
                # settings.egress has one too, and counting it reported one
                # more blocking rule than the policy has.
                enforcing = 0
                try:
                    import yaml as _yaml
                    parsed = _yaml.safe_load(text) or {}
                    enforcing = sum(
                        1 for r in (parsed.get("rules") or [])
                        if isinstance(r, dict) and str(r.get("mode") or "").lower() == "enforce"
                    )
                except Exception:
                    enforcing = len(re.findall(r"^\s{2,}mode\s*:\s*enforce\s*$", text, re.MULTILINE))
                return (
                    f"Project policy names its blocking set: {enforcing} rule(s) enforce, "
                    "everything else is reported. Written by `prismor setup --mode enforce`."
                )
            return (
                f"Project overrides are active for this workspace. Default mode: "
                f"{_policy_default_mode(text)}. "
                f"{_policy_rule_override_count(text)} explicit rule override(s)."
            )
        return "No project override file for this workspace."
    if scope == "global":
        # The engine merges defaults → project → org; it never reads this file
        # (grep prismor_home in policy_engine.py). Listing it in the chain
        # without saying so implies a layer that does not take part.
        if layer.get("exists"):
            return (
                "This file exists but the policy engine does not currently merge it — "
                "it changes nothing on its own. Use the project policy instead."
            )
        return "No custom global policy on this machine (this layer is not applied by the runtime)."
    return ""


def get_policy_precedence(workspace: Optional[Path] = None, scoped: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    global_layer = read_policy_layer("global")
    project_layer = read_policy_layer("project", workspace)
    enterprise_layer = read_policy_layer("enterprise")

    winner = "default"
    for scope, layer in (
        ("enterprise", enterprise_layer),
        ("project", project_layer),
        ("global", global_layer),
    ):
        if layer.get("exists"):
            winner = scope
            break

    chain: List[Dict[str, Any]] = []
    if scoped is not None:
        has_scope = bool(
            scoped.get("paused")
            or scoped.get("allowed_tools")
            or scoped.get("deny_tools")
            or scoped.get("allowed_paths")
            or scoped.get("deny_network")
        )
        chain.append({
            "scope": "session",
            "label": "Session scope",
            "exists": has_scope,
            "winning": has_scope,
            "mode": "paused" if scoped.get("paused") else "scoped",
            "path": "",
            "summary": _session_scope_summary(scoped),
        })

    for scope, label, layer in (
        ("enterprise", "Enterprise policy", enterprise_layer),
        ("project", "Project policy", project_layer),
        ("global", "Global policy", global_layer),
    ):
        chain.append({
            "scope": scope,
            "label": label,
            "exists": bool(layer.get("exists")),
            "winning": winner == scope,
            "mode": _policy_default_mode(layer.get("yaml") or ""),
            "path": layer.get("path") or "",
            "summary": _policy_layer_summary(scope, layer),
        })

    chain.append({
        "scope": "default",
        "label": "Built-in defaults",
        "exists": True,
        "winning": winner == "default",
        "mode": "observe",
        "path": "",
        "summary": _policy_layer_summary("default", {}),
    })

    return {"winner": winner, "chain": chain}


def is_policy_editable(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Whether local policy edits are worth offering here.

    Where an org's signed policy governs, it merges after the project layer, so
    a local edit either does nothing or reverts on the next pull. Saying so
    beats letting someone edit a file that gets overwritten — the dashboard
    greys its controls on this and the CLI writers refuse on it.

    This is a usability guard, not a security control — the org overlay merges
    after the local layers either way, so it still wins on anything it
    specifies. That is why every uncertain case below resolves to *editable*:
    refusing is only worth it when we can positively show an org policy is
    live, and a read-only screen nobody can explain is worse than an edit that
    a later pull overwrites.

    Two things must hold: the workspace is org-managed, and a cached signed
    policy exists to govern it. Enrollment alone is not enough — an org that
    has not configured repo scoping manages every workspace by default
    (workspace_scope.resolve_scope, reason "default_all"), so keying on
    management would take local policy away from an enrolled solo developer in
    their own side project for an org policy that does not exist.

    ``is_managed`` already returns False once the device is revoked, so a
    device removed from its org unlocks as soon as any authenticated call has
    seen the 401 — which is also what the refusal message points at, for the
    window before that has happened.
    """
    try:
        from prismor.runtime.enterprise import workspace_scope as _scope
        if not _scope.is_managed(workspace):
            return {"editable": True, "reason": "", "error": ""}
    except Exception:
        return {"editable": True, "reason": "", "error": ""}

    try:
        from prismor.runtime.enterprise import remote_policy as _remote
        if not _remote.cached_policy_path().exists():
            return {"editable": True, "reason": "", "error": ""}
    except Exception:
        return {"editable": True, "reason": "", "error": ""}

    return {
        "editable": False,
        "reason": "org_managed",
        # Deliberately does not mention `prismor workspace personal`. On an org
        # that has not configured repo patterns every workspace is managed by
        # default (reason "default_all"), and that override sits *below*
        # default_all in resolve_scope — so it detaches the workspace from org
        # policy and org telemetry entirely. Telling someone that in the same
        # breath as "you may not edit this" is handing them the way out of
        # governance. It stays available for genuinely personal repos; it is
        # not the answer to "the org policy is in my way".
        "error": "This workspace's policy is managed by your organization — "
                 "edit it in the Prismor console if you administer the org, or "
                 'request an exemption with `prismor exempt request --reason "<why>"`.\n'
                 "If you think this device was removed from the org, check with "
                 "`prismor enroll-status`.",
    }


def write_policy_layer(scope: str, content: str, workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Write a policy layer.  Returns {ok, path?, error?}"""
    if scope == "enterprise":
        return {"ok": False, "error": "Enterprise policy is managed by org admin — edit it in the Prismor web dashboard."}

    editable = is_policy_editable(workspace)
    if not editable["editable"]:
        return {"ok": False, "error": editable["error"], "reason": editable["reason"]}

    if scope == "global":
        path = _global_policy_path()
    elif scope == "project":
        if not workspace:
            return {"ok": False, "error": "workspace path required for project scope"}
        path = _project_policy_path(workspace)
    else:
        return {"ok": False, "error": f"unknown scope: {scope}"}

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return {"ok": True, "path": str(path)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ── network egress config ────────────────────────────────────────────────────
#
# `prismor egress ...` edits settings.egress in the project policy, but its
# helpers print and sys.exit, so they cannot be called from the dashboard. These
# are the same operations as data: they validate with the same EgressEntry the
# runtime compiles with, and they save through write_policy_layer, which is what
# makes the org-managed refusal apply here too.

def _egress_settings_block(data: Dict[str, Any]) -> Dict[str, Any]:
    settings = data.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        data["settings"] = settings
    block = settings.setdefault("egress", {})
    if not isinstance(block, dict):
        block = {}
        settings["egress"] = block
    return block


def _entry_to_dict(entry: Any) -> Dict[str, Any]:
    if isinstance(entry, str):
        return {"host": entry, "reason": ""}
    if isinstance(entry, dict):
        return {
            "host": str(entry.get("host") or entry.get("domain") or entry.get("cidr") or ""),
            "reason": str(entry.get("reason") or ""),
        }
    return {"host": str(entry), "reason": ""}


def get_egress_config(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """The effective egress policy plus the project-local block that edits write.

    Two views because they can differ: the effective one is what devices apply
    after the org layer merges, and the editable one is this workspace's file.
    Showing only the first would invite edits that appear to do nothing.
    """
    effective: Dict[str, Any] = {}
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        engine = PolicyEngine(workspace=workspace) if workspace else PolicyEngine()
        pol = engine.egress
        effective = {
            "enabled": bool(pol.enabled),
            # None means "inherit the policy's default_mode", which is what the
            # runtime does; spell it out rather than showing a blank.
            "mode": pol.mode or engine.default_mode,
            "modeInherited": pol.mode is None,
            "default": pol.default,
            "allowPrivate": bool(pol.allow_private),
            "allow": [_entry_to_dict(e.raw) for e in pol.allow],
            "deny": [_entry_to_dict(e.raw) for e in pol.deny],
            "source": pol.source or "default",
            "legacy": bool(pol.legacy),
            "errors": list(pol.errors or []),
        }
    except Exception as exc:
        effective = {"error": str(exc)}

    local: Dict[str, Any] = {}
    if workspace:
        try:
            from prismor.runtime.policy_engine import _load_yaml
            ppath = _project_policy_path(workspace)
            if ppath.exists():
                raw = _load_yaml(ppath) or {}
                block = ((raw.get("settings") or {}).get("egress") or {})
                if isinstance(block, dict):
                    local = {
                        "enabled": bool(block.get("enabled", False)),
                        "mode": block.get("mode"),
                        "default": block.get("default", "allow"),
                        "allowPrivate": bool(block.get("allow_private", True)),
                        "allow": [_entry_to_dict(e) for e in (block.get("allow") or [])],
                        "deny": [_entry_to_dict(e) for e in (block.get("deny") or [])],
                    }
        except Exception:
            local = {}

    return {
        "effective": effective,
        "project": local,
        "editable": is_policy_editable(workspace),
        "path": str(_project_policy_path(workspace)) if workspace else "",
    }


def _save_egress(workspace: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        import yaml
        content = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    except ImportError:
        return {"ok": False, "error": "PyYAML is required to edit the egress policy"}
    return write_policy_layer("project", content, workspace)


def _load_project_policy(workspace: Path) -> Dict[str, Any]:
    from prismor.runtime.policy_engine import _load_yaml
    ppath = _project_policy_path(workspace)
    if not ppath.exists():
        return {"version": "1.0"}
    loaded = _load_yaml(ppath)
    return loaded if isinstance(loaded, dict) else {"version": "1.0"}


def set_egress_option(workspace: Path, field: str, value: Any) -> Dict[str, Any]:
    """Set enabled / mode / default / allow_private on the project egress block."""
    allowed = {"enabled", "mode", "default", "allow_private"}
    if field not in allowed:
        return {"ok": False, "error": f"unknown egress field '{field}'"}
    if field == "mode" and str(value) not in ("observe", "enforce"):
        return {"ok": False, "error": "mode must be observe or enforce"}
    if field == "default" and str(value) not in ("allow", "deny"):
        return {"ok": False, "error": "default must be allow or deny"}

    data = _load_project_policy(workspace)
    block = _egress_settings_block(data)
    block[field] = value
    # Setting anything other than the switch itself on a disabled policy is a
    # silent no-op, which is how `prismor egress` behaves too.
    if field != "enabled":
        block.setdefault("enabled", True)
    result = _save_egress(workspace, data)
    if result.get("ok"):
        result["egress"] = get_egress_config(workspace)
    return result


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)


def validate_egress_host(host: str) -> Optional[str]:
    """Why this is not a usable egress entry, or None if it is.

    EgressEntry accepts any non-empty string, because to the matcher an
    unparseable host is simply one that never matches — harmless at evaluation
    time, useless as an entry. Typed into a form that is a silent mistake: the
    rule saves, looks right, and never fires. So the shape is checked here.
    """
    host = (host or "").strip()
    if not host:
        return "host required"
    if host == "*":
        return None
    if "://" in host:
        return "enter a host, not a URL — e.g. api.github.com"
    candidate = host[2:] if host.startswith("*.") else host
    if host.startswith("*.") and not candidate:
        return "wildcard needs a domain, e.g. *.example.com"
    if "/" in host:
        import ipaddress
        try:
            ipaddress.ip_network(host, strict=False)
            return None
        except ValueError as exc:
            return f"not a valid CIDR: {exc}"
    import ipaddress
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(candidate):
        return "not a hostname, wildcard (*.example.com), IP, or CIDR"
    return None


def add_egress_host(workspace: Path, host: str, list_name: str = "allow",
                    reason: str = "") -> Dict[str, Any]:
    """Add a host/wildcard/CIDR to settings.egress.allow or .deny."""
    if list_name not in ("allow", "deny"):
        return {"ok": False, "error": "list must be allow or deny"}
    host = (host or "").strip()
    problem = validate_egress_host(host)
    if problem:
        return {"ok": False, "error": f"{host!r}: {problem}" if host else problem}
    try:
        from prismor.runtime.egress import EgressEntry
        EgressEntry(host, list_name)  # compile it the way the runtime will
    except Exception as exc:
        return {"ok": False, "error": f"invalid host {host!r}: {exc}"}

    data = _load_project_policy(workspace)
    block = _egress_settings_block(data)
    current = block.setdefault(list_name, [])
    if not isinstance(current, list):
        current = []
        block[list_name] = current
    existing = {_entry_to_dict(e)["host"] for e in current}
    if host in existing:
        return {"ok": False, "error": f"{host} is already in {list_name}"}
    current.append({"host": host, "reason": reason} if reason else host)
    if not block.get("enabled"):
        block["enabled"] = True
        block.setdefault("mode", "observe")
    result = _save_egress(workspace, data)
    if result.get("ok"):
        result["egress"] = get_egress_config(workspace)
    return result


def remove_egress_host(workspace: Path, host: str) -> Dict[str, Any]:
    """Remove a host from both egress lists."""
    data = _load_project_policy(workspace)
    block = _egress_settings_block(data)
    removed: List[str] = []
    for key in ("allow", "deny"):
        current = block.get(key)
        if not isinstance(current, list):
            continue
        kept = []
        for item in current:
            if _entry_to_dict(item)["host"] == host:
                removed.append(f"{key}:{host}")
            else:
                kept.append(item)
        block[key] = kept
    if not removed:
        return {"ok": False, "error": f"no entry for {host}"}
    result = _save_egress(workspace, data)
    if result.get("ok"):
        result["removed"] = removed
        result["egress"] = get_egress_config(workspace)
    return result


def get_policy_rule_catalog(workspace: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return every rule from the bundled default policy with its current state
    — the data behind the dashboard's per-rule list.

    Two different states, and the difference matters: a rule is *off* when the
    project override lists it with ``enabled: false``, and separately it either
    *blocks* or only *reports*, which is what the merged policy's resolved mode
    decides. Reporting only the first would show 78 identical green toggles for
    a policy where three rules actually stop anything.
    """
    from prismor.runtime.policy_engine import (
        PolicyEngine,
        _load_yaml,
        is_floor_protected_rule,
        is_self_protection_rule,
    )

    disabled: set = set()
    if workspace:
        ppath = _project_policy_path(workspace)
        if ppath.exists():
            try:
                pdata = _load_yaml(ppath) or {}
                for r in pdata.get("rules", []):
                    if isinstance(r, dict) and not r.get("enabled", True):
                        disabled.add(r.get("id"))
            except Exception:
                pass

    # Effective mode per rule, straight from the engine that decides it at
    # dispatch — never recomputed here, or the dashboard would drift from
    # enforcement the first time the resolution rules change.
    modes: Dict[str, str] = {}
    try:
        engine = PolicyEngine(workspace=workspace) if workspace else PolicyEngine()
        for compiled in engine.rules:
            modes[compiled.id] = engine._resolve_mode(compiled)
    except Exception:
        modes = {}

    default_path = Path(__file__).resolve().parent / "default_policy.yaml"
    rules: List[Dict[str, Any]] = []
    try:
        data = _load_yaml(default_path) or {}
        for r in data.get("rules", []):
            rid = r.get("id")
            if not rid:
                continue
            locked = is_floor_protected_rule(rid, r)
            self_protect = is_self_protection_rule(rid)
            requested_enabled = rid not in disabled
            enabled = True if locked else requested_enabled
            mode = modes.get(rid, "")
            rules.append({
                "id": rid,
                "severity": r.get("severity", "MEDIUM"),
                "category": r.get("category", ""),
                "title": r.get("title", rid),
                "action": r.get("action", ""),
                "enabled": enabled,
                "locked": locked,
                "selfProtect": self_protect,
                "requestedEnabled": requested_enabled,
                # What this rule does right now: stop the call, or report it.
                "mode": mode,
                "blocks": bool(enabled and mode == "enforce"),
                "lockReason": (
                    "Prismor guards its own configuration with this rule — it always blocks."
                    if self_protect else
                    "Pinned by Prismor's core safety floor and cannot be disabled at the project level."
                    if locked else ""
                ),
            })
    except Exception:
        pass
    return rules


def set_project_rule_states(workspace: Path, disabled_ids: List[str]) -> Dict[str, Any]:
    """Persist per-rule enable/disable to the project policy, preserving any
    other settings (mode, allowlists) already in the file. ``disabled_ids`` is
    the list of rule ids to turn off; everything else stays enabled."""
    if not workspace:
        return {"ok": False, "error": "workspace required"}
    from prismor.runtime.policy_engine import _load_yaml, is_floor_protected_rule

    ppath = _project_policy_path(workspace)
    data: Dict[str, Any] = {}
    if ppath.exists():
        try:
            loaded = _load_yaml(ppath)
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}

    default_rules_by_id: Dict[str, Dict[str, Any]] = {}
    try:
        default_path = Path(__file__).resolve().parent / "default_policy.yaml"
        default_data = _load_yaml(default_path) or {}
        default_rules_by_id = {
            str(rule.get("id")): rule
            for rule in default_data.get("rules", [])
            if isinstance(rule, dict) and rule.get("id")
        }
    except Exception:
        default_rules_by_id = {}

    data.setdefault("version", "1.0")
    seen: List[str] = []
    ignored: List[str] = []
    wanted_off: List[str] = []
    for rid in disabled_ids or []:
        if not rid or rid in seen:
            continue
        seen.append(rid)
        if is_floor_protected_rule(rid, default_rules_by_id.get(rid)):
            ignored.append(rid)
            continue
        wanted_off.append(rid)

    # Merge into the existing entries rather than replacing them. The rules
    # block also carries the per-rule `mode` that `prismor setup --mode enforce`
    # writes to record which rules were chosen to block, and rewriting the block
    # from the enable/disable list alone would silently discard that selection.
    existing: List[Dict[str, Any]] = [
        dict(r) for r in (data.get("rules") or []) if isinstance(r, dict) and r.get("id")
    ]
    by_id = {str(r["id"]): r for r in existing}
    for rid in wanted_off:
        by_id.setdefault(rid, {"id": rid})
        by_id[rid]["enabled"] = False
    for rid, rule in by_id.items():
        if rid not in wanted_off:
            rule.pop("enabled", None)  # re-enabled: drop the override, keep mode
    rules_block = [r for r in by_id.values() if len(r) > 1]
    data["rules"] = rules_block

    try:
        import yaml
        content = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    except Exception:
        lines = [f'version: "{data.get("version", "1.0")}"', "", "rules:"]
        if rules_block:
            for r in rules_block:
                lines.append(f"  - id: {r['id']}")
                lines.append("    enabled: false")
        else:
            lines[-1] = "rules: []"
        content = "\n".join(lines) + "\n"

    result = write_policy_layer("project", content, workspace)
    if result.get("ok"):
        result["ignored"] = ignored
    return result


#: How many trail rows a session view ships after the Pre/Post merge below.
_TRAIL_ROWS = 250


def _merge_tool_phases(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fold a tool call's PreToolUse and PostToolUse rows into one.

    A hooked agent logs both phases of every call, so a session view listing
    raw events showed each command twice -- an unbroken column of pairs that
    reads as a rendering bug and buries anything else. One call is one row:
    the pre-call row carries the verdict (the point of a pre-call check), and
    the post-call row contributes what came back.

    Events arrive newest-first, so the Post phase is seen before its Pre.
    """
    merged: List[Dict[str, Any]] = []
    pending: Dict[Any, Dict[str, Any]] = {}
    for ev in events:
        phase = ev.get("agentEvent") or ""
        key = (ev.get("type"), ev.get("toolTag"), (ev.get("action") or "")[:200])
        if phase == "PostToolUse":
            pending[key] = ev
            continue
        if phase == "PreToolUse" and key in pending:
            post = pending.pop(key)
            for field in ("stdout", "stderr", "response", "content"):
                value = (post.get("artifacts") or {}).get(field)
                if value and field not in (ev.get("artifacts") or {}):
                    ev.setdefault("artifacts", {})[field] = value
            ev["phases"] = ["PreToolUse", "PostToolUse"]
        merged.append(ev)
    # A Post with no Pre in this window is still something that happened.
    for leftover in pending.values():
        merged.append(leftover)
    merged.sort(key=lambda e: e.get("tsAbs") or "", reverse=True)
    return merged[:_TRAIL_ROWS]


def get_session_scoped_detail(workspace: Path, session_id: str) -> Dict[str, Any]:
    """Return scoped rules + recent blocked findings for a session."""
    from prismor.runtime.scoped_agent import load_scoped_rules, check_scoped_rules
    scoped = load_scoped_rules(workspace, session_id)

    recent_blocked: List[Dict[str, Any]] = []
    recent_events: List[Dict[str, Any]] = []
    db = prismor_home() / "prismor.db"
    if db.exists():
        try:
            conn = sqlite3.connect(str(db), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                """
                SELECT f.title, f.category, f.severity, f.evidence, e.ts
                FROM findings f
                LEFT JOIN events e
                  ON e.session_id = f.session_id
                 AND (
                   SELECT COUNT(*)
                   FROM events e2
                   WHERE e2.session_id = e.session_id
                     AND e2.id < e.id
                 ) = COALESCE(f.event_index, 0)
                WHERE f.session_id = ?
                ORDER BY e.ts DESC LIMIT 5
                """,
                (session_id,),
            )
            recent_blocked = [
                {"title": r[0], "category": r[1], "severity": r[2], "evidence": r[3], "ts": r[4]}
                for r in cur.fetchall()
            ]
            for row in conn.execute(
                """
                WITH numbered_events AS (
                    SELECT e.*,
                           ROW_NUMBER() OVER (PARTITION BY e.session_id ORDER BY e.id) - 1 AS rn
                    FROM events e
                    WHERE e.session_id = ?
                )
                SELECT e.ts, e.type, e.agent_event, e.command_text, e.path_text,
                       e.url_text, e.raw_json, e.rn,
                       f.finding_id, f.severity, f.category, f.title, f.evidence,
                       f.enrichment_json
                FROM numbered_events e
                LEFT JOIN findings f ON f.session_id = e.session_id AND f.event_index = e.rn
                ORDER BY e.ts DESC
                LIMIT 600
                """,
                (session_id,),
            ):
                raw = {}
                try:
                    raw = json.loads(row["raw_json"] or "{}")
                except Exception:
                    raw = {}
                meta = raw.get("metadata", {}) if isinstance(raw, dict) else {}
                tool_tag = meta.get("tool_name") if isinstance(meta, dict) else ""
                finding_id = row["finding_id"]
                severity = row["severity"]
                category = row["category"]
                title = row["title"]
                evidence = row["evidence"]
                enrichment = {}
                if row["enrichment_json"]:
                    try:
                        enrichment = json.loads(row["enrichment_json"])
                    except Exception:
                        enrichment = {}
                verdict = "blocked" if finding_id else "allowed"
                if not finding_id and scoped and isinstance(raw, dict):
                    inferred = check_scoped_rules(scoped, raw, session_id=session_id)
                    if inferred:
                        finding_id = inferred.get("id") or "scoped-agent"
                        severity = inferred.get("severity") or "HIGH"
                        category = inferred.get("category") or "scoped_agent"
                        title = inferred.get("title") or "Scoped agent policy blocked this event"
                        evidence = inferred.get("evidence") or ""
                        enrichment = {
                            "ruleId": inferred.get("ruleId"),
                            "action": inferred.get("action"),
                            "mode": inferred.get("mode"),
                            "source": "inferred-scoped",
                        }
                        verdict = "blocked"
                artifacts = event_artifacts(raw)
                # A prompt has no command, path or url, so the trail used to
                # describe the most informative event in a session as the bare
                # word "prompt".
                detail = (row["command_text"] or row["path_text"] or row["url_text"]
                          or artifacts.get("prompt") or artifacts.get("response") or "")
                recent_events.append({
                    "ts": _relative_time_store(row["ts"]) if row["ts"] else "",
                    "tsAbs": _absolute_time_store(row["ts"]),
                    "type": row["type"] or "",
                    "agentEvent": row["agent_event"] or "",
                    "lane": event_lane(row["type"] or "", meta if isinstance(meta, dict) else {}),
                    "artifacts": artifacts,
                    "toolTag": tool_tag or "",
                    "action": (f"{row['type']}: {' '.join(str(detail).split())[:300]}"
                               if detail else (row["type"] or "event")),
                    "verdict": verdict,
                    "severity": (severity or "low").lower(),
                    "policy": {
                        "id": finding_id or "",
                        "ruleId": enrichment.get("ruleId") or finding_id or "",
                        "category": category or "",
                        "title": title or "",
                        "evidence": evidence or "",
                        "action": enrichment.get("action") or ("block" if verdict == "blocked" else ""),
                        "mode": enrichment.get("mode") or "",
                        "source": enrichment.get("source") or ("finding" if finding_id else ""),
                    },
                })
            recent_events = _merge_tool_phases(recent_events)
            block_keys = {
                (item.get("title") or "", item.get("evidence") or "", item.get("ts") or "")
                for item in recent_blocked
            }
            for item in recent_events:
                if item.get("verdict") != "blocked":
                    continue
                policy = item.get("policy") or {}
                block = {
                    "title": policy.get("title") or "Blocked by runtime policy",
                    "category": policy.get("category") or "runtime_policy",
                    "severity": item.get("severity") or "high",
                    "evidence": policy.get("evidence") or item.get("action") or "",
                    "ts": item.get("ts") or "",
                }
                key = (block["title"], block["evidence"], block["ts"])
                if key not in block_keys:
                    recent_blocked.append(block)
                    block_keys.add(key)
            conn.close()
        except Exception:
            pass

    return {
        "session_id": session_id,
        "scoped": scoped,
        "paused": bool(scoped.get("paused")) if scoped else False,
        "policy_precedence": get_policy_precedence(workspace, scoped),
        "recent_blocked": recent_blocked,
        "recent_events": recent_events,
    }


def update_session_control(
    workspace: Path, session_id: str, action: str, data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Control session immunity.  action: 'pause' | 'resume' | 'clear' | 'update'"""
    from prismor.runtime.scoped_agent import load_scoped_rules, save_scoped_rules, clear_scoped_rules

    if action == "clear":
        clear_scoped_rules(workspace, session_id)
        return {"ok": True, "action": "clear"}

    if action == "pause":
        scoped: Dict[str, Any] = load_scoped_rules(workspace, session_id) or {}
        scoped["paused"] = True
        save_scoped_rules(workspace, session_id, scoped)
        return {"ok": True, "action": "pause", "scoped": scoped}

    if action == "resume":
        scoped = load_scoped_rules(workspace, session_id) or {}
        scoped["paused"] = False
        save_scoped_rules(workspace, session_id, scoped)
        return {"ok": True, "action": "resume", "scoped": scoped}

    if action == "update" and data:
        scoped = load_scoped_rules(workspace, session_id) or {}
        for field in ("allowed_tools", "deny_tools", "deny_network", "allowed_paths"):
            if field in data:
                scoped[field] = data[field]
        # An operator edit is authoritative: the hook stops auto-widening the
        # scope on later prompts once a human has shaped it by hand.
        scoped["operator_edited"] = True
        save_scoped_rules(workspace, session_id, scoped)
        return {"ok": True, "action": "update", "scoped": scoped}

    return {"ok": False, "error": f"unknown action: {action}"}
