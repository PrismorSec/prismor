"""Scan context: clock, homes, and the only ways a collector may touch the network or a process."""
from __future__ import annotations

import os
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from prismor.runtime.inventory.ids import host_id as make_host_id
from prismor.runtime.inventory.ids import user_hash

HttpFn = Callable[..., "HttpResult"]
RunFn = Callable[..., "subprocess.CompletedProcess[bytes]"]


@dataclass
class HttpResult:
    status: int
    headers: Dict[str, str]
    body: bytes

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        import json
        return json.loads(self.body.decode("utf-8"))

    def header(self, name: str) -> str:
        want = name.lower()
        for key, value in self.headers.items():
            if key.lower() == want:
                return value
        return ""


def default_http(method: str, url: str, *, headers: Optional[Dict[str, str]] = None,
                 body: Optional[bytes] = None, timeout: float = 30) -> HttpResult:
    """Stdlib HTTP. Response bodies are returned to the caller and must not be logged."""
    import urllib.error
    import urllib.request

    from prismor.runtime.http_ua import user_agent

    request = urllib.request.Request(url, data=body, headers=dict(headers or {}), method=method.upper())
    request.add_header("User-Agent", user_agent())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # operator-configured URL  # nosec B310
            raw = resp.read()
            hdrs = {k: v for k, v in resp.headers.items()}
            return HttpResult(int(resp.status), hdrs, raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read() if exc.fp else b""
        hdrs = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        return HttpResult(int(exc.code), hdrs, raw)


def default_run(argv: Sequence[str], *, timeout: float = 30,
                cwd: Optional[str] = None) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        list(argv), capture_output=True, timeout=timeout, cwd=cwd, check=False,
    )


def _now() -> datetime:
    raw = os.environ.get("PRISMOR_INVENTORY_NOW", "").strip()
    if raw:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


@dataclass
class ScanContext:
    """Everything a collector is allowed to depend on. Tests replace ``http`` and ``run``."""

    os_name: str
    workspace: Path
    homes: List[Path] = field(default_factory=list)
    run_id: str = ""
    now: datetime = field(default_factory=_now)
    org_salt: str = ""
    hash_users: bool = True
    all_users: bool = False
    hostname: str = ""
    machine_id: str = ""
    enrolled_device_id: str = ""
    http: HttpFn = default_http
    run: RunFn = default_run
    request_timeout: float = 30.0
    record_cap: int = 10000
    dry_run: bool = False
    profiles_root: Optional[Path] = None
    wsl_root: Optional[Path] = None
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    surfaces: List[str] = field(default_factory=list)
    #: The full ``inventory.yaml``. Plugin collectors read their own section.
    settings: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.run_id:
            from prismor.runtime.inventory.ids import _sha256
            self.run_id = "run_" + _sha256(self.now.isoformat() + (self.machine_id or ""))[:16]
        if not self.hostname:
            try:
                self.hostname = socket.gethostname()
            except OSError:
                self.hostname = ""
        self.workspace = Path(self.workspace)

    @property
    def observed_at(self) -> str:
        return self.now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def host_id(self) -> str:
        return make_host_id(self.machine_id, self.org_salt, self.enrolled_device_id)

    def user_token(self, username: str) -> str:
        if not username:
            username = "unknown"
        if self.hash_users:
            return user_hash(self.org_salt, username)
        return username

    def scanner_version(self) -> str:
        try:
            from prismor.runtime import __version__
            return __version__
        except Exception:
            return ""


def machine_id_default() -> str:
    """``/etc/machine-id``, IOPlatformUUID, or the Windows MachineGuid. Empty if unavailable."""
    override = os.environ.get("PRISMOR_INVENTORY_MACHINE_ID", "").strip()
    if override:
        return override
    system = os_name_default()
    if system == "linux":
        for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
            try:
                text = path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if text:
                return text
    if system == "darwin":
        try:
            proc = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, timeout=5, check=False,
            )
            text = proc.stdout.decode("utf-8", errors="replace")
            for line in text.splitlines():
                if "IOPlatformUUID" in line and "=" in line:
                    return line.split("=", 1)[1].strip().strip('"')
        except (OSError, subprocess.TimeoutExpired):
            return ""
    if system == "windows":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
            ) as key:
                value, _typ = winreg.QueryValueEx(key, "MachineGuid")
                return str(value)
        except OSError:
            return ""
    return ""


def os_name_default() -> str:
    override = os.environ.get("PRISMOR_INVENTORY_OS", "").strip().lower()
    if override in {"windows", "darwin", "linux"}:
        return override
    import platform
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "darwin"
    return "linux"
