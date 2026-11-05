"""Hermes-specific cloaking installer.

Installs the Prismor cloaking plugin into Hermes Agent's plugin
discovery path and registers it in the Hermes config.

Hermes discovers plugins from:
  - Bundled: <hermes-home>/plugins/<name>/plugin.yaml  (auto-loaded for kind: backend/standalone)
  - User:    ~/.hermes/plugins/<name>/plugin.yaml       (gated by plugins.enabled)
  - Project: ./.hermes/plugins/<name>/plugin.yaml       (opt-in via HERMES_ENABLE_PROJECT_PLUGINS)
  - Pip:     entry_point group hermes_agent.plugins     (auto-discovered on install)

We install as a **user plugin** at ``~/.hermes/plugins/prismor-cloak/``
and enable it via ``plugins.enabled`` in Hermes config.yaml.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_PLUGIN_NAME = "prismor-cloak"
_MARKER = "prismor-cloak"
# A source checkout keeps the plugin next to this file; the wheel can't ship a
# hyphenated non-package directory there, so it is force-included under
# prismor/runtime/data/cloaking/ instead (pyproject.toml).
_BUNDLED_PLUGIN_DIR = next(
    (d for d in (Path(__file__).resolve().parent / "hermes-plugin",
                 Path(__file__).resolve().parent.parent / "data" / "cloaking" / "hermes-plugin")
     if d.is_dir()),
    Path(__file__).resolve().parent / "hermes-plugin",
)


def _hermes_home() -> Path:
    """Resolve Hermes home directory."""
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env)
    return Path.home() / ".hermes"


def _user_plugins_dir() -> Path:
    """User plugin directory under Hermes home."""
    return _hermes_home() / "plugins"


def _plugin_install_dir() -> Path:
    """Where the plugin will be installed."""
    return _user_plugins_dir() / _PLUGIN_NAME


def _hermes_config_path() -> Path:
    """Path to Hermes config.yaml."""
    return _hermes_home() / "config.yaml"


def _read_yaml_config(path: Path) -> dict:
    """Read a YAML config file, returning empty dict on failure."""
    try:
        import yaml
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
    except Exception:
        pass
    return {}


def _write_yaml_config(path: Path, data: dict) -> None:
    """Write a YAML config file."""
    import yaml
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def _enable_plugin_in_config(name: str) -> bool:
    """Add a plugin name to Hermes' plugins.enabled list. Returns True if modified."""
    # A missing config.yaml is created: Hermes merges it over its defaults, and
    # without plugins.enabled it loads no user plugin at all.
    config_path = _hermes_config_path()
    config = _read_yaml_config(config_path)
    if not config and config_path.exists():
        return False  # unreadable or empty: never overwrite the user's file
    plugins = config.get("plugins")
    if not isinstance(plugins, dict):
        plugins = {}
        config["plugins"] = plugins
    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        enabled = []
        plugins["enabled"] = enabled
    if name in enabled:
        return False
    enabled.append(name)
    _write_yaml_config(config_path, config)
    return True


def _disable_plugin_in_config(name: str) -> bool:
    """Remove a plugin name from Hermes' plugins.enabled. Returns True if modified."""
    config_path = _hermes_config_path()
    config = _read_yaml_config(config_path)
    if not config:
        return False
    plugins = config.get("plugins")
    if not isinstance(plugins, dict):
        return False
    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        return False
    if name not in enabled:
        return False
    enabled[:] = [p for p in enabled if p != name]
    _write_yaml_config(config_path, config)
    return True


def install(
    *,
    workspace: Optional[Path] = None,
    scope: str = "user",
) -> Dict[str, Any]:
    """Install the Prismor cloaking plugin into Hermes."""
    if not _BUNDLED_PLUGIN_DIR.exists():
        raise FileNotFoundError(f"Bundled plugin source not found at {_BUNDLED_PLUGIN_DIR}")

    if scope == "project" and workspace:
        target_dir = workspace / ".hermes" / "plugins" / _PLUGIN_NAME
    else:
        target_dir = _plugin_install_dir()

    if target_dir.exists():
        shutil.rmtree(target_dir)
    shutil.copytree(_BUNDLED_PLUGIN_DIR, target_dir)

    _enable_plugin_in_config(_PLUGIN_NAME)

    # Determine secrets dir path — preserve OS-native format. Pinned in the
    # Hermes config only when chosen on purpose (see pinned_secrets_dir); the
    # plugin resolves the default from HOME itself.
    from prismor.runtime.cloaking.secrets_store import pinned_secrets_dir
    pinned = pinned_secrets_dir()
    secrets_dir_path = pinned or Path.home() / ".prismor" / "secrets"
    # The plugin auto-vaults pasted secrets under <secrets>/auto_vault.
    (secrets_dir_path / "auto_vault").mkdir(parents=True, exist_ok=True)
    for d in (secrets_dir_path, secrets_dir_path / "auto_vault"):
        try:
            d.chmod(0o700)
        except PermissionError:
            pass

    config_path = _hermes_config_path()
    config = _read_yaml_config(config_path)
    readable = bool(config) or not config_path.exists()  # never overwrite an unreadable config
    env = config.get("env", {})
    if not isinstance(env, dict):
        env = {}
    # Use os.path.normpath to preserve OS-appropriate separators
    if pinned is not None:
        env["PRISMOR_SECRETS_DIR"] = os.path.normpath(str(pinned))
    else:
        env.pop("PRISMOR_SECRETS_DIR", None)
    if env:
        config["env"] = env
    else:
        config.pop("env", None)
    if readable and (config or config_path.exists()):
        _write_yaml_config(config_path, config)

    return {
        "configPath": str(config_path),
        "pluginDir": str(target_dir),
        "hooksInstalled": [
            "pre_tool_call (decloak + secret-guard)",
            "post_tool_call (audit)",
            "transform_terminal_output (scrub)",
            "transform_tool_result (scrub)",
            "pre_gateway_dispatch (userprompt-guard)",
        ],
        "secretsDir": str(secrets_dir_path),
    }


def uninstall(
    *,
    workspace: Optional[Path] = None,
    scope: str = "user",
) -> Dict[str, Any]:
    """Remove the Prismor cloaking plugin from Hermes."""
    if scope == "project" and workspace:
        target_dir = workspace / ".hermes" / "plugins" / _PLUGIN_NAME
    else:
        target_dir = _plugin_install_dir()

    removed = False
    if target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)
        removed = True

    if _disable_plugin_in_config(_PLUGIN_NAME):
        removed = True

    config_path = _hermes_config_path()
    config = _read_yaml_config(config_path)
    env = config.get("env", {})
    if isinstance(env, dict) and "PRISMOR_SECRETS_DIR" in env:
        del env["PRISMOR_SECRETS_DIR"]
        config["env"] = env
        _write_yaml_config(config_path, config)
        removed = True

    return {"pluginDir": str(target_dir), "removed": removed}


def status(
    *,
    workspace: Optional[Path] = None,
    scope: str = "user",
) -> Dict[str, Any]:
    """Report installation state of the Hermes cloaking plugin."""
    if scope == "project" and workspace:
        target_dir = workspace / ".hermes" / "plugins" / _PLUGIN_NAME
    else:
        target_dir = _plugin_install_dir()

    secrets = os.environ.get("PRISMOR_SECRETS_DIR", str(Path.home() / ".prismor" / "secrets"))
    result: Dict[str, Any] = {
        "installed": False,
        "pluginDir": str(target_dir),
        "hooks": [],
        "secretsDir": secrets,
    }

    if not target_dir.exists():
        return result

    plugin_yaml = target_dir / "plugin.yaml"
    if not plugin_yaml.exists():
        return result

    try:
        import yaml
        manifest = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8"))
        result["hooks"] = manifest.get("hooks", [])
        result["installed"] = True
    except Exception:
        result["installed"] = True

    return result
