"""`prismor elevenlabs` — put ElevenLabs voice agents behind the LLM proxy.

An ElevenLabs agent runs in ElevenLabs' cloud: there is no hook to install and
no SDK to wrap. What it does have is a **Custom LLM** setting — an
OpenAI-compatible URL the agent sends every turn to. Pointing that at
``prismor proxy`` puts each turn, and every tool call the model proposes
(webhook tools, client tools, MCP tools, and system tools like
``transfer_to_number``), through the same policy as a Bash hook, before
ElevenLabs executes anything.

Subcommands:
    status
        Every agent in the workspace: its LLM, whether it is routed through
        Prismor, and whether a backup LLM could route around it.
    connect <agent_id>... | --all  --proxy-url URL
        Mint a virtual key per agent (proxy.json), store it as an ElevenLabs
        workspace secret, switch the agent to that proxy, and turn its backup
        LLM off. The original LLM settings are saved for `disconnect`.
    disconnect <agent_id>... | --all
        Restore exactly what `connect` replaced, delete the secret, and remove
        the virtual key.

What `connect` sets, and why each matters
-----------------------------------------
* ``custom_llm.api_key`` is a *virtual* key. The real provider key stays in the
  proxy's environment; ElevenLabs never holds it, and cutting one agent off is
  deleting its key.
* ``backup_llm_config`` is set to ``disabled``. ElevenLabs falls back to its own
  models when the custom LLM errors or is slow, and those turns never reach the
  proxy — a fail-open path around every rule. Disabling it makes the proxy the
  only way the agent can think.
* ``cascade_timeout_seconds`` goes from ElevenLabs' 4s default to 8s
  (``--turn-timeout``). With the backup LLM off, a turn that has not started
  answering by then is *retried*, and each retry is screened again, so a
  verdict that briefly runs long turned into a retry storm and a silent agent.
  Keep Prismor's own share bounded too (``settings.semantic_guard.budget_ms``
  in the proxy workspace).
* ``X-Prismor-Screening: parallel`` (``--sequential-screening`` to drop it): each
  turn is judged while the model is already answering, and the reply is held
  until the verdict, so screening adds ``max(0, verdict - first token)``
  instead of the verdict's whole time. The prompt reaches the provider before
  its verdict (secrets still masked first); sequential keeps a blocked prompt
  from ever leaving, for policies whose data-boundary rules must stop the send.
* ``request_headers`` carry ``X-Prismor-Session`` = the ElevenLabs
  ``system__conversation_id``, so one phone call is one Prismor session with
  the same id ElevenLabs shows in its history, and ``X-Prismor-Refusal:
  spoken`` so a blocked turn is said to the caller as a sentence instead of a
  rule id.

The API key is read from ``ELEVENLABS_API_KEY``. Stdlib only, like the rest of
the runtime.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.proxy import default_config_path

API = os.environ.get("ELEVENLABS_API_BASE", "https://api.elevenlabs.io")

#: Header values ElevenLabs resolves per conversation.
SESSION_HEADER = {"X-Prismor-Session": {"variable_name": "system__conversation_id"},
                  "X-Prismor-Refusal": "spoken"}

#: Judge each turn while the model is already answering it; the reply is held
#: until the verdict. See ProxyHandler._start_parallel_screen for the trade.
PARALLEL_HEADER = {"X-Prismor-Screening": "parallel"}


class ElevenLabsError(RuntimeError):
    pass


# ── state ────────────────────────────────────────────────────────────────────

def state_path() -> Path:
    home = os.environ.get("PRISMOR_HOME") or str(Path.home() / ".prismor")
    return Path(home) / "elevenlabs.json"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8") or "{}")


def _write_private(path: Path, data: Dict[str, Any]) -> None:
    """Both files hold credentials (virtual keys): owner-only, written whole."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


# ── API ──────────────────────────────────────────────────────────────────────

class Client:
    def __init__(self, api_key: str, base: str = API) -> None:
        self.api_key = api_key
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, body: Any = None) -> Any:
        req = urllib.request.Request(
            self.base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"xi-api-key": self.api_key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise ElevenLabsError(f"{method} {path} -> HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise ElevenLabsError(f"{method} {path}: {exc.reason}") from None
        return json.loads(raw) if raw.strip() else {}

    def agents(self) -> List[Dict[str, Any]]:
        out, cursor = [], None
        while True:
            q = "?page_size=100" + (f"&cursor={cursor}" if cursor else "")
            page = self.call("GET", f"/v1/convai/agents{q}")
            out.extend(page.get("agents") or [])
            cursor = page.get("next_cursor")
            if not page.get("has_more") or not cursor:
                return out

    def agent(self, agent_id: str) -> Dict[str, Any]:
        return self.call("GET", f"/v1/convai/agents/{agent_id}")

    def patch_prompt(self, agent_id: str, prompt: Dict[str, Any]) -> None:
        self.call("PATCH", f"/v1/convai/agents/{agent_id}",
                  {"conversation_config": {"agent": {"prompt": prompt}}})

    def create_secret(self, name: str, value: str) -> str:
        return self.call("POST", "/v1/convai/secrets",
                         {"type": "new", "name": name, "value": value})["secret_id"]

    def delete_secret(self, secret_id: str) -> None:
        self.call("DELETE", f"/v1/convai/secrets/{secret_id}")


def _client() -> Client:
    key = os.environ.get("ELEVENLABS_API_KEY", "").strip()
    if not key:
        raise ElevenLabsError("ELEVENLABS_API_KEY is not set")
    return Client(key)


def _prompt(agent: Dict[str, Any]) -> Dict[str, Any]:
    return ((agent.get("conversation_config") or {}).get("agent") or {}).get("prompt") or {}


def _governed_by(prompt: Dict[str, Any], proxy_url: str = "") -> bool:
    if prompt.get("llm") != "custom-llm":
        return False
    url = ((prompt.get("custom_llm") or {}).get("url") or "").rstrip("/")
    if proxy_url:
        return url == _llm_url(proxy_url)
    return url in {_llm_url(a.get("proxy_url", "")) for a in
                   (_load_json(state_path()).get("agents") or {}).values()}


def _llm_url(proxy_url: str) -> str:
    base = proxy_url.rstrip("/")
    return base if base.endswith("/v1") else base + "/v1"


#: The model a connected agent runs on unless ``--model`` says otherwise.
DEFAULT_MODEL = "gpt-5.6-luna"


def body_rules(model: str) -> Dict[str, Any]:
    """Request fixes the proxy applies for this agent's virtual key.

    ElevenLabs sends ``max_tokens`` and ``temperature: 0`` on every turn. The
    GPT-5-era and o-series models refuse both -- they take
    ``max_completion_tokens`` and only the default temperature -- so without
    this every turn of a gpt-5.6-luna agent fails at OpenAI with a 400.

    GPT-5/6 also refuse function tools on chat/completions unless
    ``reasoning_effort`` is ``none``, and every agent with a tool sends them.
    ``none`` is what a voice turn wants anyway: no thinking pause before the
    agent speaks.
    """
    if model.startswith(("gpt-5", "gpt-6")):
        return {"rename": {"max_tokens": "max_completion_tokens"}, "drop": ["temperature"],
                "set": {"reasoning_effort": "none"}}
    if model.startswith(("o1", "o3", "o4")):
        return {"rename": {"max_tokens": "max_completion_tokens"}, "drop": ["temperature"]}
    return {}


# ── commands ─────────────────────────────────────────────────────────────────

def status(client: Client) -> int:
    agents = client.agents()
    if not agents:
        print("No ElevenLabs agents in this workspace.")
        return 0
    connected = (_load_json(state_path()).get("agents") or {})
    print(f"{'AGENT':38} {'NAME':34} {'LLM':16} {'PRISMOR':9} BACKUP LLM")
    for summary in agents:
        aid = summary["agent_id"]
        prompt = _prompt(client.agent(aid))
        governed = _governed_by(prompt)
        backup = (prompt.get("backup_llm_config") or {}).get("preference", "default")
        llm = prompt.get("llm") or "?"
        if llm == "custom-llm":
            llm = (prompt.get("custom_llm") or {}).get("model_id") or llm
        flag = "yes" if governed else ("stale" if aid in connected else "no")
        warn = "  <- can bypass Prismor" if governed and backup != "disabled" else ""
        print(f"{aid:38} {summary.get('name', '')[:34]:34} {llm[:16]:16} {flag:9} {backup}{warn}")
    return 0


def connect(client: Client, agent_ids: List[str], proxy_url: str, *,
            model: str = "", upstream: str = "openai",
            config_path: Optional[Path] = None, keep_backup: bool = False,
            turn_timeout: float = 8.0, parallel: bool = True,
            refusal_text: str = "") -> int:
    if not 2.0 <= turn_timeout <= 15.0:
        raise ElevenLabsError("--turn-timeout must be between 2 and 15 seconds (ElevenLabs' range)")
    if not proxy_url.startswith("https://"):
        # ElevenLabs calls the URL from its own cloud and sends the virtual key
        # in the Authorization header: plain http would put it on the wire.
        raise ElevenLabsError("--proxy-url must be a public https:// URL that reaches "
                              "`prismor proxy` (a tunnel or a TLS reverse proxy)")
    config_path = config_path or default_config_path()
    proxy_cfg = _load_json(config_path)
    proxy_cfg.setdefault("keys", {})
    state = _load_json(state_path())
    state.setdefault("agents", {})
    restart = False

    for aid in agent_ids:
        agent = client.agent(aid)
        name = agent.get("name") or aid
        prompt = _prompt(agent)
        model_id = model or DEFAULT_MODEL
        key_meta: Dict[str, Any] = {"subject": f"elevenlabs:{name}", "upstream": upstream}
        if body_rules(model_id):
            key_meta["body"] = body_rules(model_id)
        if (aid in state["agents"] and _governed_by(prompt, proxy_url)
                and (prompt.get("custom_llm") or {}).get("model_id") == model_id
                and prompt.get("cascade_timeout_seconds") == turn_timeout
                and ((prompt.get("custom_llm") or {}).get("request_headers") or {}).get(
                    "X-Prismor-Screening") == ("parallel" if parallel else None)
                and ((prompt.get("custom_llm") or {}).get("request_headers") or {}).get(
                    "X-Prismor-Refusal-Text") == (refusal_text or None)
                and proxy_cfg["keys"].get(state["agents"][aid]["virtual_key"]) == key_meta):
            print(f"  = {name} ({aid}) already routed through {proxy_url} on {model_id}")
            continue
        if aid in state["agents"]:
            # Re-pointing (new tunnel URL): keep the first-saved originals, reuse the key.
            entry = state["agents"][aid]
        else:
            vkey = "pk_el_" + secrets.token_hex(16)
            entry = {
                "name": name,
                "virtual_key": vkey,
                "secret_id": client.create_secret(f"prismor_{aid}", vkey),
                "original": {
                    "llm": prompt.get("llm"),
                    "custom_llm": prompt.get("custom_llm"),
                    "backup_llm_config": prompt.get("backup_llm_config"),
                    "cascade_timeout_seconds": prompt.get("cascade_timeout_seconds"),
                },
            }
        if proxy_cfg["keys"].get(entry["virtual_key"]) != key_meta:
            restart = True
        proxy_cfg["keys"][entry["virtual_key"]] = key_meta
        _write_private(config_path, proxy_cfg)

        patch: Dict[str, Any] = {
            "llm": "custom-llm",
            "custom_llm": {
                "url": _llm_url(proxy_url),
                "model_id": model_id,
                "api_key": {"secret_id": entry["secret_id"]},
                "request_headers": {**SESSION_HEADER, **(PARALLEL_HEADER if parallel else {}),
                                    **({"X-Prismor-Refusal-Text": refusal_text} if refusal_text else {})},
                "api_type": "chat_completions",
            },
        }
        if not keep_backup:
            patch["backup_llm_config"] = {"preference": "disabled"}
        patch["cascade_timeout_seconds"] = turn_timeout
        client.patch_prompt(aid, patch)

        entry.update(proxy_url=proxy_url.rstrip("/"), connected_at=int(time.time()))
        state["agents"][aid] = entry
        _write_private(state_path(), state)
        print(f"  + {name} ({aid}) -> {_llm_url(proxy_url)}  model={patch['custom_llm']['model_id']}"
              f"{'' if keep_backup else '  backup LLM off'}")

    if restart:
        print(f"\nVirtual keys written to {config_path}. The proxy reads it once at startup:")
        print(f"restart `prismor proxy --mode enforce --config {config_path}` before the next call.")
    return 0


def disconnect(client: Client, agent_ids: List[str], *,
               config_path: Optional[Path] = None) -> int:
    config_path = config_path or default_config_path()
    proxy_cfg = _load_json(config_path)
    state = _load_json(state_path())
    agents = state.get("agents") or {}
    for aid in agent_ids:
        entry = agents.get(aid)
        if not entry:
            print(f"  ? {aid}: not connected by prismor, left alone")
            continue
        orig = entry.get("original") or {}
        # custom_llm goes back too, as null if there was none: ElevenLabs rejects
        # a custom_llm block on an agent whose llm is not custom-llm.
        restore: Dict[str, Any] = {"llm": orig.get("llm") or "gpt-4o-mini",
                                   "custom_llm": orig.get("custom_llm")}
        restore["backup_llm_config"] = orig.get("backup_llm_config") or {"preference": "default"}
        restore["cascade_timeout_seconds"] = orig.get("cascade_timeout_seconds") or 4.0
        gone = False
        try:
            client.patch_prompt(aid, restore)
        except ElevenLabsError as exc:
            if "HTTP 404" not in str(exc):
                raise
            gone = True
        try:
            client.delete_secret(entry["secret_id"])
        except ElevenLabsError as exc:
            print(f"  ! could not delete secret {entry['secret_id']}: {exc}")
        (proxy_cfg.get("keys") or {}).pop(entry.get("virtual_key", ""), None)
        agents.pop(aid)
        _write_private(config_path, proxy_cfg)
        _write_private(state_path(), state)
        print(f"  - {entry.get('name', aid)} ({aid}) "
              + ("deleted in ElevenLabs; key and secret removed" if gone
                 else f"restored to {restore['llm']}"))
    return 0


def run(args: Any) -> int:
    cmd = getattr(args, "el_command", None)
    try:
        client = _client()
        if cmd == "status":
            return status(client)
        config = Path(args.config).expanduser() if getattr(args, "config", None) else None
        if cmd in ("connect", "disconnect"):
            ids = list(args.agent_ids or [])
            if args.all:
                ids = ([a["agent_id"] for a in client.agents()] if cmd == "connect"
                       else list((_load_json(state_path()).get("agents") or {}).keys()))
            if not ids:
                print("Name at least one agent id, or pass --all.", file=sys.stderr)
                return 2
            if cmd == "connect":
                proxy_url = args.proxy_url or os.environ.get("PRISMOR_PROXY_PUBLIC_URL", "")
                if not proxy_url:
                    print("--proxy-url (or PRISMOR_PROXY_PUBLIC_URL) is required.", file=sys.stderr)
                    return 2
                return connect(client, ids, proxy_url, model=args.model or "",
                               upstream=args.upstream, config_path=config,
                               keep_backup=args.keep_backup_llm,
                               turn_timeout=args.turn_timeout,
                               parallel=not args.sequential_screening,
                               refusal_text=args.refusal_text or "")
            return disconnect(client, ids, config_path=config)
    except ElevenLabsError as exc:
        print(f"prismor elevenlabs: {exc}", file=sys.stderr)
        return 1
    print("usage: prismor elevenlabs {status,connect,disconnect}", file=sys.stderr)
    return 2
