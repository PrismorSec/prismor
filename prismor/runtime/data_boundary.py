"""Data boundary: sensitive-datum × destination screening for outbound calls.

An agent following third-party documentation (a setup guide, a ``SKILL.md``)
will happily run whatever the doc says — including commands that ship the
user's own email, phone number, or credentials to a service the user never
approved. The egress engine (:mod:`prismor.runtime.egress`) decides *whether a
host may be contacted*; this module decides *what may be sent there*.

Trigger = **non-synthetic sensitive datum** × **external / untrusted
destination**. Either half alone is not a finding: an email to your own
staging box, a ``user@example.com`` test fixture to anywhere, or a
``{"prompt": "a sunset"}`` payload to a brand-new API all pass silently.

Config shape (``settings.data_boundary`` in default_policy.yaml)::

    data_boundary:
      enabled: true
      mode: observe                 # observe | enforce
      trusted_domains: ["*.mycorp.com"]
      classes:                      # action per class, per destination tier
        email:  {trusted: allow, external: step_up, untrusted: redact}
        secret: {external: block}   # non-vendor destinations only
      per_domain:                   # per-class carve-outs for known vendors
        api.resend.com: {email: allow}
      bulk_threshold: 10            # ≥N distinct values of a class → bulk
      self_identity: []             # extra emails/phones that mean "me"
      unknown_cli: observe          # posture when a CLI's destination is unknown

Actions: ``allow`` (silent), ``observe`` (finding, never blocks), ``warn``,
``step_up`` (inline approval), ``redact`` (rewrite the call via the
``pii_redact`` transform; falls back to step_up for CLI flag values, since
dropping a required flag breaks the command), ``block``.

Destination tiers, resolved in order: ``internal`` (loopback / RFC1918 /
.local), ``trusted`` (``trusted_domains`` + git remotes + package registries +
a vendor's own CLI), ``untrusted`` (explicit egress deny), ``external``
(everything else). A CLI whose destination cannot be determined from argv is
``unknown`` and screened per ``unknown_cli`` — escalated to ``external`` only
when the session shows the binary was installed this session or a doc from
that vendor was just fetched (the "follow the SKILL.md" shape).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlparse

from prismor.runtime.egress import (
    Destination,
    EgressPolicy,
    _ENV_ASSIGN_RE,
    _HTTP_CMDS,
    _SHELL_SEP_RE,
    _URL_RE,
    _looks_like_host,
    _split_host_port,
    _tokenize,
)

__all__ = [
    "CATEGORY",
    "DataBoundaryPolicy",
    "Match",
    "Outbound",
    "classify",
    "extract_outbound",
    "redact_command",
]

CATEGORY = "data_boundary"

RULE_PII_EXTERNAL = "pii-to-external"
RULE_PII_UNTRUSTED = "pii-to-untrusted"
RULE_SELF_EXTERNAL = "self-identity-to-external"
RULE_SECRET_NONVENDOR = "secret-to-non-vendor"
RULE_BULK = "bulk-pii-outbound"
RULE_FILE_UPLOAD = "file-upload-to-external"

ACTIONS = ("allow", "observe", "warn", "step_up", "redact", "block")
_ACTION_LADDER = ["allow", "observe", "warn", "step_up", "redact", "block"]
TIERS = ("internal", "trusted", "external", "untrusted", "unknown")

# ── Sensitive-datum classifier ────────────────────────────────────────────────

_EMAIL_RE = re.compile(
    r'(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63})(?![A-Za-z0-9\-])'
)
# E.164 with explicit '+', or a keyed local-format phone. Bare digit runs never
# fire (version strings, timestamps, ports, order ids).
_PHONE_E164_RE = re.compile(r'(?<![\w.])\+[1-9]\d{1,2}[\s.\-]?\(?\d{2,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}\b')
_PHONE_LOCAL_RE = re.compile(r'\(?[2-9]\d{2}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b')
_PHONE_KEYS = ("phone", "mobile", "tel", "cell", "sms", "whatsapp", "msisdn")
_SSN_RE = re.compile(r'\b(?!000|666|9\d{2})\d{3}[-.\s](?!00)\d{2}[-.\s](?!0000)\d{4}\b')
_SSN_KEYS = ("ssn", "social", "tax_id", "taxid", "tin", "national_id")
_CARD_RE = re.compile(r'\b(?:\d[ \-]?){13,19}\b')
_IBAN_RE = re.compile(r'\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}[ ]?[A-Z0-9]{1,4}\b')

# Placeholder / fixture values that documentation and tests use. Never a
# finding on their own.
_SYNTHETIC_EMAIL_DOMAINS = (
    "example.com", "example.org", "example.net", "example.io", "example.dev",
    "test.com", "test.local", "email.com", "domain.com", "mail.com", "foo.com",
    "bar.com", "acme.com", "acme.io", "yourdomain.com", "your-domain.com",
    "company.com", "site.com", "mycompany.com", "placeholder.com",
)
_SYNTHETIC_TLDS = (".test", ".invalid", ".localhost", ".example", ".local")
_SYNTHETIC_LOCALPARTS = (
    "user", "test", "you", "your", "name", "email", "someone", "foo", "bar",
    "john.doe", "jane.doe", "johndoe", "janedoe", "admin", "example", "me",
    "your-email", "your_email", "yourname", "your.name", "first.last",
    "firstname.lastname", "noreply", "no-reply",
)
# Network test PANs (issuer sandboxes) — never real cards.
_TEST_PANS = frozenset({
    "4111111111111111", "4242424242424242", "4000056655665556", "5555555555554444",
    "5105105105105100", "378282246310005", "371449635398431", "6011111111111117",
    "6011000990139424", "3530111333300000", "4012888888881881", "4222222222222",
})
_PLACEHOLDER_RE = re.compile(r'^(?:<[^>]+>|\{\{[^}]+\}\}|\$\{?[A-Z_][A-Z0-9_]*\}?|[A-Z][A-Z0-9_\-]{3,}|\[[^\]]+\]|x{3,}|\.{3})$')


class Match:
    """One classified sensitive value in a payload."""

    __slots__ = ("kind", "value", "start", "end", "synthetic", "is_self", "context", "vendor")

    def __init__(self, kind: str, value: str, start: int, end: int, *,
                 synthetic: bool = False, self_: bool = False, context: str = "") -> None:
        self.kind = kind
        self.value = value
        self.start = start
        self.end = end
        self.synthetic = synthetic
        self.is_self = self_
        self.context = context   # "flag" | "query" | "body" | "header" | "text"
        self.vendor = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "synthetic": self.synthetic, "self": self.is_self,
            "context": self.context, "masked": mask(self.value),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"Match({self.kind}, {mask(self.value)!r}, synthetic={self.synthetic}, self={self.is_self})"


def mask(value: str) -> str:
    """Show enough of a value to recognise it, never the whole thing."""
    v = str(value)
    if "@" in v:
        local, _, dom = v.partition("@")
        return f"{local[:1]}***@{dom}"
    if len(v) <= 4:
        return "***"
    return f"{v[:2]}{'*' * min(len(v) - 4, 8)}{v[-2:]}"


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_synthetic_email(addr: str) -> bool:
    local, _, dom = addr.lower().rpartition("@")
    if not dom:
        return True
    if dom in _SYNTHETIC_EMAIL_DOMAINS or dom.endswith(_SYNTHETIC_TLDS):
        return True
    if any(dom.endswith("." + d) for d in _SYNTHETIC_EMAIL_DOMAINS):
        return True
    if local in _SYNTHETIC_LOCALPARTS or _PLACEHOLDER_RE.match(local):
        return True
    # user1@…, test42@…, foo+bar@example…
    if re.match(r'^(?:user|test|demo|sample|dummy|fake)[\-_.]?\d*$', local):
        return True
    return False


def _keyed(text: str, start: int, keys: Sequence[str]) -> bool:
    """True when one of ``keys`` appears just before ``start`` (``phone=``, ``--phone``, ``"phone":``)."""
    window = text[max(0, start - 40):start].lower()
    return any(k in window for k in keys)


def _self_values(policy: Optional["DataBoundaryPolicy"]) -> Set[str]:
    return set(policy.self_identity) if policy is not None else set()


def classify(
    text: str,
    *,
    policy: Optional["DataBoundaryPolicy"] = None,
    context: str = "text",
    keyed_only: bool = False,
) -> List[Match]:
    """Classify sensitive values in ``text``.

    ``keyed_only`` restricts phone/SSN to keyed occurrences (used for free-form
    command text where bare digit runs are noise). Email, card (Luhn), IBAN and
    secrets always classify. Synthetic/placeholder values are returned with
    ``synthetic=True`` so callers can count them without acting on them.
    """
    if not text:
        return []
    out: List[Match] = []
    selfset = {s.lower() for s in _self_values(policy)}

    for m in _EMAIL_RE.finditer(text):
        val = m.group(1)
        # Skip scp/git `user@host:` and mailto-less `user@host` without a TLD is
        # already excluded by the regex; skip when the "email" is followed by ':'
        # + path (scp) since that is a host, not an address.
        tail = text[m.end():m.end() + 1]
        if tail == ":" and "/" in text[m.end():m.end() + 40]:
            continue
        out.append(Match("email", val, m.start(1), m.end(1),
                         synthetic=_is_synthetic_email(val),
                         self_=val.lower() in selfset, context=context))

    for m in _PHONE_E164_RE.finditer(text):
        val = m.group(0)
        digits = re.sub(r'\D', '', val)
        synth = digits[1:4] == "555" or digits.endswith("5550100") or len(set(digits)) <= 2
        out.append(Match("phone", val, m.start(), m.end(), synthetic=synth,
                         self_=digits in selfset, context=context))
    for m in _PHONE_LOCAL_RE.finditer(text):
        if not _keyed(text, m.start(), _PHONE_KEYS):
            continue
        val = m.group(0)
        digits = re.sub(r'\D', '', val)
        synth = digits[3:6] == "555" or len(set(digits)) <= 2
        out.append(Match("phone", val, m.start(), m.end(), synthetic=synth,
                         self_=digits in selfset, context=context))

    for m in _SSN_RE.finditer(text):
        if not _keyed(text, m.start(), _SSN_KEYS):
            continue
        val = m.group(0)
        synth = val.replace("-", "").replace(".", "").replace(" ", "") in ("123456789", "078051120")
        out.append(Match("ssn", val, m.start(), m.end(), synthetic=synth, context=context))

    for m in _CARD_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if not 13 <= len(digits) <= 19 or not _luhn(digits):
            continue
        # Issuer prefixes only — otherwise any Luhn-valid id (IMEI, tracking) fires.
        if not re.match(r'^(?:4|5[1-5]|2[2-7]|3[47]|6011|65|35)', digits):
            continue
        out.append(Match("card", raw, m.start(), m.end(),
                         synthetic=digits in _TEST_PANS, context=context))

    for m in _IBAN_RE.finditer(text):
        raw = m.group(0)
        compact = raw.replace(" ", "")
        if len(compact) < 15 or not _iban_ok(compact):
            continue
        out.append(Match("iban", raw, m.start(), m.end(),
                         synthetic=compact.upper() in ("GB82WEST12345698765432", "DE89370400440532013000"),
                         context=context))

    for m, secret_kind in _iter_secrets(text):
        sm = Match("secret", m.group(0), m.start(), m.end(), context=context)
        sm.vendor = secret_kind
        out.append(sm)

    for m in _CONNECTION_CREDS_RE.finditer(text):
        sm = Match("secret", m.group(0), m.start(), m.end(), context=context,
                   synthetic=_is_synthetic_creds(m.group("user"), m.group("secret"),
                                                 m.group("host") or ""))
        sm.vendor = "custom"
        out.append(sm)

    # Drop overlaps (a card inside an IBAN, etc.) keeping the earliest/longest.
    out.sort(key=lambda x: (x.start, -(x.end - x.start)))
    dedup: List[Match] = []
    last_end = -1
    for x in out:
        if x.start < last_end:
            continue
        dedup.append(x)
        last_end = x.end
    return dedup


def _iban_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    try:
        n = int("".join(str(int(c, 36)) for c in s))
    except ValueError:
        return False
    return n % 97 == 1


# Secret prefix → the vendor domain(s) that legitimately receive it. Sending
# a Stripe key to api.stripe.com is the point of having one; sending it
# anywhere else is exfiltration.
SECRET_VENDORS: Dict[str, Tuple[str, ...]] = {
    "stripe": ("stripe.com",),
    "github": ("github.com", "githubusercontent.com", "ghcr.io"),
    "aws": ("amazonaws.com", "aws.amazon.com"),
    "google": ("googleapis.com", "google.com", "firebaseio.com"),
    "slack": ("slack.com",),
    "gitlab": ("gitlab.com",),
    "jwt": (),          # bearer of unknown origin — vendor cannot be inferred
    "custom": (),
}
_SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}'), "stripe"),
    (re.compile(r'\b(?:github_pat_[0-9a-zA-Z_]{20,}|gh[pousr]_[0-9a-zA-Z]{36})'), "github"),
    (re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), "aws"),
    (re.compile(r'\bAIza[0-9A-Za-z_\-]{35}'), "google"),
    (re.compile(r'\bxox[bpoar]-[0-9]+-[0-9]+-[0-9a-zA-Z]{24,}'), "slack"),
    (re.compile(r'\bglpat-[0-9a-zA-Z_\-]{20,}'), "gitlab"),
    (re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'), "jwt"),
]

#: Credentials embedded in a connection URI — ``scheme://user:password@host``.
#: A hardcoded DSN is one of the most common ways a real credential sits in
#: ordinary source (and in build output, stack traces and `env` dumps), and no
#: vendor-prefix pattern above can catch it because the password is arbitrary.
#:
#: Only the ``user:password@`` span is matched, not the whole URI, so redaction
#: leaves the scheme and host intact — the reader still learns *which* database
#: is being talked to, which is usually the point of reading the line, while the
#: credential is gone.
#:
#: The username is held to an identifier charset rather than "any non-delimiter".
#: A permissive class also matches inside regex literals — ``r"ssh://(?:git@)?"``
#: yields user ``(?``, secret ``git`` — and redacting a regex in a file the model
#: is reading corrupts the source it is about to edit. Silently breaking an Edit
#: is a worse outcome than missing an exotic username, so the charset is strict.
_CONNECTION_CREDS_RE = re.compile(
    r'(?<=://)(?P<user>[A-Za-z0-9_.+\-%]{1,64}):(?P<secret>[^\s:/@"\'<>]{3,128})@'
    r'(?=(?P<host>[^\s/:"\'<>]+))'
)

#: Documentation and templates are full of ``postgres://user:password@localhost``.
#: Redacting those corrupts examples and trains people to ignore the output, so
#: an obvious placeholder credential is classified but marked synthetic.
_PLACEHOLDER_CREDS = frozenset({
    "password", "passwd", "pass", "secret", "changeme", "your_password",
    "your-password", "yourpassword", "mypassword", "hunter2", "xxxx", "xxx",
    "pwd", "test", "example", "placeholder", "redacted", "none", "null",
})

#: Credentials for the loopback interface are development fixtures by
#: construction — nobody off the machine can use them — and they show up in
#: docker-compose files, dev scripts and READMEs that people genuinely need to
#: read back verbatim.
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal")  # a host list, not a bind  # nosec B104

#: ``{db_pw}`` — a str.format template slot. _PLACEHOLDER_RE covers ``{{...}}``
#: and ``${...}`` but not the single-brace form used by Python templates.
_FORMAT_SLOT_RE = re.compile(r'^\{[A-Za-z_][A-Za-z0-9_]*\}$')


def _is_synthetic_creds(user: str, secret: str, host: str = "") -> bool:
    low = secret.lower()
    if low in _PLACEHOLDER_CREDS or user.lower() in ("user", "username", "youruser"):
        return True
    if _FORMAT_SLOT_RE.match(secret):
        return True
    bare = host.split("@")[-1].split(":")[0].strip("[]").lower()
    if bare in _LOOPBACK_HOSTS:
        return True
    # ${DB_PASS}, {{password}}, <password>, $PASSWORD, ALL_CAPS_TOKEN
    return bool(_PLACEHOLDER_RE.match(secret))


def _iter_secrets(text: str) -> Iterable[Tuple[re.Match, str]]:
    for pat, kind in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            yield m, kind
    # Org custom cloak patterns (best-effort; never fail classification).
    try:
        from prismor.runtime.cloaking.patterns import list_custom_patterns
        for raw in list_custom_patterns():
            try:
                for m in re.compile(raw).finditer(text):
                    yield m, "custom"
            except re.error:
                continue
    except Exception:
        return


# ── Outbound payload extraction ───────────────────────────────────────────────

class Outbound:
    """One outbound call: destination + the data pieces travelling with it."""

    __slots__ = ("dest", "tool", "parts", "files", "segment", "known_vendor")

    def __init__(self, dest: Optional[Destination], tool: str, segment: str, *,
                 known_vendor: bool = False) -> None:
        self.dest = dest              # None when the tool's destination is unknown
        self.tool = tool
        self.parts: List[Tuple[str, str]] = []   # (context, text)
        self.files: List[str] = []               # uploaded local file paths
        self.segment = segment
        self.known_vendor = known_vendor

    def add(self, context: str, text: str) -> None:
        if text:
            self.parts.append((context, text))

    def __repr__(self) -> str:  # pragma: no cover
        return f"Outbound({self.tool}, dest={self.dest and self.dest.host}, parts={len(self.parts)})"


# Tools that never send anything anywhere on their own. PII in their argv is
# not outbound (git author, gpg identity, openssl subject, …).
LOCAL_TOOLS = frozenset({
    "git", "gpg", "gpg2", "openssl", "ssh-keygen", "ssh-add", "docker", "podman",
    "make", "cmake", "cargo", "go", "python", "python3", "node", "npm", "npx", "pnpm",
    "yarn", "bun", "pip", "pip3", "poetry", "uv", "brew", "apt", "apt-get", "dnf",
    "yum", "echo", "printf", "cat", "grep", "rg", "sed", "awk", "jq", "yq", "cut",
    "sort", "uniq", "head", "tail", "less", "more", "tee", "touch", "mkdir", "cp",
    "mv", "rm", "ls", "find", "xargs", "test", "true", "false", "export", "source",
    "cd", "pwd", "env", "printenv", "which", "type", "chmod", "chown", "ln", "date",
    "sleep", "tar", "zip", "unzip", "gzip", "gunzip", "base64", "md5sum", "sha256sum",
    "shasum", "diff", "patch", "wc", "tr", "read", "eval", "exec", "sh", "bash", "zsh",
    "code", "vim", "nvim", "nano", "open", "kill", "ps", "top", "sqlite3", "psql", "mysql",
    "prismor", "claude", "codex",
})
# `git push`/`npm publish` do contact a remote, but the remote is a VCS host /
# package registry the user already trusts by construction; see trusted seeding.

# CLI wrappers whose network destination is fixed and knowable from the binary.
KNOWN_CLI_VENDORS: Dict[str, str] = {
    "gh": "github.com", "hub": "github.com", "glab": "gitlab.com",
    "aws": "amazonaws.com", "gcloud": "googleapis.com", "gsutil": "googleapis.com",
    "az": "azure.com", "vercel": "vercel.com", "wrangler": "cloudflare.com",
    "flyctl": "fly.io", "fly": "fly.io", "heroku": "heroku.com", "netlify": "netlify.com",
    "railway": "railway.app", "render": "render.com", "stripe": "stripe.com",
    "twilio": "twilio.com", "sendgrid": "sendgrid.com", "doppler": "doppler.com",
    "op": "1password.com", "vault": "", "kubectl": "", "helm": "", "terraform": "",
    "supabase": "supabase.com", "firebase": "firebase.google.com", "planetscale": "planetscale.com",
    "pscale": "planetscale.com", "neonctl": "neon.tech", "turso": "turso.tech",
    "openai": "openai.com", "anthropic": "anthropic.com", "hf": "huggingface.co",
    "huggingface-cli": "huggingface.co", "wandb": "wandb.ai", "modal": "modal.com",
    "replicate": "replicate.com", "linear": "linear.app", "slack": "slack.com",
    "certbot": "letsencrypt.org", "snyk": "snyk.io", "sentry-cli": "sentry.io",
    "datadog-ci": "datadoghq.com", "posthog": "posthog.com", "resend": "resend.com",
    "acme": "acme.example",
}
# Registries / VCS hosts trusted by default: publishing there is normal.
DEFAULT_TRUSTED = (
    "github.com", "*.github.com", "githubusercontent.com", "*.githubusercontent.com",
    "gitlab.com", "*.gitlab.com", "bitbucket.org", "*.bitbucket.org",
    "registry.npmjs.org", "*.npmjs.org", "pypi.org", "*.pypi.org", "files.pythonhosted.org",
    "crates.io", "*.crates.io", "rubygems.org", "proxy.golang.org", "sum.golang.org",
    "*.docker.io", "docker.io", "ghcr.io", "hub.docker.com",
)

# CLI flags whose value is a datum worth classifying, whatever the tool.
_DATA_FLAG_RE = re.compile(
    r'^--?(?:e|email|mail|user-?email|phone|mobile|tel|name|full-?name|first-?name|last-?name|'
    r'address|street|city|zip|postal|ssn|dob|birth-?date|card|cc|token|api-?key|key|secret|password|pass|pw|'
    r'auth|bearer|u|user|username|login|account|customer|contact|to|from|recipient|body|data|json|payload|input|i|d)$',
    re.IGNORECASE,
)
_CURL_DATA_FLAGS = ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json")
_CURL_FORM_FLAGS = ("-F", "--form", "--form-string")
_CURL_UPLOAD_FLAGS = ("-T", "--upload-file")
_CURL_HEADER_FLAGS = ("-H", "--header")
_CURL_AUTH_FLAGS = ("-u", "--user", "--oauth2-bearer")
_CURL_PROXY_FLAGS = ("-x", "--proxy")
_CURL_VALUE_FLAGS = frozenset(
    _CURL_DATA_FLAGS + _CURL_FORM_FLAGS + _CURL_UPLOAD_FLAGS + _CURL_HEADER_FLAGS + _CURL_AUTH_FLAGS
    + _CURL_PROXY_FLAGS + ("-o", "--output", "-X", "--request", "-A", "--user-agent", "-e", "--referer",
                           "-b", "--cookie", "-c", "--cookie-jar", "-m", "--max-time", "--connect-timeout",
                           "-w", "--write-out", "--retry", "--cacert", "--cert", "--key", "-K", "--config",
                           "--url", "--resolve", "--interface", "--limit-rate", "-r", "--range", "--proto")
)
_MAX_FILE_BYTES = 256 * 1024


def _read_file_capped(path: str) -> str:
    try:
        from pathlib import Path as _P
        p = _P(path).expanduser()
        if not p.is_file():
            return ""
        with p.open("rb") as fh:
            data = fh.read(_MAX_FILE_BYTES)
        return data.decode("utf-8", "replace")
    except Exception:
        return ""


def _dest_from_url(url: str) -> Optional[Destination]:
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.hostname or ""
    except Exception:
        return None
    if not host:
        return None
    return Destination(host, parsed.port, parsed.scheme or "https", "url", url)


def _split_argv_prefix(tokens: List[str]) -> List[str]:
    while tokens and _ENV_ASSIGN_RE.match(tokens[0]):
        tokens.pop(0)
    if not tokens:
        return tokens
    argv0 = tokens[0].rsplit("/", 1)[-1].lower()
    if argv0 in ("sudo", "env", "command", "nohup", "time", "doas", "npx", "bunx", "pnpx", "uvx"):
        tokens = tokens[1:]
        while tokens and (_ENV_ASSIGN_RE.match(tokens[0]) or tokens[0].startswith("-")):
            tokens.pop(0)
    return tokens


def _query_text(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
    except Exception:
        return ""
    if not parsed.query:
        return ""
    return " ".join(f"{k}={unquote(v)}" for k, v in parse_qsl(parsed.query, keep_blank_values=True))


def _http_outbound(argv0: str, args: List[str], segment: str) -> Optional[Outbound]:
    """Decompose a curl/wget/httpie call into destination + payload parts."""
    dest: Optional[Destination] = None
    ob = Outbound(None, argv0, segment)
    i = 0
    proxy_hosts: Set[str] = set()
    while i < len(args):
        tok = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        # --flag=value form
        flag, eq, inline = tok.partition("=") if tok.startswith("--") else (tok, "", "")
        val = inline if eq else nxt
        consumed = 0 if eq else 1
        if flag in _CURL_PROXY_FLAGS:
            proxy_hosts.add((val.split("://")[-1]).split("/")[0].split(":")[0])
            i += 1 + consumed
            continue
        if flag in _CURL_DATA_FLAGS:
            if val.startswith("@") and len(val) > 1:
                ob.files.append(val[1:])
                ob.add("body", _read_file_capped(val[1:]))
            else:
                ob.add("body", val)
            i += 1 + consumed
            continue
        if flag in _CURL_FORM_FLAGS:
            # name=@file uploads the file; name=<file reads it; else literal.
            k, _, v = val.partition("=")
            if v.startswith("@") or v.startswith("<"):
                ob.files.append(v[1:].split(";")[0])
                ob.add("body", f"{k}={_read_file_capped(v[1:].split(';')[0])}")
            else:
                ob.add("body", val)
            i += 1 + consumed
            continue
        if flag in _CURL_UPLOAD_FLAGS:
            ob.files.append(val)
            ob.add("body", _read_file_capped(val))
            i += 1 + consumed
            continue
        if flag in _CURL_HEADER_FLAGS:
            ob.add("header", val)
            i += 1 + consumed
            continue
        if flag in _CURL_AUTH_FLAGS:
            ob.add("header", val)
            i += 1 + consumed
            continue
        if flag == "--url":
            dest = dest or _dest_from_url(val)
            ob.add("query", _query_text(val))
            i += 1 + consumed
            continue
        if flag in _CURL_VALUE_FLAGS:
            i += 1 + consumed
            continue
        if tok.startswith("-"):
            i += 1
            continue
        # positional: URL or bare host
        if "://" in tok:
            d = _dest_from_url(tok)
            if d is not None and d.host not in proxy_hosts:
                dest = dest or d
                ob.add("query", _query_text(tok))
        else:
            head = tok.split("/")[0]
            h, p = _split_host_port(head)
            if _looks_like_host(h):
                dest = dest or Destination(h, p, "", "http-cmd", segment)
                ob.add("query", _query_text(tok))
        i += 1
    if argv0 in ("http", "https", "xh", "httpie"):
        # httpie: positional key=value / key:=json / key:header / key==query pairs
        for tok in args:
            if tok.startswith("-") or "://" in tok:
                continue
            if "==" in tok:
                ob.add("query", tok.replace("==", "="))
            elif ":=" in tok or "=" in tok:
                ob.add("body", tok)
            elif ":" in tok and not _looks_like_host(tok.split(":")[0]):
                ob.add("header", tok)
    ob.dest = dest
    return ob


def _generic_outbound(argv0: str, args: List[str], segment: str, vendor: str) -> Outbound:
    """A CLI wrapper: destination = vendor home (if known); data = keyed flag values."""
    dest = Destination(vendor, 443, "https", "cli", segment) if vendor else None
    ob = Outbound(dest, argv0, segment, known_vendor=bool(vendor))
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-"):
            flag, eq, inline = tok.partition("=")
            if _DATA_FLAG_RE.match(flag):
                val = inline if eq else (args[i + 1] if i + 1 < len(args) else "")
                if val and not val.startswith("-"):
                    if val.startswith("@") and len(val) > 1:
                        ob.files.append(val[1:])
                        ob.add("body", _read_file_capped(val[1:]))
                    else:
                        ob.add("flag", val)
                    i += 1 if eq else 2
                    continue
            i += 1
            continue
        # key=value positional (many CLIs), or a JSON literal argument
        if "=" in tok and not tok.startswith("{"):
            k, _, v = tok.partition("=")
            if _DATA_FLAG_RE.match("--" + k.lower()):
                ob.add("flag", v)
        elif tok.startswith("{") or tok.startswith("["):
            ob.add("body", tok)
        i += 1
    return ob


def extract_outbound(event: Dict[str, Any]) -> List[Outbound]:
    """Every outbound call in an event, with the data that travels with it."""
    etype = str(event.get("type", ""))
    out: List[Outbound] = []

    if etype == "network":
        url = str(event.get("url") or "")
        dest = _dest_from_url(url) if url else None
        ob = Outbound(dest, str((event.get("metadata") or {}).get("tool_name") or "network"), url)
        if url:
            ob.add("query", _query_text(url))
        payload = str(event.get("outbound_payload") or "")
        if payload:
            ob.add("body", payload)
        if ob.dest is not None or ob.parts:
            out.append(ob)
        return out

    if etype != "shell":
        return out
    command = str(event.get("command") or "")
    if not command:
        return out

    for sub in _SHELL_SEP_RE.split(command):
        sub = sub.strip()
        if not sub:
            continue
        tokens = _split_argv_prefix(_tokenize(sub))
        if not tokens:
            continue
        argv0 = tokens[0].rsplit("/", 1)[-1].lower()
        args = tokens[1:]
        if argv0 in _HTTP_CMDS:
            ob = _http_outbound(argv0, args, sub)
            if ob is not None:
                out.append(ob)
        elif argv0 in LOCAL_TOOLS:
            continue
        else:
            vendor = KNOWN_CLI_VENDORS.get(argv0, "")
            ob = _generic_outbound(argv0, args, sub, vendor)
            if ob.parts or ob.files:
                out.append(ob)
    return out


# ── Redaction ────────────────────────────────────────────────────────────────

def redact_command(command: str, matches: Iterable[Match]) -> Tuple[str, int]:
    """Replace each match's literal value with ``[REDACTED:<kind>]``.

    Values are substituted verbatim wherever they occur in the command (a
    payload value appears in the command text exactly once in practice; if it
    appears twice — e.g. echoed and posted — both are redacted, which is the
    safe direction). Returns ``(new_command, replacements)``.
    """
    new = command
    n = 0
    seen: Set[str] = set()
    for m in sorted(matches, key=lambda x: -len(x.value)):
        if m.synthetic or m.value in seen or not m.value:
            continue
        seen.add(m.value)
        token = f"[REDACTED:{m.kind}]"
        if m.value in new:
            n += new.count(m.value)
            new = new.replace(m.value, token)
        # URL-encoded form of the same value
        enc = m.value.replace("@", "%40").replace("+", "%2B")
        if enc != m.value and enc in new:
            n += new.count(enc)
            new = new.replace(enc, token)
    return new, n


# ── Policy ────────────────────────────────────────────────────────────────────

_DEFAULT_CLASS_ACTIONS: Dict[str, Dict[str, str]] = {
    # tier → action. Missing tier → allow (internal/trusted) or the class default.
    "email":  {"internal": "allow", "trusted": "allow", "external": "warn", "untrusted": "step_up", "unknown": "observe"},
    "phone":  {"internal": "allow", "trusted": "allow", "external": "warn", "untrusted": "step_up", "unknown": "observe"},
    "ssn":    {"internal": "allow", "trusted": "warn", "external": "block", "untrusted": "block", "unknown": "warn"},
    "card":   {"internal": "allow", "trusted": "warn", "external": "block", "untrusted": "block", "unknown": "warn"},
    "iban":   {"internal": "allow", "trusted": "warn", "external": "step_up", "untrusted": "block", "unknown": "warn"},
    # secret: only reached for NON-vendor destinations (vendor == allow).
    "secret": {"internal": "allow", "trusted": "warn", "external": "block", "untrusted": "block", "unknown": "warn"},
    "file":   {"internal": "allow", "trusted": "allow", "external": "warn", "untrusted": "step_up", "unknown": "observe"},
}


def _norm_action(a: Any, fallback: str = "observe") -> str:
    a = str(a or "").lower()
    if a == "modify":
        a = "redact"
    return a if a in ACTIONS else fallback


def escalate(action: str, steps: int = 1) -> str:
    """One rung up the ladder, capped at step_up (never invent a block/redact)."""
    if action in ("redact", "block"):
        return action
    idx = _ACTION_LADDER.index(action) if action in _ACTION_LADDER else 1
    return _ACTION_LADDER[min(idx + steps, _ACTION_LADDER.index("step_up"))]


class DataBoundaryPolicy:
    """Compiled ``settings.data_boundary``. Inert unless enabled."""

    __slots__ = ("enabled", "mode", "trusted", "classes", "per_domain", "bulk_threshold",
                 "self_identity", "unknown_cli", "source", "errors", "_trusted_policy")

    def __init__(self) -> None:
        self.enabled = False
        self.mode: Optional[str] = None
        self.trusted: List[str] = []
        self.classes: Dict[str, Dict[str, str]] = {k: dict(v) for k, v in _DEFAULT_CLASS_ACTIONS.items()}
        self.per_domain: Dict[str, Dict[str, str]] = {}
        self.bulk_threshold = 10
        self.self_identity: List[str] = []
        self.unknown_cli = "observe"
        self.source = ""
        self.errors: List[str] = []
        self._trusted_policy: Optional[EgressPolicy] = None

    @classmethod
    def from_settings(cls, settings: Dict[str, Any], *, source: str = "") -> "DataBoundaryPolicy":
        raw = settings.get("data_boundary")
        pol = cls()
        pol.source = source
        if not isinstance(raw, dict) or not raw.get("enabled"):
            return pol
        pol.enabled = True
        _mode = str(raw.get("mode") or "").lower()
        pol.mode = _mode if _mode in ("observe", "enforce") else None
        pol.trusted = [str(h).lower() for h in (raw.get("trusted_domains") or []) if str(h).strip()]
        classes = raw.get("classes")
        if isinstance(classes, dict):
            for cls_name, tiers in classes.items():
                if not isinstance(tiers, dict):
                    if str(tiers).lower() in ACTIONS:  # shorthand: email: warn
                        pol.classes.setdefault(cls_name, {}).update(
                            {t: _norm_action(tiers) for t in ("external", "untrusted", "unknown")}
                        )
                    continue
                bucket = pol.classes.setdefault(cls_name, dict(_DEFAULT_CLASS_ACTIONS.get(cls_name, {})))
                for tier, act in tiers.items():
                    if tier in TIERS:
                        bucket[tier] = _norm_action(act)
                    else:
                        pol.errors.append(f"classes.{cls_name}: unknown tier {tier!r}")
        pd = raw.get("per_domain")
        if isinstance(pd, dict):
            for host, cmap in pd.items():
                if isinstance(cmap, dict):
                    pol.per_domain[str(host).lower()] = {k: _norm_action(v) for k, v in cmap.items()}
        try:
            pol.bulk_threshold = max(2, int(raw.get("bulk_threshold", 10)))
        except (TypeError, ValueError):
            pol.errors.append("bulk_threshold must be an integer")
        pol.self_identity = [str(s).strip().lower() for s in (raw.get("self_identity") or []) if str(s).strip()]
        pol.unknown_cli = _norm_action(raw.get("unknown_cli"), "observe")
        # Compile the trusted list through the egress matcher for wildcard/CIDR support.
        pol._trusted_policy = EgressPolicy._from_dict({
            "enabled": True, "default": "deny", "allow_private": True,
            "allow": list(DEFAULT_TRUSTED) + list(pol.trusted),
        })
        return pol

    # ── tiers ─────────────────────────────────────────────────────────

    def tier(self, dest: Optional[Destination], *, egress_findings: Sequence[Dict[str, Any]] = (),
             known_vendor: bool = False, escalate_unknown: bool = False) -> str:
        if dest is None:
            return "external" if escalate_unknown else "unknown"
        if dest.is_private:
            return "internal"
        for f in egress_findings:
            if str(f.get("egressHost") or "").lower() == dest.host and f.get("ruleId") == "egress-deny":
                return "untrusted"
        if self._trusted_policy is not None:
            action, entry = self._trusted_policy.verdict(dest)
            if action == "allow" and entry is not None:
                return "trusted"
        if known_vendor and not escalate_unknown:
            # The vendor's own CLI talking to the vendor is as trusted as the
            # user's decision to install and invoke it (`certbot --email`,
            # `vercel login`). The exception is the doc-follower shape: the
            # binary was installed this session, or a doc from that vendor was
            # just fetched — then it is screened as any external destination.
            return "trusted"
        return "external"

    def action_for(self, kind: str, tier: str, host: str) -> str:
        if host:
            dom = self.per_domain.get(host.lower())
            if dom is None:
                for h, cmap in self.per_domain.items():
                    if h.startswith("*.") and (host == h[2:] or host.endswith("." + h[2:])):
                        dom = cmap
                        break
            if dom and kind in dom:
                return dom[kind]
        bucket = self.classes.get(kind) or {}
        return _norm_action(bucket.get(tier), "allow" if tier in ("internal", "trusted") else "observe")

    # ── evaluation ────────────────────────────────────────────────────

    def evaluate(
        self,
        event: Dict[str, Any],
        index: int,
        *,
        session_id: str = "",
        egress_findings: Sequence[Dict[str, Any]] = (),
        default_mode: str = "observe",
        device_mode: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
        installed_this_session: Optional[Set[str]] = None,
        first_seen: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Screen an event's outbound data. Returns policy findings.

        ``provenance`` is the freshest doc/skill taint source for the session
        (``{"kind","ref","host","index"}``) — attached to findings as context and
        used to escalate one rung when the destination matches the doc's host
        or is first-seen. ``installed_this_session`` is the set of binaries the
        session installed (npm -g / pip / brew); an unknown CLI in that set is
        screened as external. ``first_seen`` is a callable ``host -> bool``.
        """
        if not self.enabled:
            return []
        if str(event.get("type", "")) not in ("network", "shell"):
            return []
        try:
            calls = extract_outbound(event)
        except Exception:
            return []
        if not calls:
            return []

        findings: List[Dict[str, Any]] = []
        prov_host = str((provenance or {}).get("host") or "").lower()
        # `npm i -g vendor-cli && vendor setup --email …` installs and runs in
        # one command: count the same-command install as "this session".
        installed = set(installed_this_session or ())
        if str(event.get("type")) == "shell":
            installed |= installed_binaries_from_command(str(event.get("command") or ""))
        installed_this_session = installed
        for ob in calls:
            # Doc-follower shape: an unknown or vendor CLI that this session
            # installed, or whose vendor's doc was just fetched, is screened
            # as external rather than unknown/trusted.
            escalate_unknown = False
            if ob.dest is None or ob.known_vendor:
                if installed_this_session and ob.tool in installed_this_session:
                    escalate_unknown = True
                elif prov_host and ob.tool and (ob.tool in prov_host or prov_host.split(".")[0] == ob.tool):
                    escalate_unknown = True
                elif ob.dest is not None and prov_host and (ob.dest.host == prov_host or ob.dest.host.endswith("." + prov_host)):
                    escalate_unknown = True
            tier = self.tier(ob.dest, egress_findings=egress_findings,
                             known_vendor=ob.known_vendor, escalate_unknown=escalate_unknown)
            if tier == "internal":
                continue
            host = ob.dest.host if ob.dest is not None else ""

            matches: List[Match] = []
            for ctx, text in ob.parts:
                keyed_only = ctx in ("flag", "text")
                matches.extend(classify(text, policy=self, context=ctx, keyed_only=keyed_only))
            real = [m for m in matches if not m.synthetic]
            if not real and not ob.files:
                continue

            # ── secrets: vendor-aware ──
            by_kind: Dict[str, List[Match]] = {}
            for m in real:
                if m.kind == "secret":
                    vendors = SECRET_VENDORS.get(m.vendor or "custom", ())
                    if host and any(host == v or host.endswith("." + v) for v in vendors):
                        continue  # a key going home to its own vendor
                by_kind.setdefault(m.kind, []).append(m)

            # ── file uploads (a datum in their own right) ──
            if ob.files and not by_kind:
                act = self.action_for("file", tier, host)
                if act != "allow":
                    findings.append(self._finding(
                        RULE_FILE_UPLOAD, "MEDIUM", act, index, session_id, event, ob, tier,
                        [], title=f"Local file uploaded to {tier} destination {host or ob.tool}: {', '.join(ob.files[:3])}",
                        provenance=provenance, default_mode=default_mode, device_mode=device_mode,
                    ))
                continue
            if not by_kind:
                continue

            # ── choose the strongest class action ──
            chosen_action = "allow"
            chosen_kind = ""
            for kind, ms in by_kind.items():
                act = self.action_for(kind, tier, host)
                if any(m.is_self for m in ms) and kind in ("email", "phone") and tier not in ("trusted", "internal"):
                    act = escalate(act)  # your own identity is the doc-follower's likeliest leak
                if len({m.value for m in ms}) >= self.bulk_threshold:
                    act = escalate(act)
                if _ACTION_LADDER.index(act) > _ACTION_LADDER.index(chosen_action):
                    chosen_action, chosen_kind = act, kind
            if chosen_action == "allow":
                continue

            # ── provenance escalation (one rung, only when the doc points here) ──
            if provenance and chosen_action in ("observe", "warn"):
                new_host = bool(first_seen and host and first_seen(host))
                if (prov_host and host and (host == prov_host or host.endswith("." + prov_host)
                                            or prov_host.endswith("." + host))) or new_host or ob.dest is None:
                    chosen_action = escalate(chosen_action)

            # ── redact is only safe for URL/body values; flags → step_up ──
            all_ms = [m for ms in by_kind.values() for m in ms]
            if chosen_action == "redact" and any(m.context == "flag" for m in all_ms):
                chosen_action = "step_up"
            if chosen_action == "redact" and str(event.get("type")) == "network":
                chosen_action = "step_up"  # WebFetch/MCP url args are not rewritten in v1

            is_self = any(m.is_self for m in all_ms)
            bulk = any(len({m.value for m in ms}) >= self.bulk_threshold for ms in by_kind.values())
            if "secret" in by_kind:
                rule_id, sev = RULE_SECRET_NONVENDOR, "CRITICAL"
            elif bulk:
                rule_id, sev = RULE_BULK, "HIGH"
            elif is_self:
                rule_id, sev = RULE_SELF_EXTERNAL, "HIGH"
            elif tier == "untrusted":
                rule_id, sev = RULE_PII_UNTRUSTED, "HIGH"
            else:
                rule_id, sev = RULE_PII_EXTERNAL, "MEDIUM" if chosen_action in ("observe", "warn") else "HIGH"

            kinds = sorted(by_kind)
            who = "your own " if is_self else ""
            what = ", ".join(kinds)
            where = host or f"unknown destination via '{ob.tool}'"
            title = f"Outbound call sends {who}{what} to {tier} destination {where}"
            if provenance:
                title += f" (following {provenance.get('kind', 'doc')} from {prov_host or provenance.get('ref', '?')})"
            findings.append(self._finding(
                rule_id, sev, chosen_action, index, session_id, event, ob, tier, all_ms,
                title=title, provenance=provenance, default_mode=default_mode, device_mode=device_mode,
            ))
        return findings

    def _finding(self, rule_id: str, severity: str, action: str, index: int, session_id: str,
                 event: Dict[str, Any], ob: Outbound, tier: str, matches: List[Match], *,
                 title: str, provenance: Optional[Dict[str, Any]], default_mode: str,
                 device_mode: Optional[str]) -> Dict[str, Any]:
        host = ob.dest.host if ob.dest is not None else ""
        # observe never blocks; everything else follows the policy/device mode.
        if action in ("observe", "warn"):
            mode = "observe"
        else:
            mode = self.mode or device_mode or default_mode
        mode = "enforce" if str(mode).lower() == "enforce" else "observe"
        eng_action = {"observe": "warn", "warn": "warn", "step_up": "step_up",
                      "redact": "modify", "block": "block"}[action]
        fid = f"{rule_id}-{index}" + (f"-{host}" if host else "")
        finding: Dict[str, Any] = {
            "id": f"{session_id}:{fid}" if session_id else fid,
            "severity": severity,
            "category": CATEGORY,
            "title": title,
            "evidence": _truncate(", ".join(m.as_dict()["masked"] for m in matches) or ", ".join(ob.files) or ob.segment),
            "eventIndex": index,
            "ruleId": rule_id,
            "action": eng_action,
            "mode": mode,
            "dataClasses": sorted({m.kind for m in matches}) or (["file"] if ob.files else []),
            "dataSubject": "self" if any(m.is_self for m in matches) else "third_party",
            "destHost": host,
            "destTrust": tier,
            "destTool": ob.tool,
            "remediation": (
                f"Add '{host or ob.tool}' to settings.data_boundary.trusted_domains, or allow this "
                f"class for it under settings.data_boundary.per_domain, if sending this data is intended."
            ),
        }
        if eng_action == "modify":
            finding["transform"] = "pii_redact"
        if provenance:
            finding["provenance"] = {
                "kind": provenance.get("kind"), "ref": provenance.get("ref"),
                "host": provenance.get("host"), "eventIndex": provenance.get("index"),
            }
        if mode == "enforce" and self.source == "remote":
            finding["authoritative"] = True
        return finding

    def summary(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled, "mode": self.mode or "(inherit)",
            "trusted_domains": list(self.trusted), "classes": self.classes,
            "per_domain": self.per_domain, "bulk_threshold": self.bulk_threshold,
            "self_identity": [mask(s) for s in self.self_identity],
            "unknown_cli": self.unknown_cli, "source": self.source or "default",
            "errors": list(self.errors),
        }


def _truncate(value: str, max_length: int = 220) -> str:
    text = str(value).strip()
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."


# ── Self identity discovery ───────────────────────────────────────────────────

def discover_self_identity(workspace: Any = None) -> List[str]:
    """Best-effort: the user's own email(s) from git config and enrolment."""
    out: Set[str] = set()
    try:
        import subprocess
        for scope in (["--global"], []):
            r = subprocess.run(["git", "config", *scope, "user.email"], capture_output=True,
                               text=True, timeout=2, cwd=str(workspace) if workspace else None)
            if r.returncode == 0 and r.stdout.strip():
                out.add(r.stdout.strip().lower())
    except Exception:
        pass
    try:
        from prismor.runtime.enterprise.identity import load_identity
        ident = load_identity() or {}
        for k in ("email", "user_email", "owner_email"):
            v = ident.get(k)
            if isinstance(v, str) and "@" in v:
                out.add(v.strip().lower())
    except Exception:
        pass
    import os
    for k in ("PRISMOR_SELF_EMAIL", "GIT_AUTHOR_EMAIL", "EMAIL"):
        v = os.environ.get(k, "")
        if v and "@" in v:
            out.add(v.strip().lower())
    return sorted(out)


# ── Doc / skill provenance detection ──────────────────────────────────────────

_DOC_URL_RE = re.compile(r'(?:/|^)(?:SKILL|README|AGENTS|CLAUDE|INSTALL|SETUP|GETTING[_\-]?STARTED)\.md(?:$|[?#])|/docs?/|/skills?/|\.md(?:$|[?#])|/llms(?:-full)?\.txt(?:$|[?#])', re.IGNORECASE)


def doc_source_from_event(event: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """If this event loads external documentation or a skill, describe the source."""
    etype = str(event.get("type", ""))
    meta = event.get("metadata") or {}
    tool = str(meta.get("tool_name") or "")
    if tool == "Skill" or (etype == "tool_result" and tool == "Skill"):
        name = str(meta.get("skill") or (event.get("tool_input") or {}).get("skill")
                   or event.get("skill") or "") if isinstance(event.get("tool_input"), dict) else str(meta.get("skill") or "")
        return {"kind": "skill", "ref": name or "skill", "host": ""}
    url = str(event.get("url") or "")
    if etype in ("network", "tool_result") and url and _DOC_URL_RE.search(url):
        d = _dest_from_url(url)
        return {"kind": "doc", "ref": url, "host": d.host if d else ""}
    if etype == "shell":
        cmd = str(event.get("command") or "")
        for m in _URL_RE.finditer(cmd):
            full = cmd[m.start():].split()[0].strip('"\'')
            if _DOC_URL_RE.search(full):
                d = _dest_from_url(full)
                return {"kind": "doc", "ref": full, "host": d.host if d else ""}
    if etype == "file_write":
        path = str(event.get("path") or event.get("file_path") or "")
        if re.search(r'(^|/)\.claude/skills/[^/]+/SKILL\.md$', path) or path.endswith("/SKILL.md"):
            return {"kind": "skill_write", "ref": path, "host": ""}
    return None


_INSTALL_RE = re.compile(
    r'\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add)\s+(?:-g|--global)\s+(@?[\w.\-/]+)|'
    r'\b(?:pip3?|pipx|uv\s+tool)\s+install\s+([\w.\-\[\]]+)|'
    r'\bbrew\s+install\s+([\w.\-/@]+)|'
    r'\bcargo\s+install\s+([\w.\-]+)|'
    r'\bgo\s+install\s+([\w./\-@]+)',
    re.IGNORECASE,
)


def installed_binaries_from_command(command: str) -> Set[str]:
    """Guess the binary names a package-install command will put on PATH."""
    out: Set[str] = set()
    for m in _INSTALL_RE.finditer(command or ""):
        pkg = next((g for g in m.groups() if g), "")
        if not pkg:
            continue
        name = pkg.split("@")[0] if not pkg.startswith("@") else pkg[1:].split("@")[0]
        # @scope/name → name ; name[extras] → name ; a/b/c → c
        name = name.split("/")[-1].split("[")[0]
        for suffix in ("-cli", "_cli", "cli"):
            if name.endswith(suffix) and len(name) > len(suffix):
                out.add(name[: -len(suffix)].rstrip("-_"))
        out.add(name)
        # @acme-ai/cli → acme
        if pkg.startswith("@") and "/" in pkg:
            scope = pkg[1:].split("/")[0]
            out.add(scope.split("-")[0])
    return {n.lower() for n in out if n}


def redact_payload(payload: Any, *, workspace: Any = None, policy: Optional["DataBoundaryPolicy"] = None) -> Any:
    """Strip every non-synthetic classified value from a tool-argument payload.

    Walks ``str`` / ``dict`` / ``list`` / ``tuple`` recursively; every string is
    classified with the data-boundary policy (so ``self_identity`` and custom
    secret patterns apply) and each real match is replaced with
    ``[REDACTED:<kind>]``. Used after an "approve redacted" decision on the
    headless approval path, where the approver only saw masked values and the
    runtime must do the stripping itself. Non-string leaves are returned as-is.
    """
    if policy is None:
        try:
            from prismor.runtime.policy_engine import PolicyEngine
            from pathlib import Path as _P
            policy = PolicyEngine(workspace=_P(workspace) if workspace else None).data_boundary
        except Exception:
            policy = DataBoundaryPolicy()

    def _one(text: str) -> str:
        ms = [m for m in classify(text, policy=policy, context="body") if not m.synthetic]
        if not ms:
            return text
        new, _n = redact_command(text, ms)
        return new

    def _walk(x: Any) -> Any:
        if isinstance(x, str):
            return _one(x)
        if isinstance(x, dict):
            return {k: _walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [_walk(v) for v in x]
        if isinstance(x, tuple):
            return tuple(_walk(v) for v in x)
        return x

    return _walk(payload)
