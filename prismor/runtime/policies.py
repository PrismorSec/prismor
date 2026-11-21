"""Prismor policy evaluation.

This module provides two evaluation paths:
  1. evaluate_event()      — legacy hardcoded patterns (kept for backward compat)
  2. PolicyEngine           — new YAML-based configurable engine (prismor.runtime.policy_engine)

The legacy patterns and evaluate_event() are preserved so that existing tests
importing DESTRUCTIVE_COMMAND_PATTERN etc. continue to work. New code should
use PolicyEngine directly.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ── Legacy compiled patterns (kept for backward compat with tests) ──────────

SENSITIVE_PATH_PATTERN = re.compile(
    r"(^|/)(\.env(\..*)?|\.npmrc|\.pypirc|id_rsa|id_ed25519|known_hosts|authorized_keys|credentials|config\.json|secrets?)(/|$)|(^|/)\.(aws|ssh|gnupg)(/|$)",
    re.IGNORECASE,
)

HIGH_RISK_WRITE_PATTERN = re.compile(
    r"(^|/)(\.github/workflows/.+\.(yml|yaml)|Dockerfile|docker-compose\.ya?ml|package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements.*\.txt|pyproject\.toml|Pipfile|Gemfile|go\.mod|Cargo\.toml|pom\.xml|build\.gradle(\.kts)?|terraform\.tfvars|\.env(\..*)?)$",
    re.IGNORECASE,
)

MANIFEST_LANGUAGE_MAP = [
    (re.compile(r"package(-lock)?\.json$|pnpm-lock\.yaml$|yarn\.lock$", re.IGNORECASE), "npm"),
    (re.compile(r"requirements.*\.txt$|pyproject\.toml$|Pipfile$", re.IGNORECASE), "python"),
    (re.compile(r"Gemfile$", re.IGNORECASE), "ruby"),
    (re.compile(r"go\.mod$", re.IGNORECASE), "go"),
    (re.compile(r"Cargo\.toml$", re.IGNORECASE), "rust"),
    (re.compile(r"pom\.xml$|build\.gradle(\.kts)?$", re.IGNORECASE), "java"),
]

PROMPT_INJECTION_PATTERN = re.compile(
    r"(?:"
    # Instruction override — direct phrase attacks
    r"ignore\s+(?:all\s+)?(?:any\s+)?(?:previous\s+)?instructions"
    r"|reveal\s+(?:your|the)\s+system\s+prompt"
    r"|developer\s+instructions"
    # Directives need an object and skip negated forms; security docs and
    # project memory say "secret exfiltration" or "never print secrets" (#591).
    # Kept in step with the prompt-injection rule in default_policy.yaml.
    r"|(?<!not\s)(?<!n't\s)(?<!never\s)\bexfiltrat(?:e|es|ing)\s+\S+"
    r"|\b(?:perform|begin|start|carry\s+out|execute)\s+(?:(?:the|an?)\s+)?exfiltration\b"
    r"|(?<!not\s)(?<!n't\s)(?<!never\s)\b(?:print|show)\s+(?:[^\n.!?;]|\.(?=\w)|\n(?![ \t\r]*\n))*"
    r"(?:secret|token|key|credential|password)(?=s?\b)(?!s?[-_])(?!s?[ \t]+(?:names|ids|counts?)\b[ \t]*(?:[.!?;]|$))"
    r"|bypass(?:es|ed|ing)?\s+guardrails"
    r"|\b(?:enter|enable|activate|switch\s+to|now\s+in)\s+(?:\w+\s+){0,2}jailbreak\b"
    r"|(?<!not\s)(?<!n't\s)(?<!never\s)\bjailbreak\s+(?:yourself|(?:(?:the|this|that|your|our|a|an)\s+)?"
    r"(?:models?|assistants?|system|chatbot|llm))\b"
    # Covert exfiltration — natural-language instructions to send data silently
    r"|(?:silently|quietly|covertly|secretly)\s+(?:send|forward|transmit|upload|share|post)\b"
    r"|without\s+(?:the\s+)?user\s+(?:knowing|noticing|seeing|being\s+aware|realizing)"
    r"|(?:forward|send|transmit|relay)\s+(?:this\s+)?(?:conversation|context|chat\s+history|transcript|session)\s+to\b"
    r"|(?:call|ping|hit|notify)\s+(?:this\s+)?(?:webhook|endpoint|callback\s+url)\s+with\s+(?:the\s+)?(?:user|conversation|context|session)"
    # Social trust exploitation
    r"|(?:appear|seem|act)\s+(?:helpful|friendly|trustworthy|cooperative)\s+(?:while|but\s+(?:actually|then)|before\s+(?:then|you))"
    r"|(?:gain|build|establish)\s+(?:the\s+)?user(?:'s)?\s+trust\s+(?:and\s+then|before|so\s+that|in\s+order\s+to)"
    r")",
    re.IGNORECASE,
)

DESTRUCTIVE_COMMAND_PATTERN = re.compile(
    r"(?:"
    r"rm\s+(?:-[a-zA-Z]*f[a-zA-Z]*\s+|(?:-[a-zA-Z]+\s+)*)(?:/\s*$|/\s+)"
    r"|sudo\s+rm\b"
    # World-writable chmod — numeric modes whose "other" digit grants write
    # (…2/3/6/7, e.g. 777, 666, 0777, 1777), plus symbolic grants of write to
    # other/all (o+w, a+w, a+rwx). Group-only and read-only modes are ignored.
    r"|chmod\s+(?:-[A-Za-z]+\s+)*[0-7]?[0-7][0-7][2367]\b"
    r"|chmod\s+(?:-[A-Za-z]+\s+)*[ugoa,+=rwxXst-]*[oa][+=][a-zX]*w"
    r"|chown\s+-R\b"
    r"|mkfs\b"
    r"|dd\s+if=.*of=/dev/(?!(?:null|zero|stdout|stderr|tty|fd/)(?:\s|$))"
    r"|shutdown\b"
    r"|reboot\b"
    r"|launchctl\s+unload\b"
    r")",
    re.IGNORECASE,
)

REMOTE_EXEC_PATTERN = re.compile(r"\b(curl|wget)\b[^|;\n]*\|\s*(bash|sh)\b", re.IGNORECASE)

SECRET_EXFIL_PATTERN = re.compile(
    r"\b(cat|sed|grep|awk)\b[^\n]*(\.env|id_rsa|id_ed25519|\.npmrc|\.pypirc|\.aws|\.ssh)[^\n]*(curl|wget|nc|scp|ftp|http)",
    re.IGNORECASE,
)

SUSPICIOUS_NETWORK_PATTERN = re.compile(
    r"(webhook\.site|ngrok-free\.app|ngrok\.io|pastebin\.com|discord(app)?\.com/api/webhooks|transfer\.sh)",
    re.IGNORECASE,
)

DOS_PATTERN = re.compile(
    r"(?:"
    r":\(\)\s*\{.*\|.*&\s*\}\s*;"
    r"|while\s+true\s*;?\s*do\b"
    r"|yes\s*\|"
    r"|dd\s+if=/dev/(zero|urandom)\b(?![^\n;&|]*\bcount=)"
    r"|cat\s+/dev/urandom\b"
    r"|\b(stress|stress-ng)\b"
    r"|ulimit\s+-[a-z]+\s+unlimited"
    r")",
    re.IGNORECASE,
)

RCE_CANARY_PATTERN = re.compile(
    r"(?:"
    r"bash\s+-i\s+>&\s*/dev/tcp/"
    r"|/dev/tcp/\d"
    r"|nc\s+.*-[a-z]*l[a-z]*\s*.*-p"
    r"|python3?\s+-c\s+.*(?:exec|eval|import\s+os)"
    r"|perl\s+-e\s+.*(?:socket|exec)"
    r"|echo\s+.*\|\s*crontab"
    r"|\*\s+\*\s+\*\s+\*\s+\*.*crontab"
    r"|\b(ncat|socat)\b.*(?:exec|listen|EXEC)"
    r"|mkfifo\s+.*\bsh\b"
    r")",
    re.IGNORECASE,
)

DB_MODIFICATION_PATTERN = re.compile(
    r"(?:"
    r"\b(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE|DELETE\s+FROM|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|INSERT\s+INTO)\b"
    r"|(?:mysql|psql|sqlite3)\s+.*(?:-e\s+|-c\s+)['\"]?\s*(?:DROP|DELETE|UPDATE|ALTER|INSERT|TRUNCATE)"
    r")",
    re.IGNORECASE,
)

DB_ACCESS_PATTERN = re.compile(
    r"(?:"
    r"\b(pg_dump|mysqldump|mongodump|redis-cli\s+--rdb)\b"
    r"|sqlite3\s+.*\.dump"
    r"|\bSELECT\b[^;]*\bFROM\b[^;]*\b(users?|accounts?|credentials?|passwords?|secrets?|tokens?|sessions?|admins?)\b"
    r"|\bCOPY\b.*\bTO\b\s+['\"]"
    r")",
    re.IGNORECASE,
)

PRIVESC_PATTERN = re.compile(
    r"(?:"
    r"chmod\s+[ugo+]*s\s"
    r"|chmod\s+[0-7]*[4-7][0-7]{2}[0-7]\s"
    r"|\bsetcap\b"
    r"|\bvisudo\b|/etc/sudoers"
    r"|usermod\s+.*-[a-zA-Z]*G\s+.*sudo"
    r"|\b(useradd|adduser)\b"
    r"|\bnsenter\b"
    r"|\bpkexec\b"
    r"|chattr\s+\+i\b"
    r")",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:"
    r"(\.\./){2,}"
    r"|/etc/(passwd|shadow|hosts|sudoers)"
    r"|/proc/self/(environ|cmdline|maps|root)"
    r"|/proc/\d+/(environ|cmdline|maps)"
    r")",
    re.IGNORECASE,
)

# Cloud IMDS (Instance Metadata Service) reconnaissance — AWS 169.254.169.254,
# GCP metadata.google.internal, and the ECS task metadata endpoint.
# Also covers numeric encoding forms used to bypass naive string checks:
#   decimal integer: 2130706433 (169.254.169.254 as uint32)
#   hex integer:     0xa9fea9fe
#   octal octets:    0251.0376.0251.0376
#   IPv6-mapped:     ::ffff:a9fe:a9fe / ::ffff:169.254.169.254
CLOUD_METADATA_PATTERN = re.compile(
    r"(?:"
    r"169\.254\.169\.254"
    r"|metadata\.google\.internal"
    r"|169\.254\.170\.2"
    r"|2130706433"                            # decimal integer encoding
    r"|0xa9fe[:\-]?a9fe"                      # hex encoding (curl accepts 0xa9fea9fe)
    r"|0251\.0376\.0251\.0376"                # octal octet encoding
    r"|::ffff:a9fe:a9fe"                      # IPv6-mapped (short hex)
    r"|::ffff:169\.254\.169\.254"             # IPv6-mapped (dotted decimal)
    r")",
    re.IGNORECASE,
)

# PII in tool outputs or prompts — SSN, credit card numbers, US phone numbers.
# Intentionally requires formatted delimiters to avoid false-positives on bare
# numeric sequences (version strings, IDs, IP addresses, etc.).
PII_PATTERN = re.compile(
    r"(?:"
    # SSN: 123-45-6789 / 123.45.6789 / 123 45 6789 (all common printed forms)
    # Negative lookaheads guard invalid AAA ranges (000, 666, 9xx) and invalid
    # group values (middle 00, last 0000) per SSA issuance rules.
    r"\b(?!000|666|9\d{2})\d{3}[-.\s](?!00)\d{2}[-.\s](?!0000)\d{4}\b"
    # Credit card: 4×4 groups (Visa/MC/Discover) with space or dash separator
    r"|\b(?:4[0-9]{3}|5[1-5][0-9]{2}|6011|6[45][0-9]{2})[-\s][0-9]{4}[-\s][0-9]{4}[-\s][0-9]{4}\b"
    # Amex: 4-6-5 groups
    r"|\b3[47][0-9]{2}[-\s][0-9]{6}[-\s][0-9]{5}\b"
    # US phone: (555) 123-4567 / 555-123-4567 / +1-555-123-4567
    r"|\b(?:\+1[-.\s])?\(?[2-9][0-9]{2}\)?[-.\s][2-9][0-9]{2}[-.\s][0-9]{4}\b"
    r")",
    re.IGNORECASE,
)

# Model parameter manipulation and tool definition tampering via prompts.
# Expanded verb list covers common synonyms (adjust, alter, configure, assign).
# The "from now on" sub-pattern catches persistent instruction framing that
# doesn't use verb+object structure (a common bypass vector).
MODEL_MANIPULATION_PATTERN = re.compile(
    r"(?:"
    r"(?:set|change|override|modify|update|adjust|alter|configure|assign)\s+(?:the\s+)?temperature\s+(?:to|=)\s*[0-9]"
    r"|(?:set|change|override|modify|update|adjust|alter|configure|assign)\s+(?:the\s+)?max_tokens\s+(?:to|=)\s*\d+"
    r"|(?:redefine|override|replace|modify|tamper\s+with)\s+(?:the\s+)?(?:tool|function)\s+(?:definition|schema|spec|list)"
    r"|(?:inject|insert|add)\s+(?:a\s+)?(?:new\s+)?tool\s+(?:definition|call)\b"
    r"|(?:prepend|append|inject)\s+(?:to\s+)?(?:the\s+)?system\s+(?:prompt|message|instruction)"
    # Persistent instruction framing — "from now on you will/must/should …"
    r"|from\s+(?:now|this\s+point)\s+on[,\s]+you\s+(?:will|must|should|are\s+to)\b"
    r"|for\s+all\s+future\s+(?:responses?|messages?|requests?|interactions?)\b"
    # sed-style model swap: s/<modelA>/<modelB>/  — catches config-file model swaps.
    r"|s/(?:gpt|claude|llama|mistral|gemini|phi|deepseek|qwen)[-\w.]*/(?:gpt|claude|llama|mistral|gemini|phi|deepseek|qwen)[-\w.]*/"
    r")",
    re.IGNORECASE,
)


def infer_manifest_language(file_path: str = "") -> Optional[str]:
    for pattern, language in MANIFEST_LANGUAGE_MAP:
        if pattern.search(file_path):
            return language
    return None


def is_manifest_path(file_path: str = "") -> bool:
    return infer_manifest_language(file_path) is not None


def evaluate_event(event: Dict[str, Any], index: int, session_id: str = "") -> List[Dict[str, Any]]:
    """Legacy evaluation using hardcoded patterns. Kept for backward compat."""
    findings: List[Dict[str, Any]] = []
    event_type = str(event.get("type", "")).lower()
    command = str(event.get("command", ""))
    file_path = str(event.get("path", ""))
    url = str(event.get("url", ""))
    combined_text = "\n".join(
        str(value)
        for value in [
            event.get("prompt"),
            event.get("response"),
            event.get("content"),
            event.get("stdout"),
            event.get("stderr"),
            # Include command so PII/model-manipulation rules can scan
            # `prismor check` shell pre-checks and agent-output text events.
            event.get("command") if event_type in {"shell", "text"} else None,
        ]
        if value
    )

    if event_type in {"prompt", "tool_result"} and PROMPT_INJECTION_PATTERN.search(combined_text):
        findings.append(
            _finding(
                finding_id=f"prompt-injection-{index}",
                severity="HIGH",
                category="prompt_injection",
                title="Prompt-injection or system-prompt extraction pattern detected",
                evidence=_truncate(combined_text),
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DESTRUCTIVE_COMMAND_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"destructive-command-{index}",
                severity="CRITICAL",
                category="destructive_command",
                title="Potentially destructive shell command detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and REMOTE_EXEC_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"remote-exec-{index}",
                severity="HIGH",
                category="remote_execution",
                title="Remote fetch-and-execute pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and SECRET_EXFIL_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"secret-exfil-{index}",
                severity="CRITICAL",
                category="secret_exfiltration",
                title="Likely secret exfiltration command detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type in {"file_read", "file_write"} and SENSITIVE_PATH_PATTERN.search(file_path):
        findings.append(
            _finding(
                finding_id=f"sensitive-path-{index}",
                severity="HIGH" if event_type == "file_read" else "CRITICAL",
                category="secret_access",
                title=f"{'Sensitive file access' if event_type == 'file_read' else 'Sensitive file write'} detected",
                evidence=file_path,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "file_write" and HIGH_RISK_WRITE_PATTERN.search(file_path):
        findings.append(
            _finding(
                finding_id=f"risky-write-{index}",
                severity="HIGH" if is_manifest_path(file_path) else "MEDIUM",
                category="risky_write",
                title="Write to high-risk file path detected",
                evidence=file_path,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "network" and SUSPICIOUS_NETWORK_PATTERN.search(url):
        findings.append(
            _finding(
                finding_id=f"suspicious-network-{index}",
                severity="HIGH",
                category="secret_exfiltration",
                title="Network call to a suspicious sink detected",
                evidence=url,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DOS_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"dos-{index}",
                severity="CRITICAL",
                category="dos_resource_exhaustion",
                title="Denial-of-service or resource exhaustion pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and RCE_CANARY_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"rce-canary-{index}",
                severity="CRITICAL",
                category="rce_canary",
                title="Remote code execution or reverse shell pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DB_MODIFICATION_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"db-modification-{index}",
                severity="HIGH",
                category="db_modification",
                title="Database modification command detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and DB_ACCESS_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"db-access-{index}",
                severity="HIGH",
                category="db_access",
                title="Database dump or sensitive table access detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type == "shell" and PRIVESC_PATTERN.search(command):
        findings.append(
            _finding(
                finding_id=f"privesc-{index}",
                severity="CRITICAL",
                category="privilege_escalation",
                title="Privilege escalation pattern detected",
                evidence=command,
                event_index=index,
                session_id=session_id,
            )
        )

    _check_path = file_path if event_type == "file_read" else command
    if event_type in {"shell", "file_read"} and _check_path and PATH_TRAVERSAL_PATTERN.search(_check_path):
        findings.append(
            _finding(
                finding_id=f"path-traversal-{index}",
                severity="HIGH",
                category="path_traversal",
                title="Path traversal or sensitive system file access detected",
                evidence=_check_path,
                event_index=index,
                session_id=session_id,
            )
        )

    _metadata_target = command if event_type == "shell" else url
    if event_type in {"shell", "network"} and _metadata_target and CLOUD_METADATA_PATTERN.search(_metadata_target):
        findings.append(
            _finding(
                finding_id=f"cloud-metadata-ssrf-{index}",
                severity="CRITICAL",
                category="reconnaissance",
                title="Cloud instance metadata endpoint access detected",
                evidence=_metadata_target,
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type in {"prompt", "tool_result", "shell", "text"} and PII_PATTERN.search(combined_text):
        findings.append(
            _finding(
                finding_id=f"pii-exposure-{index}",
                severity="HIGH",
                category="pii_exposure",
                title="Personally identifiable information (PII) detected in agent context",
                evidence=_truncate(combined_text),
                event_index=index,
                session_id=session_id,
            )
        )

    if event_type in {"prompt", "tool_result", "shell", "text"} and MODEL_MANIPULATION_PATTERN.search(combined_text):
        findings.append(
            _finding(
                finding_id=f"model-manipulation-{index}",
                severity="HIGH",
                category="model_manipulation",
                title="Model parameter manipulation or tool definition tampering attempt detected",
                evidence=_truncate(combined_text),
                event_index=index,
                session_id=session_id,
            )
        )

    return findings


def _finding(
    *,
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    evidence: str,
    event_index: int,
    session_id: str = "",
) -> Dict[str, Any]:
    prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
    return {
        "id": prefixed_id,
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "eventIndex": event_index,
    }


def _truncate(value: str, max_length: int = 220) -> str:
    text = str(value).strip()
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."
