"""Optional NER PII detection (Microsoft Presidio) beside the regex detectors.

Cloak vaults known secrets. The ``pii-exposure`` rule and the data-boundary
classifier catch formatted identifiers (SSN, card, phone, email, IBAN) with
regular expressions. Neither recognises a person's name, a street, or an NHS
number written out in a sentence. This module adds that pass.

It is off unless ``settings.pii.enabled`` is true. The default hook path never
imports Presidio and never scans, so a coding-agent hook stays on the regex
budget. When the extra is installed (``pip install "prismor[pii]"``) and the
stanza is enabled, :class:`AnalyzerEngine` is built once per process and reused.
Coding-agent hooks are a new process per call, so they pay model load each
time; long-lived surfaces (eval-server, MCP gateway, LLM proxy, framework
adapters) pay it once. If Presidio or its spaCy model is missing, detection
falls back to the regex classifier and says so once on stderr. Raw values are
never written to a finding, a warning, or a log line.
"""
from __future__ import annotations

import hashlib
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# Presidio entity types the regex fallback can approximate. PERSON, LOCATION
# and MEDICAL_LICENSE need the spaCy model; the fallback reports them as
# unsupported rather than guessing.
REGEX_ENTITIES = frozenset({
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "UK_NHS",
    "IP_ADDRESS",
})

DEFAULT_ENTITIES: Tuple[str, ...] = (
    "PERSON",
    "LOCATION",
    "MEDICAL_LICENSE",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "UK_NHS",
    "IP_ADDRESS",
)

DEFAULT_FIELDS: Tuple[str, ...] = (
    "prompt",
    "response",
    "content",
    "stdout",
    "stderr",
    "command",
    "mcp_args",
    "outbound_payload",
    "typed_text",
)

ACTIONS = ("observe", "redact", "block")
MODES = ("observe", "enforce")
MASK_STYLES = ("mask", "replace", "hash", "redact")
BACKENDS = ("presidio", "regex")

# Structured identifiers outrank a name or a street in the finding severity.
_HIGH_ENTITIES = frozenset({
    "US_SSN", "CREDIT_CARD", "UK_NHS", "IBAN_CODE", "MEDICAL_LICENSE",
    "US_PASSPORT", "US_DRIVER_LICENSE", "US_ITIN", "US_BANK_NUMBER",
    "UK_NINO",
})

_NHS_RE = re.compile(r"\b(\d{3})[\s-](\d{3})[\s-](\d{4})\b")
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def _skip_ip(value: str) -> bool:
    """Loopback, unspecified and the broadcast address are not personal data."""
    if value.startswith("127.") or value == "255.255.255.255":
        return True
    octets = value.split(".")
    return bool(octets) and octets[0] == "0"


_SSN_RE = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}[-.\s](?!00)\d{2}[-.\s](?!0000)\d{4}\b"
)
_PHONE_RE = re.compile(
    r"(?<!\w)(?:\+1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}\b"
)
_SYNTHETIC_SSN = frozenset({"123456789", "078051120", "219099999"})
_SYNTHETIC_IBAN = frozenset({
    "GB82WEST12345698765432",
    "DE89370400440532013000",
})

RULE_ID = "pii-ner"
_MAX_EVIDENCE_ENTITIES = 8


class PiiNotes(list):
    """Hit list a redactor fills in.

    ``backend`` is the detector that ran. ``scanned`` is set even when there
    were no hits, so a surface that redacts and then re-evaluates the masked
    text can skip a second model pass.
    """

    def __init__(self) -> None:
        super().__init__()
        self.backend = ""
        self.fallback = ""
        self.scanned = False


@dataclass(frozen=True)
class PiiHit:
    """One span. ``value`` stays in memory for redaction and is not serialized."""

    entity: str
    score: float
    start: int
    end: int
    value: str


@dataclass
class PiiResult:
    hits: Tuple[PiiHit, ...] = ()
    backend: str = "off"
    requested_backend: str = "presidio"
    fallback_reason: str = ""
    unsupported: Tuple[str, ...] = ()
    truncated: bool = False
    latency_ms: float = 0.0


@dataclass
class PiiSettings:
    """Resolved ``settings.pii``. Defaults match ``default_policy.yaml``."""

    enabled: bool = False
    backend: str = "presidio"
    entities: Tuple[str, ...] = DEFAULT_ENTITIES
    score_threshold: float = 0.5
    language: str = "en"
    action: str = "observe"
    mode: str = "observe"
    mask_style: str = "mask"
    model: str = "en_core_web_sm"
    max_chars: int = 4000
    fields: Tuple[str, ...] = DEFAULT_FIELDS
    errors: Tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "backend": self.backend,
            "entities": list(self.entities),
            "score_threshold": self.score_threshold,
            "language": self.language,
            "action": self.action,
            "mode": self.mode,
            "mask_style": self.mask_style,
            "model": self.model,
            "max_chars": self.max_chars,
            "fields": list(self.fields),
        }

    @classmethod
    def from_mapping(cls, raw: Any) -> "PiiSettings":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            return cls(errors=("settings.pii must be a map",))
        errors: List[str] = []
        enabled = raw.get("enabled", False)
        if not isinstance(enabled, bool):
            errors.append("settings.pii.enabled must be true or false")
            enabled = False

        backend = str(raw.get("backend", "presidio")).strip().lower()
        if backend not in BACKENDS:
            errors.append(
                f"settings.pii.backend must be one of {', '.join(BACKENDS)}"
            )
            backend = "presidio"

        entities = raw.get("entities", DEFAULT_ENTITIES)
        if not isinstance(entities, (list, tuple)) or not all(
            isinstance(e, str) and e.strip() for e in entities
        ):
            errors.append("settings.pii.entities must be a list of entity names")
            parsed_entities = DEFAULT_ENTITIES
        else:
            parsed_entities = tuple(e.strip().upper() for e in entities)

        threshold = raw.get("score_threshold", 0.5)
        try:
            threshold_f = float(threshold)
        except (TypeError, ValueError):
            errors.append("settings.pii.score_threshold must be a number")
            threshold_f = 0.5
        if not 0.0 <= threshold_f <= 1.0:
            errors.append("settings.pii.score_threshold must be between 0 and 1")
            threshold_f = 0.5

        language = str(raw.get("language", "en")).strip().lower()
        if not language or len(language) > 8 or not re.fullmatch(r"[a-z]{2,3}(-[a-z0-9]+)?", language):
            errors.append("settings.pii.language must be a short language code such as en")
            language = "en"

        action = str(raw.get("action", "observe")).strip().lower()
        if action not in ACTIONS:
            errors.append(
                f"settings.pii.action must be one of {', '.join(ACTIONS)}"
            )
            action = "observe"

        mode = str(raw.get("mode", "observe")).strip().lower()
        if mode not in MODES:
            errors.append(f"settings.pii.mode must be one of {', '.join(MODES)}")
            mode = "observe"

        style = str(raw.get("mask_style", "mask")).strip().lower()
        if style not in MASK_STYLES:
            errors.append(
                f"settings.pii.mask_style must be one of {', '.join(MASK_STYLES)}"
            )
            style = "mask"

        model = str(raw.get("model", "en_core_web_sm")).strip()
        if not model or len(model) > 80 or not re.fullmatch(r"[A-Za-z0-9_.:\-]+", model):
            errors.append("settings.pii.model must be a spaCy model name")
            model = "en_core_web_sm"

        max_chars = raw.get("max_chars", 4000)
        try:
            max_chars_i = int(max_chars)
        except (TypeError, ValueError):
            errors.append("settings.pii.max_chars must be an integer")
            max_chars_i = 4000
        if max_chars_i < 200 or max_chars_i > 50000:
            errors.append("settings.pii.max_chars must be between 200 and 50000")
            max_chars_i = 4000

        fields = raw.get("fields", DEFAULT_FIELDS)
        if not isinstance(fields, (list, tuple)) or not all(
            isinstance(f, str) and f.strip() for f in fields
        ):
            errors.append("settings.pii.fields must be a list of event field names")
            parsed_fields = DEFAULT_FIELDS
        else:
            parsed_fields = tuple(f.strip() for f in fields)

        return cls(
            enabled=bool(enabled),
            backend=backend,
            entities=parsed_entities,
            score_threshold=threshold_f,
            language=language,
            action=action,
            mode=mode,
            mask_style=style,
            model=model,
            max_chars=max_chars_i,
            fields=parsed_fields,
            errors=tuple(errors),
        )


def validate_pii_settings(raw: Any) -> List[str]:
    """Errors for ``prismor policy validate``. Empty when the stanza is usable."""
    if raw is None:
        return []
    return list(PiiSettings.from_mapping(raw).errors)


def packages_available() -> Tuple[bool, str]:
    """Whether the ``pii`` extra imports. Does not load a spaCy model."""
    missing = []
    for name in ("presidio_analyzer", "presidio_anonymizer"):
        try:
            __import__(name)
        except ImportError:
            missing.append(name)
    if missing:
        return False, "missing " + ", ".join(missing)
    return True, ""


def status_line(settings: PiiSettings) -> str:
    """One clause for ``prismor doctor``. Imports Presidio only when enabled."""
    if not settings.enabled:
        return "pii: off"
    if settings.backend == "regex":
        return f"pii: {settings.action} (regex)"
    ok, detail = packages_available()
    if not ok:
        return f"pii: {settings.action} (regex fallback, {detail})"
    return f"pii: {settings.action} (presidio, {settings.model})"


# ── engine cache ─────────────────────────────────────────────────────────────
# One AnalyzerEngine per (language, model). Entity filters are applied per call
# so a policy that only changes the entity list does not reload spaCy.

_LOCK = threading.Lock()
_ENGINES: Dict[Tuple[str, str], Any] = {}
_UNAVAILABLE: Dict[Tuple[str, str], str] = {}
_ANONYMIZER: Any = None
_ANONYMIZER_FAILED = False
_WARNED: set = set()
_analyzer_factory: Optional[Callable[[PiiSettings], Any]] = None


def reset_for_tests() -> None:
    """Drop the cached engine, the fallback warning, and any test double."""
    global _ANONYMIZER, _ANONYMIZER_FAILED, _analyzer_factory
    with _LOCK:
        _ENGINES.clear()
        _UNAVAILABLE.clear()
        _WARNED.clear()
        _ANONYMIZER = None
        _ANONYMIZER_FAILED = False
        _analyzer_factory = None


def install_analyzer_for_tests(factory: Optional[Callable[[PiiSettings], Any]]) -> None:
    """Use ``factory(settings)`` instead of importing Presidio. Tests only."""
    global _analyzer_factory
    with _LOCK:
        _ENGINES.clear()
        _UNAVAILABLE.clear()
        _analyzer_factory = factory


def _warn_once(message: str) -> None:
    if message in _WARNED:
        return
    _WARNED.add(message)
    sys.stderr.write(f"[prismor] pii: {message}\n")
    try:
        from prismor.runtime.perf import degraded
        degraded("pii:regex-fallback")
    except Exception:
        pass


def _load_error(exc: BaseException, model: str) -> str:
    text = str(exc)
    if (
        isinstance(exc, ImportError)
        or "presidio" in text.lower()
        or "No module named" in text
    ):
        return 'presidio is not installed (pip install "prismor[pii]")'
    if model and (model in text or "E050" in text or "Can't find model" in text):
        return (
            f"spaCy model {model} is not installed "
            f"(python -m spacy download {model})"
        )
    return f"presidio failed to load ({exc.__class__.__name__})"


def _build_analyzer(settings: PiiSettings) -> Any:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    # Fail before Presidio's loader prints a traceback, and name the model the
    # operator asked for. The small English model is the default on purpose:
    # en_core_web_lg is hundreds of megabytes and is not what a hook should load.
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": settings.language, "model_name": settings.model}],
    })
    nlp = provider.create_engine()
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(
        nlp_engine=nlp, languages=[settings.language],
    )
    return AnalyzerEngine(
        nlp_engine=nlp,
        registry=registry,
        supported_languages=[settings.language],
    )


def _analyzer(settings: PiiSettings) -> Tuple[Any, str]:
    key = (settings.language, settings.model)
    with _LOCK:
        factory = _analyzer_factory
        if key in _ENGINES:
            return _ENGINES[key], ""
        if factory is None and key in _UNAVAILABLE:
            return None, _UNAVAILABLE[key]
    if factory is not None:
        try:
            engine = factory(settings)
        except Exception as exc:
            return None, _load_error(exc, settings.model)
        with _LOCK:
            _ENGINES[key] = engine
        return engine, ""
    try:
        engine = _build_analyzer(settings)
    except Exception as exc:
        reason = _load_error(exc, settings.model)
        with _LOCK:
            _UNAVAILABLE[key] = reason
        return None, reason
    with _LOCK:
        _ENGINES[key] = engine
    return engine, ""


# ── detection ────────────────────────────────────────────────────────────────

def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_synthetic(entity: str, value: str) -> bool:
    """Fixture values (example.com, 555 numbers, published test PANs) are not findings."""
    if entity == "EMAIL_ADDRESS":
        from prismor.runtime.data_boundary import _is_synthetic_email
        return _is_synthetic_email(value)
    if entity == "PHONE_NUMBER":
        digits = _digits(value)
        national = digits[-10:] if len(digits) >= 10 else digits
        return len(national) >= 6 and national[3:6] == "555"
    if entity == "US_SSN":
        return _digits(value) in _SYNTHETIC_SSN
    if entity == "CREDIT_CARD":
        from prismor.runtime.data_boundary import _TEST_PANS
        return _digits(value) in _TEST_PANS
    if entity == "IBAN_CODE":
        compact = re.sub(r"\s+", "", value).upper()
        return compact in _SYNTHETIC_IBAN
    return False


def _nhs_ok(digits: str) -> bool:
    if len(digits) != 10 or not digits.isdigit() or digits == digits[0] * 10:
        return False
    total = sum(int(d) * w for d, w in zip(digits[:9], range(10, 1, -1)))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == int(digits[9])


def resolve_overlaps(hits: Sequence[PiiHit]) -> List[PiiHit]:
    """Keep the higher-scoring span when two recognisers cover the same characters."""
    ordered = sorted(hits, key=lambda h: (-h.score, -(h.end - h.start), h.start))
    kept: List[PiiHit] = []
    for hit in ordered:
        if any(not (hit.end <= prev.start or hit.start >= prev.end) for prev in kept):
            continue
        kept.append(hit)
    kept.sort(key=lambda h: h.start)
    return kept


def _append_unique(hits: List[PiiHit], hit: PiiHit) -> None:
    for prev in hits:
        if prev.entity == hit.entity and prev.start == hit.start and prev.end == hit.end:
            return
    hits.append(hit)


def _detect_regex(text: str, settings: PiiSettings) -> List[PiiHit]:
    wanted = set(settings.entities)
    if not wanted:
        return []
    hits: List[PiiHit] = []
    structured = wanted & {
        "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE", "US_SSN",
    }
    if structured:
        from prismor.runtime.data_boundary import classify
        kind_map = {
            "email": "EMAIL_ADDRESS",
            "phone": "PHONE_NUMBER",
            "card": "CREDIT_CARD",
            "iban": "IBAN_CODE",
            "ssn": "US_SSN",
        }
        for match in classify(text, context="body"):
            entity = kind_map.get(match.kind)
            if not entity or entity not in wanted or match.synthetic:
                continue
            _append_unique(hits, PiiHit(
                entity, 0.85, match.start, match.end, match.value,
            ))

    if "US_SSN" in wanted:
        for match in _SSN_RE.finditer(text):
            value = match.group(0)
            if is_synthetic("US_SSN", value):
                continue
            _append_unique(hits, PiiHit("US_SSN", 0.85, match.start(), match.end(), value))

    if "PHONE_NUMBER" in wanted:
        for match in _PHONE_RE.finditer(text):
            value = match.group(0)
            if is_synthetic("PHONE_NUMBER", value):
                continue
            _append_unique(hits, PiiHit(
                "PHONE_NUMBER", 0.75, match.start(), match.end(), value,
            ))

    if "UK_NHS" in wanted:
        for match in _NHS_RE.finditer(text):
            digits = "".join(match.groups())
            if not _nhs_ok(digits):
                continue
            value = match.group(0)
            # Higher than a phone on the same digits: a checksummed NHS number
            # is the more specific reading of that span.
            _append_unique(hits, PiiHit("UK_NHS", 0.9, match.start(), match.end(), value))

    if "IP_ADDRESS" in wanted:
        for match in _IP_RE.finditer(text):
            value = match.group(0)
            if _skip_ip(value):
                continue
            _append_unique(hits, PiiHit(
                "IP_ADDRESS", 0.6, match.start(), match.end(), value,
            ))

    return [
        hit for hit in resolve_overlaps(hits)
        if hit.score >= settings.score_threshold and hit.entity in wanted
    ]


def _hits_from_analyzer(text: str, results: Iterable[Any], settings: PiiSettings) -> List[PiiHit]:
    wanted = set(settings.entities)
    hits: List[PiiHit] = []
    for result in results:
        entity = str(getattr(result, "entity_type", "") or getattr(result, "entity", ""))
        if not wanted or entity not in wanted:
            continue
        try:
            start, end = int(result.start), int(result.end)
            score = float(result.score)
        except (TypeError, ValueError, AttributeError):
            continue
        if end <= start or start < 0 or end > len(text) or score < settings.score_threshold:
            continue
        value = text[start:end]
        if is_synthetic(entity, value):
            continue
        hits.append(PiiHit(entity, score, start, end, value))
    return resolve_overlaps(hits)


def _detect_presidio(text: str, settings: PiiSettings) -> Tuple[List[PiiHit], str]:
    engine, err = _analyzer(settings)
    if engine is None:
        return [], err
    try:
        results = engine.analyze(
            text=text,
            language=settings.language,
            entities=list(settings.entities) or None,
            score_threshold=float(settings.score_threshold),
        )
    except Exception as exc:
        return [], f"presidio analyze failed ({exc.__class__.__name__})"
    return _hits_from_analyzer(text, results, settings), ""


def detect(text: str, settings: PiiSettings) -> PiiResult:
    """Find PII in ``text``. Never raises. Disabled settings return no hits.

    Presidio is imported only when ``settings.backend`` is ``presidio`` and the
    call actually runs. A missing install or model falls back to regex.
    """
    requested = settings.backend
    if not settings.enabled or not isinstance(text, str) or not text.strip():
        return PiiResult(requested_backend=requested, backend="off")

    truncated = False
    scanned = text
    if len(text) > settings.max_chars:
        scanned = text[: settings.max_chars]
        truncated = True

    started = time.perf_counter()
    unsupported = tuple(e for e in settings.entities if e not in REGEX_ENTITIES)
    fallback = ""
    if requested == "presidio":
        hits, err = _detect_presidio(scanned, settings)
        if err:
            fallback = err
            _warn_once(f"{err}; using the regex detector")
            hits = _detect_regex(scanned, settings)
            backend = "regex"
        else:
            backend = "presidio"
            unsupported = ()
    else:
        hits = _detect_regex(scanned, settings)
        backend = "regex"

    return PiiResult(
        hits=tuple(hits),
        backend=backend,
        requested_backend=requested,
        fallback_reason=fallback,
        unsupported=unsupported if backend == "regex" else (),
        truncated=truncated,
        latency_ms=(time.perf_counter() - started) * 1000,
    )


# ── redaction ────────────────────────────────────────────────────────────────

def public_mask(value: str) -> str:
    """A sample safe to store. Hides the domain of an email and all but the ends
    of a long token. Short values are bullets only."""
    text = str(value)
    if "@" in text:
        return "•••@••••"
    if len(text) < 6:
        return "•" * max(len(text), 3)
    return text[0] + ("•" * (len(text) - 2)) + text[-1]


def _local_token(value: str, entity: str, style: str) -> str:
    if style == "replace":
        return f"<{entity}>"
    if style == "redact":
        return "[REDACTED]"
    if style == "hash":
        # Truncated so a finding-sized string cannot be the value itself.
        # Short identifiers can still be guessed from a hash; mask or replace
        # is the style to use for SSN, NHS and phone numbers.
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return "•" * max(len(value), 1)


def _anonymize_local(text: str, hits: Sequence[PiiHit], style: str) -> str:
    ordered = sorted(resolve_overlaps(hits), key=lambda h: h.start, reverse=True)
    for hit in ordered:
        text = text[: hit.start] + _local_token(hit.value, hit.entity, style) + text[hit.end :]
    return text


def _anonymizer():
    global _ANONYMIZER, _ANONYMIZER_FAILED
    if _ANONYMIZER_FAILED:
        return None
    if _ANONYMIZER is not None:
        return _ANONYMIZER
    try:
        from presidio_anonymizer import AnonymizerEngine
        engine = AnonymizerEngine()
    except Exception:
        _ANONYMIZER_FAILED = True
        return None
    _ANONYMIZER = engine
    return engine


def _anonymize_presidio(text: str, hits: Sequence[PiiHit], style: str) -> Optional[str]:
    """Run presidio-anonymizer. ``None`` when it is missing or declines."""
    if style == "hash":
        # The anonymizer's hash operator emits a full digest. The local
        # truncation is the documented contract, so hash stays local.
        return None
    engine = _anonymizer()
    if engine is None:
        return None
    try:
        from presidio_analyzer import RecognizerResult
        from presidio_anonymizer.entities import OperatorConfig
    except Exception:
        return None
    results = [
        RecognizerResult(entity_type=h.entity, start=h.start, end=h.end, score=h.score)
        for h in resolve_overlaps(hits)
    ]
    if style == "replace":
        operators = {
            h.entity: OperatorConfig("replace", {"new_value": f"<{h.entity}>"})
            for h in hits
        }
        operators["DEFAULT"] = OperatorConfig("replace", {"new_value": "<PII>"})
    elif style == "redact":
        operators = {"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})}
    else:
        operators = {"DEFAULT": OperatorConfig("mask", {
            "masking_char": "•", "chars_to_mask": 10000, "from_end": False,
        })}
    try:
        out = engine.anonymize(text=text, analyzer_results=results, operators=operators)
    except Exception:
        return None
    rendered = getattr(out, "text", None)
    return rendered if isinstance(rendered, str) else None


def anonymize(
    text: str,
    hits: Sequence[PiiHit],
    style: str = "mask",
    *,
    prefer_presidio: bool = True,
) -> str:
    """Replace ``hits`` in ``text``. Uses presidio-anonymizer when it is installed."""
    if not hits:
        return text
    if style not in MASK_STYLES:
        style = "mask"
    if prefer_presidio:
        rendered = _anonymize_presidio(text, hits, style)
        if rendered is not None:
            return rendered
    return _anonymize_local(text, hits, style)


def redact_text(text: str, settings: PiiSettings, *, prefer_presidio: bool = True) -> str:
    """Mask ``text`` when this policy redacts in enforce mode. Otherwise unchanged."""
    if (
        not isinstance(text, str)
        or not text
        or not settings.enabled
        or settings.action != "redact"
        or settings.mode != "enforce"
    ):
        return text
    result = detect(text, settings)
    if not result.hits:
        return text
    return anonymize(text, result.hits, settings.mask_style, prefer_presidio=prefer_presidio)


# ── findings ─────────────────────────────────────────────────────────────────

def _severity(hits: Sequence[PiiHit]) -> str:
    if any(h.entity in _HIGH_ENTITIES for h in hits):
        return "HIGH"
    return "MEDIUM"


def _verdict(settings: PiiSettings) -> Tuple[str, str, Optional[str]]:
    """``(action, mode, transform)`` for the finding.

    ``observe`` only records. ``redact`` and ``block`` change the call only
    when ``settings.pii.mode`` is ``enforce``, the same split as every other
    rule: the action says what to do, the mode says whether it acts.
    """
    if settings.action == "observe" or settings.mode != "enforce":
        return "warn", "observe", None
    if settings.action == "block":
        return "block", "enforce", None
    return "modify", "enforce", "pii_ner_redact"


def _dedupe_values(hits: Sequence[PiiHit]) -> List[PiiHit]:
    seen = set()
    out: List[PiiHit] = []
    for hit in hits:
        key = (hit.entity, hit.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


def finding_from_hits(
    hits: Sequence[PiiHit],
    *,
    index: int,
    session_id: str = "",
    settings: PiiSettings,
    backend: str = "presidio",
    fallback_reason: str = "",
    unsupported: Sequence[str] = (),
    truncated: bool = False,
    latency_ms: float = 0.0,
    subject: Optional[Dict[str, Any]] = None,
    suppressed_by: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """One finding for the whole event. Evidence is masked; ``hits`` values are not copied."""
    unique = _dedupe_values(hits)
    if not unique:
        return None
    counts: Dict[str, int] = {}
    best: Dict[str, PiiHit] = {}
    for hit in unique:
        counts[hit.entity] = counts.get(hit.entity, 0) + 1
        current = best.get(hit.entity)
        if current is None or hit.score > current.score:
            best[hit.entity] = hit
    names = sorted(counts, key=lambda e: (e not in _HIGH_ENTITIES, e))
    label = ", ".join(
        f"{name} ×{counts[name]}" if counts[name] > 1 else name for name in names
    )
    samples = []
    for name in names[:_MAX_EVIDENCE_ENTITIES]:
        hit = best[name]
        samples.append(f"{name} {public_mask(hit.value)} ({hit.score:.2f})")
    extra = len(names) - _MAX_EVIDENCE_ENTITIES
    if extra > 0:
        samples.append(f"+{extra} more")
    action, mode, transform = _verdict(settings)
    finding_id = f"{RULE_ID}-{index}"
    finding: Dict[str, Any] = {
        "id": f"{session_id}:{finding_id}" if session_id else finding_id,
        "severity": _severity(unique),
        "category": "pii_exposure",
        "title": f"PII detected ({backend}): {label}",
        "evidence": ", ".join(samples),
        "eventIndex": index,
        "ruleId": RULE_ID,
        "action": action,
        "mode": mode,
        "entities": names,
        "piiBackend": backend,
        "piiLatencyMs": round(latency_ms, 2),
        "remediation": (
            "Raw values are not stored. Tune settings.pii (entities, "
            "score_threshold, action, mode, mask_style) in .prismor/policy.yaml."
        ),
    }
    if subject:
        finding["subject"] = subject
    if transform:
        finding["transform"] = transform
    if fallback_reason:
        finding["piiFallback"] = fallback_reason
    if unsupported and backend == "regex":
        finding["piiUnsupported"] = list(unsupported)
    if truncated:
        finding["piiTruncated"] = True
    if suppressed_by is not None:
        finding["suppressedBy"] = suppressed_by
    return finding


def screen_event(
    event: Dict[str, Any],
    field_values: Dict[str, str],
    index: int,
    session_id: str = "",
    *,
    settings: PiiSettings,
    allowlist_match: Optional[Callable[[str], Any]] = None,
    include_suppressed: bool = False,
    subject: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Scan the event's text fields. Returns zero or one finding.

    ``allowlist_match`` is handed the raw text in memory so an operator can
    exempt a known value. That text is not stored on the finding.
    """
    if (
        not settings.enabled
        or event.get("_script_line")
        or event.get("_bulk_scan")
        or event.get("_pii_done")
    ):
        return []
    chunks: List[str] = []
    for name in settings.fields:
        value = field_values.get(name) or ""
        if isinstance(value, str) and value.strip():
            chunks.append(value)
    if not chunks:
        return []

    hits: List[PiiHit] = []
    backend = "presidio" if settings.backend == "presidio" else "regex"
    fallback = ""
    unsupported: Tuple[str, ...] = ()
    truncated = False
    latency = 0.0
    for chunk in chunks:
        result = detect(chunk, settings)
        hits.extend(result.hits)
        latency += result.latency_ms
        truncated = truncated or result.truncated
        if result.backend == "regex":
            backend = "regex"
        if result.fallback_reason:
            fallback = result.fallback_reason
        if result.unsupported:
            unsupported = result.unsupported
    if not hits:
        return []

    suppressed = None
    if allowlist_match is not None:
        try:
            entry = allowlist_match("\n".join(chunks))
        except Exception:
            entry = None
        if entry is not None:
            if not include_suppressed:
                return []
            suppressed = {
                "id": getattr(entry, "id", ""),
                "reason": getattr(entry, "reason", ""),
            }

    finding = finding_from_hits(
        hits,
        index=index,
        session_id=session_id,
        settings=settings,
        backend=backend,
        fallback_reason=fallback,
        unsupported=unsupported,
        truncated=truncated,
        latency_ms=latency,
        subject=subject,
        suppressed_by=suppressed,
    )
    return [finding] if finding else []
