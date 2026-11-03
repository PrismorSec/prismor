# PII detection (Presidio)

The regex `pii-exposure` rule and the [data boundary](data-boundary.md) catch
formatted identifiers: an SSN, a card number, a phone number, an email, an
IBAN. They do not recognise a person's name, a place, or an NHS number written
in a sentence. [Cloak](sweep-and-cloak.md) is a different control: it vaults
secrets you register and substitutes `@@SECRET:name@@` at execution time.

This page is the optional third control. It runs [Microsoft Presidio](https://microsoft.github.io/presidio/)
(presidio-analyzer and presidio-anonymizer) over prompts, tool-call arguments
and tool results, and records a `pii-ner` finding. It is **off by default**.
A default hook never imports Presidio, so that path stays on the regex budget.

## Install

Presidio and spaCy are not dependencies of `prismor`. Python 3.9 or newer:

```bash
pip install "prismor[pii]"
python -m spacy download en_core_web_sm
```

`en_core_web_sm` is the small English model (about 12 MB). The detector does
not load `en_core_web_lg`. If the extra or the model is missing and `backend`
is `presidio`, detection falls back to the regex classifier and prints one
line on stderr. Names, locations and medical-license numbers are listed on the
finding as `piiUnsupported` in that case. The call is not failed.

## Enable

In `.prismor/policy.yaml`:

```yaml
version: "1.0"
rules: []
settings:
  pii:
    enabled: true
    action: observe    # observe | redact | block
    mode: observe      # observe | enforce
```

`action` is what a hit should do. `mode` is whether that action is live, the
same split as every other rule:

| action | mode | what happens |
|---|---|---|
| `observe` | either | a finding is recorded, the call is unchanged |
| `redact` | `observe` | a finding is recorded, the call is unchanged |
| `redact` | `enforce` | the value is masked, then the call continues |
| `block` | `observe` | a finding is recorded, the call is unchanged |
| `block` | `enforce` | a pre-action call is refused; a gateway tool result is withheld |

Start with `observe`. `block` refuses any pre-action call whose text contains
a hit, including an `echo` of a name. `redact` rewrites the text in place
(`transform: pii_ner_redact` on tool input, and the shared result redactor on
tool output).

Check a string without running it:

```bash
prismor check --type text "email Ada Lovelace at ada.lovelace@nhs.net"
```

`example.com`, `555` phone numbers and the published test card numbers are
treated as fixtures and do not produce a `pii-ner` finding. The regex
`pii-exposure` rule is unchanged and can still match a formatted SSN on its own.

## What it detects

Default entity list:

| Entity | Needs the spaCy model |
|---|---|
| `PERSON`, `LOCATION`, `MEDICAL_LICENSE` | yes |
| `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `US_SSN`, `UK_NHS`, `IP_ADDRESS` | no (regex recognisers; the fallback covers these) |

`IP_ADDRESS` from the regex fallback scores 0.6, so a `score_threshold` of
0.7 drops it. Dotted version numbers can look like addresses; remove
`IP_ADDRESS` from `entities` if that noise matters. `DATE_TIME` and `URL` are
not in the default list because they fire on ordinary text. Add them under
`entities` if you want them.

Other Presidio types (`US_PASSPORT`, `US_ITIN`, `UK_NINO`, …) work once you
name them. The language defaults to `en`. Another language needs a spaCy
model for that language and `language` set to its code.

## Configuration

```yaml
settings:
  pii:
    enabled: false
    backend: presidio          # presidio | regex
    language: en
    model: en_core_web_sm
    score_threshold: 0.5
    action: observe            # observe | redact | block
    mode: observe              # observe | enforce
    mask_style: mask           # mask | replace | hash | redact
    max_chars: 4000
    entities: [PERSON, EMAIL_ADDRESS, PHONE_NUMBER, UK_NHS]
    fields: [prompt, response, content, stdout, stderr, command, mcp_args, outbound_payload, typed_text]
```

A project file that sets only `enabled: true` keeps the defaults above. The
stanza merges like `semantic_guard`.

`mask_style` is how a redacted value is replaced:

| style | replacement |
|---|---|
| `mask` | the span, every character a `•` |
| `replace` | `<PERSON>`, `<EMAIL_ADDRESS>`, … |
| `redact` | `[REDACTED]` |
| `hash` | 16 hex characters of SHA-256 |

`hash` is not a secret. A short identifier (SSN, NHS number, phone) can be
guessed from it. Use `mask` or `replace` for those.

`max_chars` bounds how much of each field is scanned (default 4000, maximum
50000). A longer field sets `piiTruncated` on the finding. Hits past the cut
are not detected.

`backend: regex` never imports Presidio. Use it where you want the structured
entities without a model. `PERSON`, `LOCATION` and `MEDICAL_LICENSE` stay
unsupported.

Script bodies walked line by line, and the SessionStart skills audit, are not
scanned. One model pass per line would dominate the call. The shell command
that invokes the script is still scanned.

## Where a finding is recorded

The finding uses the existing `pii_exposure` category and the rule id
`pii-ner`, so it shows up in `prismor sessions`, the dashboard and redacted
telemetry the same way `pii-exposure` does. Stored fields are the entity type,
a score, and a mask. The value itself is not written to the finding, the
title, or the stderr line.

An allowlist on rule `pii-ner` suppresses a hit when its pattern matches the
scanned text. The match happens in memory. The raw text is not stored.

`prismor doctor` lists the layer as `pii: off` until you enable it, then
`pii: observe (presidio, en_core_web_sm)` or `pii: observe (regex fallback, …)`.

## Result redaction

Surfaces that already pass their policy engine into the shared redactor mask
tool output when `action` is `redact` and `mode` is `enforce`: the MCP
gateway, the LLM proxy, `POST /v1/redact`, and framework adapters that pass
`engine=`. The gateway scans once while it masks, and does not run the model
again on the masked text. A coding-agent hook cannot rewrite tool output; it
can refuse the call (`block`) or rewrite tool input (`redact` via
`pii_ner_redact`). `prismor pause` suspends this pass with the rest of policy.
Cloak masking keeps running.

## Latency

One run of `python3 scripts/bench_pii.py` (190-character prompt, median after
a warmup):

| path | time |
|---|---|
| `evaluate`, PII disabled (the default) | 0.78 ms |
| `evaluate`, regex backend | 1.00 ms |
| `detect()`, regex only | 0.10 ms |
| Presidio `detect()`, first call in the process | 364 ms |
| Presidio `evaluate`, warm, 190 characters | 6.9 ms |
| Presidio `evaluate`, warm, 4000 characters | 76 ms |
| Presidio `detect()`, warm | 5.8 ms |

Re-run the script on the machine you deploy to. The shape is what matters:
the disabled path stays under a millisecond, and a warm Presidio call on a
short prompt is a few milliseconds once the model is in the process. The
first call in a process pays the spaCy load (a few hundred milliseconds
here). Two consequences follow from how hooks work:

- **Default installs are unchanged.** `enabled` is false. Presidio is not
  imported. A coding-agent hook stays on the regex budget (about 1 ms).
- **The model is cached per process.** The eval-server, the MCP gateway, the
  LLM proxy and an in-process framework adapter pay the load once. A
  coding-agent hook is a new process per call, so enabling Presidio there
  adds the cold-start cost to every tool call. Prefer it on the long-lived
  surfaces (Copilot Studio goes through the eval-server) unless you have
  measured the hook overhead and accepted it.

`max_chars` is the other bound. A multi-kilobyte tool result is scanned only
up to that cap.

## Copilot Studio and other surfaces

Copilot Studio sends the planned tool call and earlier tool outputs to the
eval-server as `prompt` and `tool_result` events. Those fields are in the
default `fields` list, so the same stanza covers them. No separate provider
configuration.

See also: [Data boundary](data-boundary.md), [Sweep and Cloak](sweep-and-cloak.md),
[Decision contract](decision-contract.md), [Copilot Studio](copilot-studio.md).
