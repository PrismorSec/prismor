"""Remote (org-managed) policy distribution for enterprise control.

When a Prismor install is enrolled (see :mod:`prismor.runtime.identity`), an org admin
can manage policy centrally in prismor-web. This module fetches that policy,
verifies its signature against the bundled trust root (``keys/public.pub`` —
the same Ed25519 key used for the advisory feed), and caches it locally so the
:class:`~prismor.runtime.policy_engine.PolicyEngine` can merge it as an authoritative
overlay.

Security properties:

* **Signed, fail-closed.** A remote policy is only ever applied if its detached
  signature verifies against the bundled public key. An unsigned, tampered, or
  unverifiable policy is *ignored* — the engine falls back to local policy. A
  compromised control plane cannot inject rules.
* **Tighten-only floor.** The engine enforces ``_NON_OVERRIDABLE_RULE_IDS`` for
  the remote overlay too, so even a valid remote policy can never disable the
  destructive-command / secret-exfiltration protections or turn Prismor off.
* **Offline-safe.** If the control plane is unreachable, the last verified
  cached policy keeps applying. Loss of connectivity never weakens protection.

Verification reuses the repo's existing ``openssl`` mechanism (see
``scripts/verify_feed.sh``) rather than adding a crypto dependency — the only
hard dependency stays ``pyyaml``.
"""
from __future__ import annotations

from prismor.runtime.http_ua import user_agent as _http_user_agent

import base64
import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.enterprise import identity as _identity


def _public_key_path() -> Path:
    """Bundled Ed25519 trust root (same key that signs the advisory feed).

    Resolved via prismor.runtime.paths so it works in a git checkout *and* an installed
    wheel (where the key lives at ``prismor/runtime/data/keys/public.pub``). Resolved at
    call time, not import, so $PRISMOR_HOME overrides are honored.
    """
    from prismor.runtime.paths import public_key_path
    return public_key_path()

# Full re-fetch backstop (seconds) for the force/legacy path.
DEFAULT_TTL_SECONDS = 300

# How often the runtime does the cheap version check on the hot path. Bounds
# how stale an enrolled device's policy can be after an admin change. Override
# via $PRISMOR_POLICY_REFRESH_SECONDS (per-org tuning can later come from the
# resolved policy settings).
def _refresh_interval() -> float:
    try:
        v = float(os.environ.get("PRISMOR_POLICY_REFRESH_SECONDS", "30"))
    except ValueError:
        return 30.0
    # Clamp (audit #11): a hand-set env must not pin a stale policy indefinitely
    # (admin enforce changes would never reach the device) nor hammer the
    # control plane. Bound to [5s, 600s].
    return max(5.0, min(v, 600.0))


def _check_marker_path() -> Path:
    return _identity.prismor_home() / "remote-policy.check"


def current_version() -> Optional[int]:
    """The policy version currently cached/applied on this device, or None."""
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        v = meta.get("version")
        return int(v) if v is not None else None
    except (OSError, ValueError, TypeError):
        return None


def current_full_capture() -> Optional[bool]:
    """The capture mode (full vs redacted) of the cached policy, or None."""
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        fc = meta.get("full_capture")
        return bool(fc) if fc is not None else None
    except (OSError, ValueError, TypeError):
        return None


def current_profile_id() -> Optional[str]:
    """The id of the policy profile currently cached/applied on this device, or
    None. Lets us detect a scope switchover (e.g. org→device) even when the new
    profile happens to share the old one's version number."""
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        pid = meta.get("profile_id")
        return str(pid) if pid else None
    except (OSError, ValueError, TypeError):
        return None


def _last_checked() -> float:
    try:
        return float(_check_marker_path().read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0.0


def _touch_checked() -> None:
    try:
        _identity.prismor_home().mkdir(parents=True, exist_ok=True)
        _check_marker_path().write_text(str(time.time()), encoding="utf-8")
    except OSError:
        pass


def check_and_refresh(interval: Optional[float] = None) -> bool:
    """Hot-path policy freshness check, debounced and synchronous.

    At most once per ``interval`` seconds, makes a *cheap* GET to
    ``/api/policy/version`` (no signing, no YAML) reporting the version this
    device has applied. Only if the server's version differs do we pull the
    full signed policy via :func:`fetch`. Returns True if a new policy was
    pulled. Never raises — best-effort, never blocks the tool call beyond a
    short timeout. No-op when not enrolled.

    Unlike a fire-and-forget background thread, this runs inline and actually
    completes, so a freshly-applied policy is in effect on the *same* tool call
    that detects the change.
    """
    ident = _identity.load_identity()
    if not ident:
        return False
    if _identity.revoked_backoff_active():
        return False  # key was rejected — back off instead of hammering
    iv = _refresh_interval() if interval is None else interval
    if (time.time() - _last_checked()) < iv:
        return False
    _touch_checked()  # debounce regardless of outcome so we don't hammer on errors

    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    cur = current_version()
    url = (
        f"{base}/api/policy/version?device_id={ident.get('device_id')}"
        f"&org_id={ident.get('org_id')}&applied={cur if cur is not None else ''}"
    )
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {ident.get('device_key')}"}, method="GET"
    )
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        _identity.clear_revoked()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            _identity.mark_revoked(f"policy version check rejected ({exc.code})")
            sys.stderr.write(
                "[prismor] control plane rejected this device's key "
                f"({exc.code}) — keeping last good policy. Re-enroll with: prismor enroll <token>\n"
            )
        return False
    except (urllib.error.URLError, ValueError, OSError):
        return False

    latest = body.get("version")
    version_changed = latest is not None and latest != cur
    # A different profile can become effective without bumping the version number
    # (a fresh device/user profile at v1 shadowing an org profile at v1). Compare
    # the effective profile id too so the scope switchover propagates immediately.
    latest_profile = body.get("profileId")
    profile_changed = (
        latest_profile is not None
        and str(latest_profile) != str(current_profile_id() or "")
    )
    # A full-capture flip doesn't bump the profile version, so compare it
    # separately — otherwise the developer-facing capture notice (and the
    # actual change in what leaves the machine) would lag until the next
    # version bump or TTL.
    latest_capture = body.get("fullCapture")
    capture_changed = (
        latest_capture is not None
        and bool(latest_capture) != bool(current_full_capture())
    )
    # The org's claimed-repo patterns also live in the resolved policy, not the
    # version — so compare their signature too, else a managed-repo change
    # (which repos are governed) would lag until the next version bump.
    latest_repos_sig = body.get("managedReposSig")
    repos_changed = (
        latest_repos_sig is not None
        and str(latest_repos_sig) != str(_current_managed_repos_sig())
    )
    # Per-agent controls (kill-switch / forced mode / IAM) are served in the
    # resolved policy but deliberately do NOT bump the profile version — the
    # server exposes their signature instead, so an org pause reaches every
    # device within one debounce interval regardless of profile scope.
    latest_controls_sig = body.get("agentControlsSig")
    controls_changed = (
        latest_controls_sig is not None
        and str(latest_controls_sig) != str(_current_agent_controls_sig())
    )
    # Per-event rule exemptions (relax/flag a rule for a user/device/session)
    # also live in the resolved policy without a version bump — compare their
    # signature so an admin's exempt reaches the device within one debounce.
    latest_rule_ex_sig = body.get("ruleExemptionsSig")
    rule_ex_changed = (
        latest_rule_ex_sig is not None
        and str(latest_rule_ex_sig) != str(_current_rule_exemptions_sig())
    )
    # Per-tool denies (settings.tool_denies) also live in the resolved policy
    # without a version bump — compare their signature so an admin's tool block
    # reaches the device within one debounce interval.
    latest_tool_denies_sig = body.get("toolDeniesSig")
    tool_denies_changed = (
        latest_tool_denies_sig is not None
        and str(latest_tool_denies_sig) != str(_current_tool_denies_sig())
    )
    # Per-subject controls (suspend / deny for an end user or client team,
    # settings.subject_controls) also live in the resolved policy without a
    # version bump — compare their signature so an admin's suspension reaches
    # every device within one debounce interval.
    latest_subject_sig = body.get("subjectControlsSig")
    subject_controls_changed = (
        latest_subject_sig is not None
        and str(latest_subject_sig) != str(_current_subject_controls_sig())
    )
    # The device-level observe/enforce override (settings.device_mode) lives on
    # the Device row server-side, not in any profile, so it never bumps the
    # version — compare the raw value, like fullCapture, so a console toggle
    # reaches this machine within one debounce interval.
    latest_device_mode = body.get("deviceMode")
    device_mode_changed = (
        latest_device_mode is not None
        and str(latest_device_mode) != _current_device_mode()
    )
    # The egress policy (settings.egress) is served in the resolved policy
    # without a version bump too — compare its signature so widening or
    # tightening the fleet's network boundary reaches every device within one
    # debounce interval instead of waiting for the next profile bump.
    latest_egress_sig = body.get("egressSig")
    egress_changed = (
        latest_egress_sig is not None
        and str(latest_egress_sig) != str(_current_egress_sig())
    )
    # Tool-tag governance (settings.tool_tags) is served without a version bump
    # as well. The server has always sent toolTagsSig; nothing here compared it,
    # so a new tag rule only reached the device when some OTHER channel happened
    # to churn — an admin adding a blocking rule would watch it do nothing.
    latest_tool_tags_sig = body.get("toolTagsSig")
    tool_tags_changed = (
        latest_tool_tags_sig is not None
        and str(latest_tool_tags_sig) != str(_current_tool_tags_sig())
    )
    # The org's pause/resume for THIS machine (settings.device_pause) is served
    # in the resolved policy without a version bump. Only its signature appears
    # here — never the pause itself — because this endpoint is unsigned, and a
    # pause the runtime obeys is a remote off-switch for enforcement. Seeing the
    # signature change is enough to trigger a signed re-pull.
    latest_pause_sig = body.get("pauseSig")
    pause_changed = (
        latest_pause_sig is not None
        and str(latest_pause_sig) != str(_current_pause_sig())
    )
    # settings.self_edit — whether a human may open a password-verified window
    # in which the agent can edit local policy, and for how long. Same reasoning
    # as the pause above: it can relax enforcement, so only its signature is
    # served here and the record itself arrives signed.
    latest_self_edit_sig = body.get("selfEditSig")
    self_edit_changed = (
        latest_self_edit_sig is not None
        and str(latest_self_edit_sig) != str(_current_self_edit_sig())
    )
    # Prompt guardrails (settings.prompt_guardrails) are served without a
    # version bump; an admin's edit reaches the agent's next prompt.
    latest_guardrails_sig = body.get("promptGuardrailsSig")
    guardrails_changed = (
        latest_guardrails_sig is not None
        and str(latest_guardrails_sig) != str(_current_prompt_guardrails_sig())
    )
    if (version_changed or profile_changed or capture_changed or guardrails_changed
            or repos_changed or controls_changed or rule_ex_changed
            or egress_changed or tool_denies_changed or subject_controls_changed
            or device_mode_changed or tool_tags_changed or pause_changed
            or self_edit_changed):
        return fetch(force=True)
    return False


def _current_managed_repos_sig() -> str:
    """Signature of the cached policy's repo-scoping config — managed_repo_patterns
    AND granted exemptions (id + expiry + overlay_sig) — matching the server's
    managedReposSig so the device re-pulls when either changes. Empty when there
    is no scoping config."""
    try:
        pol = verify_and_load()
        settings = (pol or {}).get("settings") or {}
        pats = sorted(str(p) for p in (settings.get("managed_repo_patterns") or []) if p)
        exemptions = settings.get("repo_exemptions") or []
        ex_parts = sorted(
            f"{ex.get('id')}:{ex.get('expires') or ''}:{ex.get('overlay_sig') or ''}"
            for ex in exemptions if isinstance(ex, dict) and ex.get("id")
        )
        # allow_personal_workspaces=false is folded in only when set, mirroring
        # the server, so default orgs keep their existing signature.
        no_personal = settings.get("allow_personal_workspaces") is False
        if not pats and not ex_parts and not no_personal:
            return ""
        import hashlib
        sig_input = "\n".join([*pats, "|", *ex_parts, *(["|", "no_personal"] if no_personal else [])])
        return hashlib.sha256(sig_input.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_rule_exemptions_sig() -> str:
    """Signature of the cached policy's rule exemptions, matching the server's
    ruleExemptionsSig format (sorted ``id:ruleId:scope:scopeId:action:expires``
    lines → sha256 → 16 hex; empty when none) so the device re-pulls when an
    exemption is added, revoked, or expires."""
    try:
        pol = verify_and_load()
        exemptions = ((pol or {}).get("settings") or {}).get("rule_exemptions") or []
        if not isinstance(exemptions, list) or not exemptions:
            return ""
        lines = sorted(
            f"{e.get('id')}:{e.get('ruleId') or ''}:{e.get('scope') or ''}:"
            f"{e.get('scopeId') or ''}:{e.get('action') or 'allow'}:{e.get('expires') or ''}"
            for e in exemptions if isinstance(e, dict) and e.get("id")
        )
        if not lines:
            return ""
        import hashlib
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_agent_controls_sig() -> str:
    """Signature of the cached policy's per-agent controls, matching the
    server's agentControlsSig format (sorted ``key:enabled:mode:iam`` lines →
    sha256 → 16 hex chars; empty when no controls are set) so the device
    re-pulls the moment an org admin pauses or reconfigures an agent."""
    try:
        pol = verify_and_load()
        controls = ((pol or {}).get("settings") or {}).get("agent_controls") or {}
        if not isinstance(controls, dict) or not controls:
            return ""
        lines = sorted(
            f"{name}:{'1' if c.get('enabled', True) else '0'}:{c.get('mode') or ''}:{c.get('iam_profile') or ''}"
            for name, c in controls.items() if isinstance(c, dict)
        )
        if not lines:
            return ""
        import hashlib
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_subject_controls_sig() -> str:
    """Signature of the cached policy's per-subject controls, matching the
    server's subjectControlsSig format (sorted ``key:suspended:deny-csv``
    lines → sha256 → 16 hex chars; empty when none) so the device re-pulls
    the moment an org admin suspends or reconfigures an end user / client."""
    try:
        pol = verify_and_load()
        controls = ((pol or {}).get("settings") or {}).get("subject_controls") or {}
        if not isinstance(controls, dict) or not controls:
            return ""
        lines = sorted(
            f"{key}:{'1' if c.get('suspended') else '0'}:{','.join(sorted(str(t) for t in (c.get('deny_tools') or [])))}"
            for key, c in controls.items() if isinstance(c, dict)
        )
        if not lines:
            return ""
        import hashlib
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_tool_denies_sig() -> str:
    """Signature of the cached policy's tool denies, matching the server's
    toolDeniesSig format (sorted ``id:tool:action:scope:scopeId`` lines →
    sha256 → 16 hex; empty when none) so the device re-pulls when an admin
    denies, lifts, or revokes a tool."""
    try:
        pol = verify_and_load()
        denies = ((pol or {}).get("settings") or {}).get("tool_denies") or []
        if not isinstance(denies, list) or not denies:
            return ""
        lines = sorted(
            f"{d.get('id')}:{d.get('tool') or ''}:{d.get('action') or 'deny'}:"
            f"{d.get('scope') or ''}:{d.get('scopeId') or ''}"
            for d in denies if isinstance(d, dict) and d.get("id")
        )
        if not lines:
            return ""
        import hashlib
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_device_mode() -> str:
    """The cached policy's device-level mode override (settings.device_mode),
    matching the server's deviceMode field: "observe", "enforce", or "" when
    no override is set — so the device re-pulls the moment an admin flips or
    clears the toggle in the console."""
    try:
        pol = verify_and_load()
        mode = str(((pol or {}).get("settings") or {}).get("device_mode") or "").lower()
        return mode if mode in ("observe", "enforce") else ""
    except Exception:
        return ""


def _current_pause_sig() -> str:
    """Signature of the cached policy's org pause/resume (settings.device_pause),
    matching the server's ``pauseSig`` format (canonical JSON → sha256 → 16 hex;
    empty when the org has no pause opinion) so the device re-pulls the moment
    an admin pauses or resumes it from the console."""
    try:
        pol = verify_and_load()
        pause = ((pol or {}).get("settings") or {}).get("device_pause")
        if not isinstance(pause, dict) or not pause:
            return ""
        import hashlib
        blob = json.dumps(pause, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def remote_pause() -> Optional[Dict[str, Any]]:
    """The org's pause/resume record for this machine from the cached SIGNED
    policy, or None when the org has no opinion.

    Read through ``verify_and_load`` so an unverified or tampered policy file
    yields nothing rather than a forged pause — this is the one setting whose
    whole job is to stop Prismor blocking, so it must never be honored unsigned.
    """
    try:
        pol = verify_and_load()
        pause = ((pol or {}).get("settings") or {}).get("device_pause")
        if not isinstance(pause, dict):
            return None
        state = str(pause.get("state") or "")
        if state not in ("paused", "resumed") or not pause.get("at"):
            return None
        return pause
    except Exception:
        return None


def remote_self_edit() -> Optional[Dict[str, Any]]:
    """The org's self-edit settings for this device from the cached SIGNED
    policy, or None when the org has no opinion.

    ``{"enabled": bool, "window_seconds": int}`` — whether a human may open a
    password-verified window in which the agent can edit local policy, and for
    how long (see runtime/unlock.py).

    Read through ``verify_and_load`` for the same reason as ``remote_pause``:
    enabling self-edit or widening its window can only ever *relax*
    enforcement, so an unsigned file must not be able to say anything about it.
    A disable, being a tightening, is honored from any policy that verifies.
    """
    try:
        pol = verify_and_load()
        rec = ((pol or {}).get("settings") or {}).get("self_edit")
        return rec if isinstance(rec, dict) else None
    except Exception:
        return None


def _current_self_edit_sig() -> str:
    """Signature of the cached policy's settings.self_edit, matching the
    server's ``selfEditSig`` format (canonical JSON → sha256 → 16 hex; empty
    when the org has no opinion) so the device re-pulls the moment an admin
    changes the self-edit window from the console."""
    try:
        pol = verify_and_load()
        rec = ((pol or {}).get("settings") or {}).get("self_edit")
        if not isinstance(rec, dict) or not rec:
            return ""
        import hashlib
        blob = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_egress_sig() -> str:
    """Signature of the cached policy's egress config, matching the server's
    ``egressSig`` format (canonical JSON of settings.egress → sha256 → 16 hex;
    empty when unset) so the device re-pulls when an admin edits the fleet's
    network boundary.

    Canonical JSON rather than a line format because egress entries are nested
    objects (host/ports/schemes/agents), not flat records like tool denies.
    """
    try:
        pol = verify_and_load()
        settings = (pol or {}).get("settings") or {}
        egress = settings.get("egress")
        if not isinstance(egress, dict) or not egress:
            # Fall back to the legacy flat list so a policy that still uses it
            # also propagates promptly.
            legacy = settings.get("egress_allowlist") or []
            if not legacy:
                return ""
            egress = {"egress_allowlist": sorted(str(x) for x in legacy)}
        import hashlib
        blob = json.dumps(egress, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_prompt_guardrails_sig() -> str:
    """Canonical JSON of settings.prompt_guardrails → sha256 → 16 hex, matching
    the server's promptGuardrailsSig. ensure_ascii=False because the server
    hashes JavaScript's JSON.stringify, which leaves non-ASCII text unescaped."""
    try:
        pol = verify_and_load()
        block = ((pol or {}).get("settings") or {}).get("prompt_guardrails")
        if not isinstance(block, dict) or not block:
            return ""
        import hashlib
        blob = json.dumps(block, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def _current_tool_tags_sig() -> str:
    """Signature of the cached policy's tool-tag config, matching the server's
    ``toolTagsSig`` format (canonical JSON of settings.tool_tags → sha256 → 16
    hex; empty when unset).

    Canonical JSON for the same reason egress uses it: the block is nested (a
    tag map, a rule list, and per-agent overlays) and — more importantly — the
    device only ever holds the RESOLVED block, never the rows behind it. The
    server originally hashed those rows, which is a signature the device cannot
    reproduce, so this comparison could not exist at all.
    """
    try:
        pol = verify_and_load()
        settings = (pol or {}).get("settings") or {}
        tags = settings.get("tool_tags")
        if not isinstance(tags, dict) or not tags:
            return ""
        import hashlib
        blob = json.dumps(tags, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    except Exception:
        return ""


def cached_policy_path() -> Path:
    return _identity.prismor_home() / "remote-policy.yaml"


def _cached_sig_path() -> Path:
    return _identity.prismor_home() / "remote-policy.yaml.sig"


def _meta_path() -> Path:
    return _identity.prismor_home() / "remote-policy.meta.json"


def _verify_signature(payload: bytes, sig_b64: str) -> bool:
    """Verify a detached Ed25519 signature over ``payload`` using openssl and the
    bundled public key. Returns False on any error (fail-closed)."""
    pub_key = _public_key_path()
    if not pub_key.exists() or not sig_b64:
        return False
    try:
        sig_raw = base64.b64decode(sig_b64)
    except Exception:
        return False

    import tempfile
    payload_f = sig_f = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as pf:
            pf.write(payload)
            payload_f = pf.name
        with tempfile.NamedTemporaryFile(delete=False) as sf:
            sf.write(sig_raw)
            sig_f = sf.name
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(pub_key),
                "-rawin", "-in", payload_f,
                "-sigfile", sig_f,
            ],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        for f in (payload_f, sig_f):
            if f:
                try:
                    os.unlink(f)
                except OSError:
                    pass


def verify_and_load() -> Optional[Dict[str, Any]]:
    """Load and verify the cached remote policy. Returns the parsed policy dict
    (with a ``_remote_meta`` key) or None if absent / unverifiable.

    Called by the PolicyEngine on every load — must be cheap and never raise.
    """
    if _identity.revoked_info():
        return None
    policy_path = cached_policy_path()
    sig_path = _cached_sig_path()
    if not policy_path.exists() or not sig_path.exists():
        return None

    try:
        pol_stat = policy_path.stat()
        sig_stat = sig_path.stat()
        cache_key = (
            str(policy_path),
            str(sig_path),
            pol_stat.st_mtime_ns,
            pol_stat.st_size,
            sig_stat.st_mtime_ns,
            sig_stat.st_size,
        )
    except OSError:
        return None

    if cache_key in _VERIFIED_POLICY_MEMO:
        return copy.deepcopy(_VERIFIED_POLICY_MEMO[cache_key])

    try:
        payload = policy_path.read_bytes()
        sig_b64 = sig_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    if not _verify_signature(payload, sig_b64):
        sys.stderr.write("[prismor] remote policy signature INVALID — ignoring\n")
        return None

    try:
        import yaml
        parsed = yaml.safe_load(payload.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None

    meta = {}
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    parsed["_remote_meta"] = meta

    _VERIFIED_POLICY_MEMO.clear()
    _VERIFIED_POLICY_MEMO[cache_key] = parsed
    return copy.deepcopy(parsed)


def _cache_is_fresh(ttl: float) -> bool:
    try:
        meta = json.loads(_meta_path().read_text(encoding="utf-8"))
        return (time.time() - float(meta.get("fetched_at", 0))) < ttl
    except (OSError, ValueError):
        return False


def fetch(ttl: float = DEFAULT_TTL_SECONDS, force: bool = False) -> bool:
    """Refresh the cached remote policy from the control plane if stale.

    Best-effort and non-blocking semantics: returns True if a fresh, verified
    policy was written; False otherwise (not enrolled, fresh cache, network
    error, or signature failure). Never raises.
    """
    ident = _identity.load_identity()
    if not ident:
        return False
    if _identity.revoked_backoff_active():
        return False  # key was rejected — back off instead of hammering
    if not force and _cache_is_fresh(ttl):
        return False

    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = (
        f"{base}/api/policy/resolve"
        f"?device_id={ident.get('device_id')}&org_id={ident.get('org_id')}"
    )
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {ident.get('device_key')}"},
        method="GET",
    )
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        _identity.clear_revoked()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            _identity.mark_revoked(f"policy fetch rejected ({exc.code})")
            sys.stderr.write(
                "[prismor] control plane rejected this device's key "
                f"({exc.code}) — keeping last good policy. Re-enroll with: prismor enroll <token>\n"
            )
        else:
            sys.stderr.write(f"[prismor] remote policy fetch failed: {exc}\n")
        return False
    except (urllib.error.URLError, ValueError, OSError) as exc:
        sys.stderr.write(f"[prismor] remote policy fetch failed: {exc}\n")
        return False

    policy_yaml = body.get("yaml")
    signature = body.get("signature")
    if not policy_yaml or not signature:
        return False
    if not _verify_signature(policy_yaml.encode("utf-8"), signature):
        sys.stderr.write("[prismor] fetched remote policy failed verification — discarding\n")
        return False

    # Developer-facing transparency: detect the org flipping capture mode.
    # The resolved policy carries the org's full_capture decision in the
    # forced prismor output entry; surface a notice the moment it changes so
    # a developer always knows when raw detail starts (or stops) leaving
    # their machine.
    full_capture = _extract_full_capture(policy_yaml)
    prev_meta: Dict[str, Any] = {}
    try:
        prev_meta = json.loads(_meta_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    prev_capture = prev_meta.get("full_capture")
    if prev_capture is not None and bool(prev_capture) != full_capture:
        if full_capture:
            sys.stderr.write(
                "[prismor] NOTICE: your org admin enabled FULL telemetry capture — "
                "flagged events now include scrubbed content (not just metadata). "
                "Check `prismor enroll-status` for details.\n"
            )
        else:
            sys.stderr.write(
                "[prismor] NOTICE: your org switched telemetry back to redacted-only "
                "(metadata + hashes; no content leaves this machine).\n"
            )

    home = _identity.prismor_home()
    home.mkdir(parents=True, exist_ok=True)
    cached_policy_path().write_text(policy_yaml, encoding="utf-8")
    _cached_sig_path().write_text(signature, encoding="utf-8")
    # The cloak hooks are bash and read pattern files, not this YAML: project
    # the org's secret patterns to a file they load. Verified policy only -
    # this runs after the signature check above. Best-effort, never fatal.
    try:
        from prismor.runtime.cloaking.patterns import write_org_patterns
        write_org_patterns(_extract_cloak_patterns(policy_yaml))
    except Exception as exc:
        sys.stderr.write(f"[prismor] could not apply org cloak patterns: {exc}\n")
        _meta_path().write_text(json.dumps({
        "fetched_at": time.time(),
        "version": body.get("version"),
        "profile_id": body.get("profile_id"),
        "scope": body.get("scope"),
        "full_capture": full_capture,
    }), encoding="utf-8")
    clear_policy_cache()
    return True


def _extract_cloak_patterns(policy_yaml: str) -> List[str]:
    """The org's ``settings.cloak_patterns`` list. Empty on any parse problem."""
    try:
        import yaml
        parsed = yaml.safe_load(policy_yaml)
        pats = (((parsed or {}).get("settings") or {}).get("cloak_patterns")) or []
        return [str(p) for p in pats if p] if isinstance(pats, list) else []
    except Exception:
        return []


def _extract_full_capture(policy_yaml: str) -> bool:
    """Read the org's full_capture decision from the resolved policy's forced
    prismor output entry. False on any parse problem (the privacy-safe default)."""
    try:
        import yaml
        parsed = yaml.safe_load(policy_yaml)
        outputs = (((parsed or {}).get("settings") or {}).get("outputs")) or []
        for out in outputs:
            if isinstance(out, dict) and str(out.get("type", "")).lower() == "prismor":
                return bool(out.get("full_capture", False))
    except Exception:
        pass
    return False
