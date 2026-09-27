"""prismor/runtime/inference_hook_cli.py — `prismor inference-hook <serve|test|secret>`.

``serve``  runs the AI security server (see inference_hook_server.py).
``test``   sends a signed sample prompt frame — exactly what Anthropic sends —
           to a running server and prints the verdict; or, with no ``--url``,
           evaluates the frame in-process so you can tune policy without a
           server. Exit code: 0 allow, 1 deny, 2 error — CI-friendly.
``secret`` prints a fresh ``whsec_`` secret for local end-to-end runs.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.inference_hook import (
    ChannelConfig,
    evaluate_turn,
    generate_secret,
    resolve_config,
    sample_frame,
    signature_headers,
)

SAMPLES = ("clean", "pci", "secret", "injection", "config-test")


def _load_frame(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"[prismor] frame file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"[prismor] frame is not valid JSON ({p}): {exc}")
    if not isinstance(data, dict):
        raise SystemExit("[prismor] frame must be a JSON object")
    return data


def _post(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "anthropic-dlp/1 (prismor inference-hook test)")
    req.add_header("Accept-Encoding", "identity")
    for k, v in headers.items():
        req.add_header(k, v)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-supplied URL  # nosec B310
            raw = resp.read(64 * 1024)
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(64 * 1024)
        status = exc.code
    except Exception as exc:
        return {"_error": f"request failed: {exc}", "_ms": int((time.perf_counter() - t0) * 1000)}
    ms = int((time.perf_counter() - t0) * 1000)
    try:
        parsed = json.loads(raw or b"{}")
    except Exception:
        parsed = {"_error": f"non-JSON response ({len(raw)} bytes)"}
    if not isinstance(parsed, dict):
        parsed = {"_error": "response is not a JSON object"}
    parsed["_status"] = status
    parsed["_ms"] = ms
    return parsed


def _print_verdict(label: str, wire: Dict[str, Any], *, as_json: bool) -> int:
    """Render one verdict; return the exit code it implies."""
    if as_json:
        print(json.dumps({"sample": label, **wire}, indent=2, default=str))
    err = wire.get("_error")
    status = wire.get("_status", 200)
    action = wire.get("action")
    if err or status != 200 or action not in ("allow", "deny"):
        if not as_json:
            why = err or f"HTTP {status}" if err or status != 200 else f"action={action!r}"
            print(f"  {label:12s}  FAIL   webhook failure - {why}")
            if wire.get("detail"):
                print(f"               {wire['detail']}")
        return 2
    if as_json:
        return 0 if action == "allow" else 1
    pr = wire.get("prismor") or {}
    ms = wire.get("_ms")
    tail = []
    if pr.get("rule_id"):
        tail.append(str(pr["rule_id"]))
    if pr.get("basis") and pr["basis"] not in ("policy",):
        tail.append(f"basis={pr['basis']}")
    if pr.get("auth"):
        tail.append(f"auth={pr['auth']}")
    if ms is not None:
        tail.append(f"{ms}ms")
    mark = "ALLOW " if action == "allow" else "DENY  "
    print(f"  {label:12s}  {mark} {' · '.join(tail)}")
    if action == "deny" and wire.get("deny_reason"):
        print(f"               -> {wire['deny_reason']}")
    shadow = pr.get("shadow")
    if shadow:
        print(f"               (shadow: would deny - {shadow.get('deny_reason')})")
    return 0 if action == "allow" else 1


def cmd_test(
    *,
    url: Optional[str],
    secret: Optional[str],
    samples: List[str],
    frame_path: Optional[str],
    tenant: str,
    application: str,
    bearer: Optional[str],
    unsigned: bool,
    timeout: float,
    workspace: Optional[Path],
    as_json: bool,
    expect: Optional[str],
) -> int:
    """Run the test client. Returns the process exit code."""
    frames: List[tuple[str, Dict[str, Any]]] = []
    if frame_path:
        frames.append((Path(frame_path).name, _load_frame(frame_path)))
    else:
        wanted = samples or ["clean", "pci", "secret", "injection"]
        if wanted == ["all"]:
            wanted = list(SAMPLES)
        for kind in wanted:
            if kind not in SAMPLES:
                raise SystemExit(f"[prismor] unknown sample {kind!r}; choose from {', '.join(SAMPLES)}, all")
            frames.append((kind, sample_frame(kind, tenant_id=tenant, application=application)))

    # Expected outcomes for the built-in samples so `--expect` / CI can assert.
    expected = {"clean": "allow", "config-test": "allow", "pci": "deny", "secret": "deny", "injection": "deny"}

    if not as_json:
        target = url or "in-process (no --url)"
        auth = "unsigned" if unsigned else ("bearer" if bearer else ("signed" if (secret or not url) else "unsigned"))
        print(f"[prismor] inference-hook test -> {target}  ({auth})")

    worst = 0
    mismatches: List[str] = []
    for label, frame in frames:
        if url:
            body = json.dumps(frame, separators=(",", ":")).encode()
            headers: Dict[str, str] = {}
            if bearer:
                headers["Authorization"] = f"Bearer {bearer}"
            elif secret and not unsigned:
                headers.update(signature_headers(secret, message_id=str(frame.get("request_id") or label), body=body))
            wire = _post(url, body, headers, timeout)
        else:
            cfg: ChannelConfig = resolve_config(tenant, workspace=workspace)
            verdict = evaluate_turn(frame, config=cfg, workspace=workspace)
            wire = verdict.to_wire(org_id=tenant, footer=cfg.deny_footer)
            wire["_status"] = 200
            wire["_ms"] = verdict.eval_ms
        code = _print_verdict(label, wire, as_json=as_json)
        worst = max(worst, code)
        want = expect or expected.get(label)
        if want and code in (0, 1) and wire.get("action") != want:
            mismatches.append(f"{label}: expected {want}, got {wire.get('action')}")

    if mismatches:
        if not as_json:
            print("[prismor] unexpected verdicts:")
            for m in mismatches:
                print(f"  - {m}")
            print("[prismor] hint: the deny floor (pii_exposure, secret_*, prompt_injection*) is on by default;\n"
                  "         if a sample allowed, check the server's --workspace policy and PRISMOR_INFERENCE_HOOK_MODE.")
        return 2
    return worst if frame_path or expect else 0


def cmd_secret() -> int:
    print(generate_secret())
    return 0
