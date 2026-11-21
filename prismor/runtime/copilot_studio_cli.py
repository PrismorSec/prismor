"""`prismor copilot-studio setup|test`: the setup values and an in-process check.

    prismor copilot-studio setup --tenant <tenant id> --endpoint https://cs.example.com/copilot-studio
    prismor copilot-studio test [--sample clean|external|credential|injection|all]
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional


def cmd_setup(tenant: str, endpoint: str, app_id: str = "", as_json: bool = False) -> int:
    from prismor.runtime.copilot_studio import setup_values

    try:
        v = setup_values(tenant, endpoint, app_id)
    except ValueError as exc:
        print(f"[prismor] {exc}")
        return 2
    if as_json:
        print(json.dumps(v, indent=2))
        return 0
    fic, pp, env = v["federated_credential"], v["power_platform"], v["server_env"]
    print("1. Entra ID > App registrations > New registration (single tenant)")
    print(f"   Expose an API > Application ID URI:  {v['entra_app']['application_id_uri']}")
    print("   (the host must be a verified custom domain of the tenant)")
    print("")
    print("2. Same app > Certificates & secrets > Federated credentials > Add credential")
    print(f"   Scenario:  {fic['scenario']}")
    print(f"   Issuer:    {fic['issuer']}")
    print(f"   Subject:   {fic['subject']}")
    print(f"   Audience:  {fic['audience']}")
    print("")
    print("3. Power Platform admin center > Security > Threat detection >")
    print("   Additional threat detection > pick the environment > Set up")
    print(f"   Azure Entra App ID:  {pp['app_id']}")
    print(f"   Endpoint link:       {pp['endpoint']}")
    print("")
    print("4. The Prismor server (or register the tenant + app id in the console:")
    print("   Integrations > Microsoft Copilot Studio, then run with PRISMOR_AGENT_KEY)")
    for k, val in env.items():
        print(f"   {k}={val}")
    return 0


def cmd_test(samples: Optional[List[str]] = None, workspace: Optional[Path] = None,
             user_messages: Optional[str] = None, as_json: bool = False) -> int:
    from prismor.runtime.copilot_studio import SAMPLES, analyze, sample_request

    kinds = list(SAMPLES) if not samples or "all" in samples else samples
    ws = workspace or Path.cwd()
    for kind in kinds:
        t0 = time.perf_counter()
        verdict = analyze(sample_request(kind), ws, user_messages=user_messages)
        ms = int((time.perf_counter() - t0) * 1000)
        if as_json:
            print(json.dumps({"sample": kind, "ms": ms, **verdict}))
            continue
        word = "BLOCK" if verdict.get("blockAction") else "ALLOW"
        reason = f"  {verdict['reason']}" if verdict.get("reason") else ""
        print(f"{word:<5}  {kind:<10}  {ms:>4}ms{reason}")
    return 0
