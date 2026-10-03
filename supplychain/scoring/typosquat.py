"""Typosquatting detection via Levenshtein distance on popular package names."""
from __future__ import annotations

from typing import Dict, List, Optional

POPULAR_PACKAGES: Dict[str, List[str]] = {
    "npm": [
        "react", "lodash", "express", "webpack", "typescript",
        "axios", "moment", "jest", "babel", "eslint",
        "next", "vue", "angular", "tailwindcss", "vite",
        "redux", "graphql", "prisma", "zod", "langchain",
        "langfuse",
    ],
    "pnpm": [
        "react", "lodash", "express", "webpack", "typescript",
        "axios", "moment", "jest", "babel", "eslint",
        "next", "vue", "angular", "tailwindcss", "vite",
    ],
    "yarn": [
        "react", "lodash", "express", "webpack", "typescript",
        "axios", "moment", "jest", "babel", "eslint",
    ],
    "bun": [
        "react", "lodash", "express", "webpack", "typescript",
        "axios", "moment", "jest", "babel", "eslint",
    ],
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django",
        "fastapi", "pytest", "boto3", "tensorflow", "torch",
        "langchain", "openai", "anthropic", "pydantic", "sqlalchemy",
        "celery", "redis", "aiohttp", "httpx", "click",
        "langfuse", "haystack-ai", "dspy", "mirascope", "instructor",
        "ollama", "gradio", "smolagents", "crewai", "pyautogen",
        "langflow", "promptfoo",
    ],
    "pip": [
        "requests", "numpy", "pandas", "flask", "django",
        "fastapi", "pytest", "boto3", "tensorflow", "torch",
        "langchain", "openai", "anthropic", "pydantic", "sqlalchemy",
        "langfuse", "haystack-ai", "dspy", "mirascope", "instructor",
        "ollama", "gradio", "smolagents", "crewai", "pyautogen",
    ],
    "uv": [
        "requests", "numpy", "pandas", "flask", "django",
        "fastapi", "pytest", "boto3", "tensorflow", "torch",
    ],
    "poetry": [
        "requests", "numpy", "pandas", "flask", "django",
        "fastapi", "pytest", "boto3", "tensorflow", "torch",
    ],
    "cargo": [
        "serde", "tokio", "hyper", "reqwest", "clap",
        "anyhow", "thiserror", "tracing", "axum", "actix-web",
    ],
    "go": [
        "gorm", "gin", "echo", "fiber", "chi",
    ],
}


def _edit_distance(a: str, b: str) -> int:
    """Edit distance between a and b, counting a swap of two neighbours as one.

    Plain Levenshtein scores a swapped pair as two edits, so ``reqeusts``
    sat at distance 2 from ``requests`` and slipped under the distance-1
    threshold for short names (#555). A swap is one keystroke slip, the
    commonest typo there is, so it costs one edit here (optimal string
    alignment distance).
    """
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (ca != cb)
            cost = min(insertions, deletions, substitutions)
            if i and j and ca == b[j - 1] and a[i - 1] == cb:
                cost = min(cost, prev2[j - 1] + 1)
            curr.append(cost)
        prev2, prev = prev, curr
    return prev[-1]


def check_typosquat(package_name: str, ecosystem: str) -> Optional[str]:
    """Check if package_name is a typosquat of a popular package.

    Returns the trusted package name being mimicked, or None.
    Strips npm @scope/ prefix for comparison.
    """
    name_lower = package_name.lower()

    # Strip npm/pnpm scope prefix (e.g. @scope/pkg -> pkg)
    if name_lower.startswith("@") and "/" in name_lower:
        name_lower = name_lower.split("/", 1)[1]
    elif name_lower.startswith("@"):
        name_lower = name_lower[1:]

    # Normalize hyphens for comparison (some package names are dash-heavy)
    name_normalized = name_lower.replace("-", "").replace("_", "")

    trusted = POPULAR_PACKAGES.get(ecosystem, [])

    for trusted_name in trusted:
        if name_lower == trusted_name:
            return None

        trusted_normalized = trusted_name.replace("-", "").replace("_", "")
        distance = _edit_distance(name_normalized, trusted_normalized)

        # Threshold: distance 1 for names up to ~10 chars, distance 2 for longer
        threshold = 1 if len(trusted_name) <= 10 else 2
        if distance <= threshold and abs(len(name_normalized) - len(trusted_normalized)) <= 2:
            return trusted_name

    return None
