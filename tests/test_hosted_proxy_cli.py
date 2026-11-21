"""prismor hosted-proxy connect: env-file handling and provider pick (no network)."""
from prismor.runtime.hosted_proxy_cli import app_base_url, pick_provider, read_env, set_env


def test_read_and_rewrite_env_keeps_names_and_other_lines():
    text = "# app\nexport OPENROUTER_BASE_URL=https://openrouter.ai/api/v1\nOPENROUTER_API_KEY='sk-or-x'\nPORT=3000\n"
    assert read_env(text) == {"OPENROUTER_BASE_URL": "https://openrouter.ai/api/v1",
                              "OPENROUTER_API_KEY": "sk-or-x", "PORT": "3000"}
    out = set_env(text, {"OPENROUTER_BASE_URL": "https://proxy.prismor.dev/v1",
                         "OPENROUTER_API_KEY": "prism_agent_k", "NEW": "1"})
    assert out == ("# app\nexport OPENROUTER_BASE_URL=https://proxy.prismor.dev/v1\n"
                   "OPENROUTER_API_KEY=prism_agent_k\nPORT=3000\nNEW=1\n")


def test_commented_lines_are_left_alone():
    assert read_env("# OPENAI_API_KEY=old\n") == {}
    assert set_env("# OPENAI_API_KEY=old\n", {"OPENAI_API_KEY": "k"}) == "# OPENAI_API_KEY=old\nOPENAI_API_KEY=k\n"


def test_pick_provider():
    assert pick_provider("https://openrouter.ai/api/v1/", None) == ("custom", "https://openrouter.ai/api/v1")
    assert pick_provider("https://api.openai.com/v1", None) == ("openai", None)
    assert pick_provider("https://api.anthropic.com", None) == ("anthropic", None)
    assert pick_provider(None, "gemini") == ("gemini", None)
    assert pick_provider(None, None) == ("openai", None)


def test_app_base_url():
    assert app_base_url("https://proxy.prismor.dev", "custom") == "https://proxy.prismor.dev/v1"
    assert app_base_url("https://proxy.prismor.dev/", "anthropic") == "https://proxy.prismor.dev"
