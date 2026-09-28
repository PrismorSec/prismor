# Prismor

Local runtime security monitor for AI coding agents. Intercepts agent actions via hooks, evaluates them against deterministic security policies, and optionally blocks dangerous behavior before it executes.

## Supported Agents

| Agent | Hook Events | Enforce Mode |
|-------|------------|--------------|
| Claude Code | PreToolUse, PostToolUse, UserPromptSubmit, Stop | Yes |
| Cursor | before/afterShellCommand, before/afterFileWrite, beforeSubmitPrompt | Yes |
| Windsurf | pre/post_run_command, pre/post_write_code, pre/post_read_code, pre_user_prompt, pre/post_mcp_tool_use, post_cascade_response | Yes |

## Quick Start

```bash
# Install hooks for all agents in observe mode (log only)
python3 prismor/runtime/cli.py install-hooks --agent all --workspace "$(pwd)"

# Install in enforce mode (log + block dangerous actions)
python3 prismor/runtime/cli.py install-hooks --agent claude --workspace "$(pwd)" --mode enforce

# Analyze a session file
python3 prismor/runtime/cli.py analyze --input prismor/runtime/examples/sample-session.jsonl

# JSON output for automation
python3 prismor/runtime/cli.py analyze --input prismor/runtime/examples/sample-session.jsonl --json
```

## Commands

| Command | Description |
|---------|-------------|
| `analyze --input <file>` | Evaluate a JSONL session file and print findings |
| `ingest --input <file>` | Analyze and store a session in the local database |
| `sessions` | List stored sessions |
| `session --session-id <id>` | Show details for a specific session |
| `install-hooks --agent <agent>` | Install Prismor hooks into agent config |
| `uninstall-hooks --agent <agent>` | Remove Prismor hooks from agent config |
| `hook-dispatch --agent <agent>` | Internal: called by hooks to evaluate events in real time |
| `hookd [status\|stop\|restart]` | Warm hook daemon that `hook-dispatch` hands calls to (see `hookd.py`); starts on demand, `PRISMOR_HOOKD=0` disables |

All commands accept `--workspace <path>` to specify the project directory.

## Modes

- **observe** (default): Log all events and findings. No blocking.
- **enforce**: Log everything and block pre-action events that match critical policies (destructive commands, secret exfiltration, remote code execution, prompt injection, sensitive file access).

## What Gets Flagged

| Category | Severity | Examples |
|----------|----------|----------|
| `destructive_command` | CRITICAL | `sudo rm`, `rm -rf /`, `mkfs`, `dd of=/dev/` |
| `secret_exfiltration` | CRITICAL | `cat .env \| curl`, reading secrets then hitting network |
| `remote_execution` | HIGH | `curl ... \| bash`, `wget ... \| sh` |
| `prompt_injection` | HIGH | "ignore previous instructions", "reveal system prompt" |
| `secret_access` | HIGH/CRITICAL | Reading/writing `.env`, `.ssh/id_rsa`, `.aws/credentials` |
| `risky_write` | MEDIUM/HIGH | Writing to `Dockerfile`, CI workflows, dependency manifests |
| `suspicious_network` | HIGH | Requests to webhook.site, ngrok, pastebin, discord webhooks |

## Storage

Prismor stores state locally under `.prismor/` in the workspace:

```
.prismor/
  prismor.db              # SQLite: sessions, findings, metadata
  sessions/
    <session-id>.jsonl   # Raw event stream per session
```

## Uninstalling

```bash
# Remove hooks from all agents
python3 prismor/runtime/cli.py uninstall-hooks --agent all --workspace "$(pwd)"

# Remove hooks from a specific agent
python3 prismor/runtime/cli.py uninstall-hooks --agent cursor --workspace "$(pwd)"
```

This removes Prismor entries from agent hook configs but does not delete stored session data.
