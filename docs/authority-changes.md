# When authority changes during a call

Prismor judges a tool call before it runs. If an account is restricted or an
agent is paused after that, three more checks can stop the call. Each one
writes the refusing rule and policy version to the signed trail.

| Check | Where | Trail status |
|---|---|---|
| After a human approves a step-up | built in to approvals | `revoked_after_approval` |
| At commit, the moment the effect is applied | `inflight.recheck_before_commit` in the tool, or the downstream API calls the eval-server | `revoked_before_commit` |
| While the call runs | async SDK tools, MCP gateway | `cancelled_in_flight` |

## At commit

A slow tool spends most of its time on lookups and applies its effect at the
end. Re-check there. `resource` can be a function, so the check judges the
account as it is now:

```python
from prismor.runtime import inflight

decision = evaluate_tool_call(event=event, workspace=ws, agent="sdk", resource=acct_resource(acct))

def freeze_account(acct):
    history = load_history(acct)              # slow
    inflight.recheck_before_commit(           # raises inflight.Refused
        decision, resource=lambda: acct_resource(acct), tool="freeze_account")
    core_banking.freeze(acct)
```

The re-check forces a policy fetch, so a pause set in the console since the
allow is seen.

If the side effect lives in another service, that service can ask Prismor
itself at commit time through the [eval-server](authzen.md). This needs no
agent-side change:

```bash
# inside freeze_account's handler, just before it writes
curl -s localhost:7071/access/v1/evaluation -H "Authorization: Bearer $KEY" -d '{
  "subject": {"type": "agent", "id": "account-freezer"},
  "action": {"name": "freeze_account"},
  "resource": {"type": "account", "id": "ACC-3300", "properties": {"status": "restricted"}}}'
# {"decision": false, "context": {"rule_id": "nw-restricted-account", ...}} -> do not write
```

## While the call runs

| Surface | What happens |
|---|---|
| LangChain async tools | The tool runs as a task. On each policy refresh the call is re-checked; if it would now be refused, the task is cancelled and the agent gets the refusal. |
| Other SDKs | Wrap the coroutine yourself: `await inflight.run_cancellable(decision, tool(...))`. |
| MCP gateway | Calls are re-checked on each refresh. On refusal the upstream server gets `notifications/cancelled` and the client a refusal. |
| Sync Python tools | Cannot be stopped mid-run. Use `recheck_before_commit` at the commit point. `inflight.wait_cancellable` stops waiting, but the thread finishes in the background. |
| Claude Code, Codex, Copilot hooks | The harness runs the tool, so Prismor cannot stop it. Only the pre-call check applies. |

A cancel can only be as fast as the revoke reaches the device. Policy arrives
by poll: every `PRISMOR_POLICY_REFRESH_SECONDS` (default 30, minimum 5). A
restriction that rides on the call's `resource` is seen at the next re-check
with no poll.
