# Secret leak guards

Cloak keeps secret values out of the model context. These guards stop the
other ways an agent can move a secret: to a file, to a host, to a public
registry, or out of a token store that Cloak does not manage.

They are on by default after `prismor cloak install` (the hook guards) and
with the default policy (the rules). You do not configure them.

| Guard | What it stops | Result |
|---|---|---|
| [Vault flow](#vault-flow) | A vaulted `.env` sent anywhere other than the scrubbed tool output | deny |
| [Raw values in tool input](#raw-values-in-tool-input) | A real vaulted value in a Write, Edit or MCP call | deny |
| [MCP output scrub](#mcp-output-scrub) | A key in the result of an MCP tool | key is replaced |
| [Token stores](#token-stores-and-credential-commands) | Shell reads of CLI token files and browser cookie stores | deny |
| [Credential commands](#token-stores-and-credential-commands) | Commands that print, mint or copy a credential | ask |
| [Production secrets](#production-secrets) | Reading env, secrets or databases on a production host | ask |
| [Publish gate](#publish-gate) | A build, push or upload that would ship a secret | deny |

"Ask" means the user approves the call. "Deny" means the call does not run, and
the message tells the agent what to do instead.

## Vault flow

After `prismor cloak add --env-file .env`, every value in `.env` is in the
vault. The Bash output scrub replaces those values in what the model sees. But
the scrub sees only the tool output. A command that sends the file somewhere
else would send the real values.

So when a `.env` file is fully vaulted, a Bash command can show it, but cannot
send it anywhere else:

```bash
grep -c KEY .env                         # allowed: output is scrubbed
sed 's/=.*/=<set>/' .env                 # allowed
ls -la .env* | awk '{print $9}'          # allowed: names only
cat .env | curl -d @- https://...        # denied: piped into a sender
cat .env > copy.txt                      # denied: copied to a file
python3 -c "print(open('.env').read())"  # denied: a script reads it
```

These also pass: heredocs that only contain the text `.env`, loops that only
print, `prismor cloak ...`, `vercel env pull`, a copy into another env file,
and `git commit`.

To use a value in a command, use its placeholder. Decloak puts the real value
in at run time:

```bash
curl -H "Authorization: Bearer @@SECRET:OPENAI_API_KEY@@" https://api.openai.com/v1/models
```

To start your app with its env file, run it yourself or load the env in the app.
`node --env-file=.env` from the agent is denied, because the process gets the
real values.

## Raw values in tool input

Decloak runs only for Bash. If the agent writes a real vaulted value into a
file, an edit or an MCP call, nothing replaces it. `secret-guard` denies that
call. Use the placeholder in Bash, or read the value from the environment in
code:

```python
KEY = os.environ["OPENAI_API_KEY"]   # good
KEY = "sk-proj-..."                  # denied when the value is in the vault
```

## MCP output scrub

When an MCP tool returns a string that matches a key pattern, `recloak-mcp`
puts it in the vault and replaces it with its placeholder before the model sees
it. The agent can still use the key through the placeholder.

## Token stores and credential commands

CLI tools keep tokens in files that Cloak does not manage. These rules cover them.

| Rule | Example | Result |
|---|---|---|
| `credential-store-shell-read` | `cat ~/.kube/config`, `cat ~/.config/gh/hosts.yml`, a query on a browser cookie DB, a tar of `~/.aws` | deny |
| `secret-access` | The Read tool on the same files | deny |
| `credential-print` | `gh auth token`, `aws configure get aws_secret_access_key`, `gcloud auth print-access-token`, `kubectl config view --raw` | ask |
| `credential-mint` | `aws iam create-access-key`, `kubectl create token` | ask |
| `clipboard-read` | `pbpaste` into the output | ask |

The usual commands still work: `kubectl --kubeconfig ~/.kube/config get pods`,
`gh auth status`, `aws sts get-caller-identity`, `pbpaste > file`, and
`TOKEN="$(gh auth token)" npx server` (the token goes to the process, not the
output). Writing `.env.example` is allowed.

## Production secrets

`prod-secret-read` asks before the agent reads live production credentials:

```bash
ssh deploy@prod-api 'cat /srv/app/.env'       # ask
kubectl get secret app -n dev -o yaml         # ask, in any namespace
kubectl exec -n prod deploy/api -- printenv   # ask
psql "postgres://admin@prod-db/app" -c "..."  # ask
scp deploy@prod-api:/srv/app/.env ./          # ask
```

Usual production work does not ask: `tail` logs, `systemctl restart`,
`kubectl get pods`, `kubectl describe secret` and `scp` of a release to the
host. Prismor knows a production host or namespace from its name (`prod`,
`production`, `prd`).

## Publish gate

A build, push or upload ships files, not context, so the scrub cannot help.
Before one of these commands runs, the publish gate lists the files the command
would ship and looks in them, and in archives inside them, for an env file
with values, a vaulted value, or a string that looks like a key.

| Command | What it checks |
|---|---|
| `docker build`, `podman build`, `buildah bud` | the build context, minus `.dockerignore` |
| `npm publish` / `pack` (and pnpm, yarn, bun), `cargo publish` | the files the package would contain |
| `git add` | the files it would stage |
| `git push` | the commits that are not on any remote yet |
| `gh release upload/create`, `gh gist create`, `twine upload`, `gem push` | the files named, and an archive built earlier in the same command |
| `curl -F/-T/--data-binary @file`, `wget --post-file` | the file named |
| `aws s3 cp` / `gsutil cp` with a public ACL | the file named |

Example message:

```
`docker build` would ship the env file '.env'
```

To fix it, add the file to `.dockerignore` or `.gitignore`, remove the value
from the file, or use a placeholder. `scp` and `rsync` to a host, and private
bucket copies, are not checked: they go to storage you control.

## When a guard is wrong

The block message has the steps. The user runs them in their own terminal:

```bash
prismor approvals approve <id>                                  # this call, once
prismor allow credential-print --pattern 'gh auth token' --expires 2h
prismor allow prod-secret-read --observe                        # report, do not ask
```

To leave out a hook guard when you install Cloak:

```bash
prismor cloak install --no-env-guard      # no vault-flow or unimported-.env check
prismor cloak install --no-secret-guard   # no raw-value check on tool input
```

## Limits

- The guards look at the tool call. Code that the agent runs (a script or a
  package) can open files and connect to hosts in ways a command line does not
  show. Use the [sandbox](sandbox.md) and [egress control](network-isolation.md)
  for that.
- A file name built at run time is not seen as a `.env` file.
- The publish gate reads at most 20,000 files and skips files over 5 MB.

## See also

- [Sweep and Cloak](sweep-and-cloak.md): the vault, placeholders and the scrub
- [Residual risk](residual-risk.md): what the hooks cannot see
- [Policy layers and exemptions](policy-layers-and-exemptions.md): how `prismor allow` works
