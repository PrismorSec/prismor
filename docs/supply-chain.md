# Supply Chain Enforcement

Prismor wraps your package manager so every install is evaluated before it runs. The `prismor` CLI intercepts the command, scores each package against live threat intelligence, then either passes through to the real package manager or blocks with a reason.

See [LLM_FRAMEWORK_COVERAGE.md](../LLM_FRAMEWORK_COVERAGE.md) for which LLM app frameworks/libraries (LangChain, CrewAI, Langfuse, etc.) currently have NVD advisory tracking and typosquat protection.

---

## Usage

```bash
prismor supplychain npm install express
prismor supplychain pip install requests numpy
prismor supplychain pnpm add lodash
prismor supplychain uv add fastapi
prismor supplychain cargo add serde
prismor supplychain go get github.com/some/pkg
```

Any command that isn't a recognised package install passes through transparently - so you can alias `npm` or `pip` to `prismor` without breakage.

```bash
# Alias-based transparent wrapping
alias npm="prismor supplychain npm"
alias pip="prismor supplychain pip"
```

---

## Output

```
  PRISMOR  supply chain  [npm]
  ────────────────────────────────────────────────────

  BLOCK  score 100  @tanstack/react-router  age 1d, 3 maintainers
             +100 @tanstack/* - 42 packages compromised May 11 2026 via CI/CD cache
                  poisoning. SLSA attestations do NOT protect against this.
             +100 known malicious payload referenced: router_init.js
             +50  Bun runtime execution in install script

  WARN   score  35  github:user/pkg
             +35 git/GitHub dependency bypasses registry

  ALLOW  score   0  express  age 5612d, 5 maintainers

  Blocked: @tanstack/react-router
  To override: add to supply_chain.allowlist in .prismor/policy.yaml
```

---

## Scoring

Each package is scored additively. IOC matches bypass the threshold and force a block regardless of total score.

| Signal | Points |
|---|---|
| Known compromised package / IOC match | +100 (force block) |
| C2 domain in install script | +100 (force block) |
| Known malicious payload in install script | +100 (force block) |
| Bun runtime download in install script | +100 (force block) |
| Credential env var access in install script (`AWS_SECRET`, `GITHUB_TOKEN`, etc.) | +50 |
| Persistence write in install script (`.claude/settings.json`, `.vscode/tasks.json`) | +50 |
| git / GitHub dependency bypasses registry | +35 |
| tarball install bypasses registry | +25 |
| Package published < 7 days ago | +25 |
| Package published < 30 days ago | +15 |
| Has postinstall/preinstall script | +20 |
| Single maintainer | +10 |
| Custom `--registry` flag | +10 |
| Local path dependency | +10 |
| Maintainer data unavailable | +8 |

**Verdicts:** `< 30` allow · `30–59` warn · `≥ 60` block

**Known vulnerabilities (OSV.dev).** The version being installed is checked
against OSV: +50 critical, +30 high, +15 medium, +5 low, at most three
advisories. Without a pinned version, the registry's latest version is used
(npm, PyPI, crates.io, RubyGems, Packagist and the Go proxy). When no version
can be resolved (Maven), only malicious-package advisories count, since every
historical advisory would otherwise score a current, patched package 100/100.

**Malicious packages block in every mode.** An install that matches the IOC
list or an OSV/GitHub malware advisory (`MAL-*`, CWE-506 "is malware") is the
safety floor, like `curl | bash`: the hook blocks it whatever `default_mode`
says, including under `prismor setup --recommended`. Merely vulnerable
versions follow the policy mode (a warning unless you enforce the rule).

`prismor deps` runs the same OSV lookup over the exact versions in your
manifests and lockfiles (`--offline` skips it) and names the source of each
match: OSV.dev, the signed advisory feed, or the bundled IOC list.

---

## Supported Ecosystems

| Ecosystem | Commands intercepted |
|---|---|
| npm | `npm install`, `npm i`, `npm add` |
| pnpm | `pnpm install`, `pnpm add`, `pnpm i` |
| yarn | `yarn add` |
| bun | `bun add`, `bun install` |
| pip | `pip install`, `pip3 install` |
| uv | `uv add`, `uv pip install` |
| poetry | `poetry add` |
| cargo | `cargo add`, `cargo install` |
| go | `go get`, `go install` |

---

## Threat Intelligence

The IOC database lives in [`supplychain/ioc.py`](../supplychain/ioc.py). It is checked before any registry call - IOC matches are immediate, not scored.

### Active advisories

**mini-shai-hulud - May 11, 2026** (attribution: TeamPCP)

GitHub Actions pwn-request against `TanStack/router` triggered a `pull_request_target` workflow with base repository permissions. The attacker poisoned the pnpm cache (1.1 GB entry) via malicious commit `79ac49ee`, extracted OIDC tokens directly from runner memory, then published backdoored packages with valid SLSA Build Level 3 attestations.

Affected packages (170+ total):

| Package | Ecosystem | Compromised versions |
|---|---|---|
| `@tanstack/*` | npm | all versions published May 11 2026 (42 packages) |
| `@opensearch-project/*` | npm | all versions published May 11 2026 |
| `@uipath/*` | npm | all versions published May 11 2026 (65 packages) |
| `@mistralai/mistralai` | npm | 1.7.1 - 2.2.4 |
| `mistralai` | PyPI | 2.4.6 (legitimate latest: 2.4.5) |
| `guardrails-ai` | PyPI | 0.10.1 (legitimate latest: 0.10.0) |

npm delivery: `preinstall` hook runs `setup.mjs`, downloads Bun runtime, executes `router_init.js` / `tanstack_runner.js` via `optionalDependencies` pointing to malicious GitHub commits.

PyPI delivery: payload injected into `__init__.py`, downloads `/tmp/transformers.pyz` on import.

Credential targets: GitHub tokens (`ghp_*`, `gho_*`, `ghs_*`), npm publish tokens (`npm_*`), AWS IAM (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), AWS instance metadata (`169.254.169.254`), HashiCorp Vault (`127.0.0.1:8200`), Kubernetes service accounts.

C2 infrastructure: `filev2.getsession.org` (Session Protocol exfiltration), `git-tanstack.com` (phishing domain, Cloudflare-flagged). Secondary C2 via GitHub GraphQL - encodes instructions in commit messages, exfiltrates via repo contents API.

Worm propagation: uses `createCommitOnBranch` GraphQL mutation to commit poisoned `.vscode/setup.mjs` and `.claude/setup.mjs` to feature branches, spreading to other developers who pull the branch.

Persistence: `.claude/settings.json`, `.claude/setup.mjs`, `.claude/router_runtime.js`, `.vscode/tasks.json`, `.vscode/setup.mjs`

Known payload hashes (SHA-256):
- `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` - `router_init.js`
- `ce7e4199506959fd7a71b64209b2c07b9c82e53a946aa7d78298dc9249230d01` - `tanstack_runner.js`

> Valid SLSA Build Level 3 attestations do **not** protect against this attack. The attacker held legitimate OIDC tokens at publish time. This is the first documented npm worm to produce valid SLSA attestations. Same threat actor (TeamPCP) was responsible for the March 2026 Trivy supply chain compromise.

References: [Prismor](https://prismor.dev/blog/tanstack-mistral-mini-shai-hulud-supply-chain) - [Snyk](https://snyk.io/blog/tanstack-npm-packages-compromised/) - [SafeDep](https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/)

---

### Adding new IOCs

Open [`supplychain/ioc.py`](../supplychain/ioc.py) and add to the relevant section:

```python
# Compromised package version range
_COMPROMISED_VERSIONS["@scope/package"] = [
    {
        "min": "1.0.0", "max": "1.2.3",
        "attack": "attack-id-YYYY-MM-DD",
        "note": "brief description with reference",
    }
]

# Compromised namespace
_COMPROMISED_NAMESPACES["@scope/"] = {
    "attack": "attack-id-YYYY-MM-DD",
    "affected_date": "YYYY-MM-DD",
    "note": "brief description",
}

# C2 domain
C2_DOMAINS |= {"evil.example.com"}

# Install script pattern
_SCRIPT_PATTERNS.append((
    re.compile(r"evil\.example\.com", re.I),
    "C2 domain: evil.example.com",
    "CRITICAL",
))
```

---

## Config Hardening

Install-time scoring only fires when the install command actually goes through `prismor`. If something invokes `npm install` directly (a CI step, an IDE plugin, an agent that doesn't honour the alias), the runtime gate is bypassed.

`prismor supplychain harden` closes that gap by hardening the package manager's own config files. It runs before any install happens and applies settings the package manager itself enforces.

```bash
prismor supplychain harden              # apply hardening to the current directory
prismor supplychain harden --dry-run    # preview without writing
prismor supplychain harden <path>       # harden a specific project root
```

What it does for each ecosystem detected in the project root:

| File | Trigger | Settings applied |
|---|---|---|
| `.npmrc` | `package.json` present | `ignore-scripts=true`, `save-exact=true`, `audit=true` |
| `.yarnrc` | file present | `--ignore-scripts true` |
| `.yarnrc.yml` | file present | `enableScripts: false` |
| `pip.conf` | `requirements.txt` / `pyproject.toml` / `setup.py` / `setup.cfg` | `no-input=true`, `disable-pip-version-check=true` |
| `.cargo/config.toml` | `Cargo.toml` present | `[net] retry=2`, `git-fetch-with-cli=true` |

Existing keys are never overwritten — if you've already set `save-exact=false` for a reason, the hardener leaves it and reports it. New settings are appended under a `# prismor supplychain harden` comment so they're easy to identify and remove later.

### Why these settings

**`ignore-scripts` / `enableScripts: false`** is the single highest-impact rule. Every npm supply chain attack in [`supplychain/ioc.py`](../supplychain/ioc.py) — mini-shai-hulud, the AntV hijacked-maintainer wave, the PyPI mistralai/guardrails-ai variant — delivered its payload via a `preinstall` or `postinstall` hook. Disabling lifecycle scripts at the config layer neutralises that vector regardless of whether `prismor` is in the call path.

**`save-exact=true`** is the closest thing to age-gating that npm offers natively. With the default SemVer caret ranges, `npm install express` writes `"express": "^4.18.2"` and a fresh `npm install` on a teammate's machine can resolve to any 4.x version published since — including a hijacked one published an hour ago. Pinning exact versions means the lockfile is the source of truth and new versions only enter the project when someone explicitly bumps them.

**`git-fetch-with-cli=true`** for Cargo routes git dependencies through your system `git` binary instead of cargo's built-in libgit2 fetcher. This respects your existing `.gitconfig`, SSH agent, and credential helpers — and makes git-based supply chain probes (private repo enumeration, malformed URL handling) the responsibility of a more battle-tested tool.

### Hardening + runtime scoring

The config hardening and the runtime scorer are complementary, not redundant:

- **Hardening** narrows the attack surface for *any* install (`npm install` direct, CI, agent without alias).
- **Runtime scoring** still catches the things hardening can't: a published-2-days-ago malicious package that has no install scripts but is named to typosquat a popular library, or a package whose name matches the IOC database.

Run `prismor supplychain harden` once when bootstrapping a project, and use the `prismor` wrapper for installs. The two together give you both a static gate (what the package manager itself enforces) and a dynamic gate (what the prismor scorer rejects).

### Caveats

- `pip.conf` is not auto-read from the project root. Activate with `export PIP_CONFIG_FILE=pip.conf` or place it at `$VIRTUAL_ENV/pip.conf` after creating the venv. The hardener prints this reminder.
- `ignore-scripts` will break packages that legitimately need install scripts (e.g. `node-gyp` native modules). Allow them per-package via `npm rebuild <pkg> --foreground-scripts` or pnpm's `onlyBuiltDependencies` allowlist in `package.json`.

---

## Architecture

```
prismor supplychain npm install express
         │
         ▼
supplychain/ecosystems/detector.py   - parse argv → InstallEvent
         │
         ▼
supplychain/ecosystems/metadata.py   - fetch registry metadata (npm / PyPI)
         │                             3s timeout, fail-open, 5-min cache
         ▼
supplychain/ioc.py                   - IOC check (package versions, namespaces)
         │                             check install script content for C2/patterns
         ▼
supplychain/scoring/engine.py        - additive signal scoring → allow/warn/block
         │
    ┌────┴─────┐
  block      allow/warn
    │              │
  exit 1      os.execv(npm, argv)   - replace process, transparent passthrough
```

The `prismor` binary at the repo root is a thin shebang wrapper over `supplychain/cli.py`. Non-install commands (`npm run build`, `pip freeze`, etc.) skip evaluation entirely and exec directly.
