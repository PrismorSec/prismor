# Deploy with Microsoft Intune (Windows)

The Prismor Windows package installs a [system install](system-install.md):
one machine-wide setup that screens every user's Claude Code, Codex, Cursor
and Gemini CLI. It carries its own Python, so the device needs nothing else.
The same folder works for SCCM and for a GPO startup script.

## Build the package

```powershell
python -m build --wheel --outdir dist
python packaging\mdm\windows\build_package.py (Get-ChildItem dist\*.whl).FullName out
powershell -File packaging\mdm\windows\make_intunewin.ps1 -Package out\prismor-<version>-windows -Out out
# -> out\prismor-<version>.intunewin
```

`make_intunewin.ps1` uses Microsoft's Win32 Content Prep Tool, pinned to
v1.8.7, and checks the tool's Microsoft signature before running it.

Each release attaches `prismor-<version>.intunewin` and
`prismor-<version>-windows.zip` to its GitHub Release, each with a `.sha256`
file. The `MDM packages` CI workflow builds and tests the package on every
change.

### Signing

The install command runs with `-ExecutionPolicy Bypass`, so Intune doesn't
need signed scripts. Devices that enforce `AllSigned` or WDAC script rules
do, so sign the scripts before wrapping:

```powershell
powershell -File packaging\mdm\windows\sign_package.ps1 -Package out\prismor-<version>-windows -PfxPath codesign.pfx -PfxPassword <pw>
# -SignRuntime also signs python.exe and every .dll/.pyd (needs signtool, Windows SDK)
```

The release workflow signs the scripts when the repository secrets
`WINDOWS_CODESIGN_PFX` (the `.pfx`, base64) and `WINDOWS_CODESIGN_PASSWORD`
are set. Without them it ships the scripts unsigned.

## Win32 app

| Setting | Value |
|---|---|
| Install command | `powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Token <fleet token>` |
| Uninstall command | `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1` |
| Install behavior | **System** |
| Device restart behavior | No specific action |
| Return codes | `0` success, `1` failure |
| Detection rules | Custom script: `detect.ps1`, run as 32-bit: **No** |

`install.ps1` options:

- `-Mode enforce|observe` (default `enforce`);
- `-Rules id1,id2` (default: the recommended set);
- `-ApiBase` (only for a self-hosted control plane);
- `-Label` (default: the computer name).

Leave out `-Token` to install without enrolling.

Mint the token in the console (Devices → Fleet token). It has a use limit
and an expiry, so the copy stored in the Intune app can't enroll machines
past either.

The install log is `C:\ProgramData\PrismorInstall\install.log`.

What gets installed:

- `C:\Program Files\Prismor\runtime\<version>\` — Python and Prismor, with
  the `current` junction pointing at it;
- `C:\Program Files\Prismor\bin\prismor.cmd`, added to the machine `PATH`;
- the system install files in `C:\ProgramData\Prismor` and each agent's
  machine-wide hook file;
- the scheduled task `Prismor System Sync`.

## Remediations (optional)

Create a remediation script package that runs as **System** in **64-bit**
PowerShell:

- **Detection script:** `remediation-detect.ps1`. It reports drift: the marker,
  the launcher or the Claude Code / Codex hook file is missing, or no longer
  points at Prismor.
- **Remediation script:** `remediation-fix.ps1`. It re-runs
  `prismor setup --system` with the mode the device was installed with. The
  enrollment is untouched.

## Upgrade

Add the new `.intunewin` as a new app that supersedes the old one, with
**Uninstall previous version** off. `install.ps1` upgrades in place: it
copies the new runtime, repoints the `current` junction and removes the old
version. Hooks run through `current`, so they keep working through the
upgrade, and the enrollment is kept.

## Remove

Uninstall the app from Intune, or run `uninstall.ps1` as SYSTEM. It removes
the hooks, `C:\Program Files\Prismor`, `C:\ProgramData\Prismor`, the sync
task and the `PATH` entry.
