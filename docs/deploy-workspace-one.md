# Deploy with Workspace ONE UEM (macOS and Windows)

Workspace ONE UEM installs the same packages as [Jamf](deploy-jamf.md) and
[Intune](deploy-intune.md): a [system install](system-install.md) that screens
every user's Claude Code, Codex, Cursor and Gemini CLI, with its own Python
bundled. Build the packages as those pages describe, or take
`prismor-<version>-macos.pkg` and `prismor-<version>-windows.zip` from the
GitHub Release (each has a `.sha256` file).

The console paths below follow the current Workspace ONE UEM layout. This
setup has not yet been run against a live Workspace ONE tenant, so check the
install log on a pilot device before you widen the assignment.

## macOS

### 1. Custom Settings profile

**Resources → Profiles & Baselines → Profiles → Add → macOS → Device**, then
add a **Custom Settings** payload. Assign it to the same Smart Group as the
app, and let it land before the app installs, so the package's postinstall
can read it from `/Library/Managed Preferences/dev.prismor.plist`.

```xml
<dict>
  <key>PayloadType</key><string>dev.prismor</string>
  <key>PayloadIdentifier</key><string>dev.prismor.settings</string>
  <key>PayloadUUID</key><string><!-- uuidgen --></string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>FleetToken</key><string>prismor_fleet_…</string>
  <key>Mode</key><string>enforce</string>
</dict>
```

The keys are the same as on Jamf: `FleetToken` (optional; from the console,
Devices → Fleet token), `Mode` (`enforce` or `observe`), `EnforceRules`
(comma-separated rule ids, default the recommended set) and `ApiBase` (only
for a self-hosted control plane).

### 2. Internal app

**Resources → Apps → Native → Internal → Add → Application File**, upload
`prismor-<version>-macos.pkg`, and generate the metadata with the
Workspace ONE Admin Assistant when the console asks for it. Install as the
device (not the user). The install log is `/var/log/prismor-install.log`.

To pass settings on the command line instead of the profile, add a
post-install script on the app's **Scripts** tab:

```bash
#!/bin/bash
/opt/prismor/bin/prismor-mdm-setup --token "prismor_fleet_…" --mode enforce
```

### 3. Sensor

**Resources → Sensors → Add → macOS**, language Bash, execution context
System, response type String:

```bash
#!/bin/bash
P=/opt/prismor/bin/prismor
if [ ! -x "$P" ] || [ ! -f "/Library/Application Support/Prismor/system.json" ]; then
  echo "not installed"; exit 0
fi
v=$(PRISMOR_NO_UPDATE_CHECK=1 "$P" --version 2>/dev/null | awk '{print $2}')
if PRISMOR_NO_UPDATE_CHECK=1 "$P" enroll-status >/dev/null 2>&1; then echo "$v enrolled"; else echo "$v not-enrolled"; fi
```

It is the Jamf extension attribute without Jamf's `<result>` wrapper. Build a
Smart Group on the sensor value to find Macs that need attention.

## Windows

### 1. Win32 app

**Resources → Apps → Native → Internal → Add → Application File**, upload
`prismor-<version>-windows.zip`.

| Setting | Value |
|---|---|
| Install command | `powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Token <fleet token>` |
| Uninstall command | `powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1` |
| Install context | **Device** |
| Admin privileges | Yes |
| Device restart | Do not restart |
| Install complete when | Custom script `detect.ps1` (PowerShell, 64-bit), success exit code `0` |

`install.ps1` takes the same options as on Intune: `-Mode`, `-Rules`,
`-ApiBase`, `-Label` and `-Discover`. Leave out `-Token` to install without
enrolling. The install log is `C:\ProgramData\PrismorInstall\install.log`.

### 2. Drift check (optional)

**Resources → Scripts → Add → Windows**, PowerShell, execution context
System, with `remediation-fix.ps1`. Pair it with a sensor running
`remediation-detect.ps1`, and run the script on devices whose sensor
reports drift. It re-runs `prismor setup --system` with the mode the device
was installed with, and leaves the enrollment as it is.

## Upgrade

Add the new package as a new version of the same app. On macOS the
postinstall repoints `/opt/prismor/current`. On Windows `install.ps1`
upgrades in place and repoints the `current` junction. Hooks run through
`current`, so they keep working through the upgrade, and the enrollment is
kept.

## Remove

Remove the app's assignment, or run the uninstaller as root/SYSTEM:
`/opt/prismor/bin/prismor-uninstall` on macOS, `uninstall.ps1` on Windows.
