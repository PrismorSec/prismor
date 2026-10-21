# Deploy with Jamf Pro (macOS)

The Prismor macOS package installs a [system install](system-install.md):
one machine-wide setup that screens every user's Claude Code, Codex, Cursor
and Gemini CLI. It carries its own Python, so the Mac needs nothing else.

## Build the package

```bash
python3 -m build --wheel --outdir dist
packaging/mdm/macos/build_pkg.sh dist/prismor-*.whl out
# -> out/prismor-<version>-macos.pkg  (Apple Silicon and Intel)
```

Each release attaches the package to its GitHub Release, as
`prismor-<version>-macos.pkg` with a `.sha256` file. The `MDM packages` CI
workflow also builds it on every change, as a run artifact.

### Signing and notarization

Jamf installs unsigned packages. Signed and notarized, the package also
passes Gatekeeper when someone opens it by hand. To build one yourself:

```bash
PRISMOR_CODESIGN_IDENTITY="Developer ID Application: <Org> (TEAMID)" \
PRISMOR_PKG_SIGN_IDENTITY="Developer ID Installer: <Org> (TEAMID)" \
  packaging/mdm/macos/build_pkg.sh dist/prismor-*.whl out
APPLE_NOTARY_KEY_PATH=AuthKey.p8 APPLE_NOTARY_KEY_ID=… APPLE_NOTARY_ISSUER_ID=… \
  packaging/mdm/macos/notarize.sh out/prismor-*-macos.pkg
```

The first identity signs every binary in the bundled Python with the
hardened runtime, which notarization requires. The second signs the
package. The release workflow does the same when these repository secrets
are set:

| Secret | What |
|---|---|
| `MACOS_APP_CERT_P12` | Developer ID Application certificate + key, `.p12`, base64 |
| `MACOS_INSTALLER_CERT_P12` | Developer ID Installer certificate + key, `.p12`, base64 |
| `MACOS_CERT_PASSWORD` | Password for both `.p12` files |
| `APPLE_NOTARY_KEY_P8` | App Store Connect API key (`.p8`), base64 |
| `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID` | That key's id and issuer |

Without the certificate secrets the release ships the package unsigned.
Without the notary secrets it is signed but not notarized.

The package installs:

- `/opt/prismor/runtime/<version>/` — Python and Prismor, with
  `/opt/prismor/current` pointing at it;
- `/opt/prismor/bin/` — `prismor`, `prismor-mdm-setup`, `prismor-uninstall`
  and `jamf-extension-attribute.sh`.

Its postinstall runs `prismor setup --system` and, if the configuration
profile carries a fleet token, enrolls the Mac.

## 1. Configuration profile

Create a profile with an Application & Custom Settings payload for the
domain **`dev.prismor`**, scoped to the same Macs as the package. Deliver the
profile first, so the package's postinstall can read it.

| Key | Value |
|---|---|
| `FleetToken` | A fleet token from the console (Devices → Fleet token). Optional. |
| `Mode` | `enforce` (default) or `observe` |
| `EnforceRules` | Comma-separated rule ids. Default: the recommended set |
| `ApiBase` | Only for a self-hosted control plane |

```xml
<dict>
  <key>FleetToken</key><string>prismor_fleet_…</string>
  <key>Mode</key><string>enforce</string>
</dict>
```

## 2. Policy

Upload `prismor-<version>-macos.pkg`, then create a policy that installs it.
Use the trigger and scope you want, for example recurring check-in plus
enrollment complete. The install log is `/var/log/prismor-install.log`.

You can pass settings as script parameters instead of using a profile. Add
a script to the same policy, with Priority **After**:

```bash
#!/bin/bash
/opt/prismor/bin/prismor-mdm-setup --token "$4" --mode "${5:-enforce}"
```

## 3. Inventory

Add an extension attribute (Data type String, Input type Script) with the
contents of `/opt/prismor/bin/jamf-extension-attribute.sh`. It reports
`<version> enrolled`, `<version> not-enrolled` or `not installed`.

A smart group on *Prismor is not like `enrolled`* finds Macs that need
attention. To re-apply the setup on them, scope a policy to that group that
runs `/opt/prismor/bin/prismor-mdm-setup`.

## Upgrade

Upload the new package and point the policy at it. The postinstall repoints
`/opt/prismor/current` and removes the old version. Hooks run through
`current`, so they keep working through the upgrade, and the enrollment
is kept.

## Remove

Run `/opt/prismor/bin/prismor-uninstall` as root, for example from a Jamf
policy. It removes the hooks, `/opt/prismor`,
`/Library/Application Support/Prismor`, the sync LaunchDaemon and the
package receipt.
