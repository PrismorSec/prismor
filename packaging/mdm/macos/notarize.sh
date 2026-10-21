#!/bin/bash
# Notarize and staple a signed Prismor package with an App Store Connect API
# key. Needs: APPLE_NOTARY_KEY_PATH (.p8), APPLE_NOTARY_KEY_ID, APPLE_NOTARY_ISSUER_ID.
#   packaging/mdm/macos/notarize.sh out/prismor-X-macos.pkg
set -euo pipefail
PKG=$1
: "${APPLE_NOTARY_KEY_PATH:?}" "${APPLE_NOTARY_KEY_ID:?}" "${APPLE_NOTARY_ISSUER_ID:?}"
pkgutil --check-signature "$PKG" | grep -q "Developer ID Installer" || {
  echo "notarize: $PKG is not signed with a Developer ID Installer identity" >&2; exit 1; }
xcrun notarytool submit "$PKG" --key "$APPLE_NOTARY_KEY_PATH" --key-id "$APPLE_NOTARY_KEY_ID" \
  --issuer "$APPLE_NOTARY_ISSUER_ID" --wait --timeout 30m --output-format json | tee /tmp/notary.json
grep -q '"status" *: *"Accepted"' /tmp/notary.json || { echo "notarize: not accepted" >&2; exit 1; }
xcrun stapler staple "$PKG"
xcrun stapler validate "$PKG"
