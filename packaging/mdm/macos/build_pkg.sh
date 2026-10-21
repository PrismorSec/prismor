#!/bin/bash
# Build the Prismor macOS installer package (both architectures; postinstall
# keeps the one the Mac needs). Needs macOS (pkgbuild).
#   packaging/mdm/macos/build_pkg.sh dist/prismor-X.whl out/
# Signing (both optional; notarization needs both):
#   PRISMOR_CODESIGN_IDENTITY="Developer ID Application: ..."  signs every
#     Mach-O in the bundled runtime (hardened runtime, timestamp)
#   PRISMOR_PKG_SIGN_IDENTITY="Developer ID Installer: ..."    signs the .pkg
# Then: packaging/mdm/macos/notarize.sh out/prismor-X-macos.pkg
set -euo pipefail
WHEEL=$(cd "$(dirname "$1")" && pwd)/$(basename "$1"); OUT=${2:-out}
HERE=$(cd "$(dirname "$0")" && pwd); MDM=$(dirname "$HERE")
VER=$(basename "$WHEEL" | sed -E 's/^prismor-([^-]+)-.*/\1/')
WORK=$(mktemp -d); ROOT=$WORK/root
mkdir -p "$ROOT/opt/prismor/bin" "$ROOT/opt/prismor/runtime/$VER" "$OUT"
RTDIR="$ROOT/opt/prismor/runtime/$VER"
python3 "$MDM/build_runtime.py" --target macos-arm64 --wheel "$WHEEL" --out "$RTDIR/arm64"
# Without Rosetta an Apple Silicon host can't run the x86_64 interpreter, so
# its bytecode comes from the arm64 one (same CPython version; pycs are portable).
python3 "$MDM/build_runtime.py" --target macos-x86_64 --wheel "$WHEEL" --out "$RTDIR/x86_64" \
  --compile-with "$RTDIR/arm64/bin/python3"
if [ -n "${PRISMOR_CODESIGN_IDENTITY:-}" ]; then
  # Notarization rejects any unsigned Mach-O in the package, and libraries
  # must be signed before the executables that load them.
  n=0
  while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q "Mach-O"; then
      codesign --force --timestamp --options runtime --entitlements "$HERE/entitlements.plist" \
        --sign "$PRISMOR_CODESIGN_IDENTITY" "$f"
      n=$((n + 1))
    fi
  done < <(find "$RTDIR" -type f \( -name "*.so" -o -name "*.dylib" \) -print0; \
           find "$RTDIR" -type f -perm -u+x ! -name "*.so" ! -name "*.dylib" -print0)
  echo "signed $n Mach-O files with $PRISMOR_CODESIGN_IDENTITY"
fi
cp "$HERE/prismor" "$HERE/prismor-mdm-setup" "$HERE/prismor-uninstall" "$HERE/jamf-extension-attribute.sh" "$ROOT/opt/prismor/bin/"
chmod 755 "$ROOT/opt/prismor/bin/"*
chmod -R a+rX,go-w "$ROOT/opt"
cp -R "$HERE/scripts" "$WORK/scripts"
sed -i '' "s/__VERSION__/$VER/" "$WORK/scripts/postinstall"
chmod 755 "$WORK/scripts/postinstall"
PKG="$OUT/prismor-$VER-macos.pkg"
# The runtime contains .app bundles (Python's), which pkgbuild marks
# relocatable by default: Installer would then write them wherever a bundle
# with the same id already lives instead of under /opt/prismor.
pkgbuild --analyze --root "$ROOT" "$WORK/components.plist" >/dev/null
/usr/bin/plutil -replace BundleIsRelocatable -bool NO "$WORK/components.plist" 2>/dev/null || true
n=$(/usr/libexec/PlistBuddy -c "Print" "$WORK/components.plist" | grep -c "BundleIsRelocatable" || true)
for ((i = 0; i < n; i++)); do /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" "$WORK/components.plist"; done
pkgbuild --root "$ROOT" --component-plist "$WORK/components.plist" --scripts "$WORK/scripts" \
  --identifier dev.prismor.system --version "$VER" --install-location / --ownership recommended \
  ${PRISMOR_PKG_SIGN_IDENTITY:+--sign "$PRISMOR_PKG_SIGN_IDENTITY"} "$PKG"
rm -rf "${WORK:?}"
echo "built $PKG ($(du -h "$PKG" | cut -f1))"
