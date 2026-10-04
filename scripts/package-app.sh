#!/usr/bin/env bash
# Assemble Reline.app from the SwiftPM build; optionally sign with Hardened Runtime.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release -p recovery-ffi
(cd app && swift build -c release --product Reline)
BIN="app/.build/release/Reline"
APP="dist/Reline.app"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/Reline"
# app/Info.plist is shared with the Xcode project and uses build-setting variables; expand them.
sed -e 's/\$(EXECUTABLE_NAME)/Reline/g' -e 's/\$(PRODUCT_BUNDLE_IDENTIFIER)/io.github.davidho27941.reline/g' \
    -e 's/\$(PRODUCT_NAME)/Reline/g' app/Info.plist > "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
grep -q '\$(' "$APP/Contents/Info.plist" && { echo "unexpanded variable in Info.plist" >&2; exit 1; }
# Localized strings (en, zh-Hant) live in the SwiftPM resource bundle; Bundle.module finds it in Resources/.
cp -R app/.build/release/Reline_RelineApp.bundle "$APP/Contents/Resources/"
xattr -cr "$APP"
echo -n "APPL????" > "$APP/Contents/PkgInfo"
case "${1:-}" in
  --sign)
    : "${CODESIGN_IDENTITY:?set CODESIGN_IDENTITY to a Developer ID Application identity}"
    codesign --force --options runtime --timestamp --entitlements app/Reline.entitlements --sign "$CODESIGN_IDENTITY" "$APP"
    codesign --verify --deep --strict --verbose=2 "$APP"
    spctl --assess --type execute --verbose "$APP" || { echo "Gatekeeper assessment failed (expected until notarized)"; }
    ditto -c -k --keepParent "$APP" dist/Reline.zip
    ;;
  --adhoc)
    # Local verification of bundle layout, entitlements and Hardened Runtime flags without a
    # Developer ID. Gatekeeper will not accept an ad-hoc signature; that is expected.
    codesign --force --options runtime --entitlements app/Reline.entitlements --sign - "$APP"
    codesign --verify --deep --strict --verbose=2 "$APP"
    ENT=$(codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -p -)
    for key in com.apple.security.files.user-selected.read-write com.apple.security.files.bookmarks.app-scope; do
      grep -q "$key" <<<"$ENT" || { echo "entitlement $key missing from signed bundle" >&2; exit 1; }
    done
    [[ $(grep -c '=> 1' <<<"$ENT") -eq 2 ]] || { echo "unexpected entitlements:" >&2; echo "$ENT" >&2; exit 1; }
    echo "$ENT"
    codesign -dvv "$APP" 2>&1 | grep -E "^(Identifier|Format|CodeDirectory|flags)" || codesign -dvv "$APP" 2>&1 | grep -iE "runtime|flags"
    ;;
esac
echo "packaged $APP"
