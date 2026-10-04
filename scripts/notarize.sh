#!/usr/bin/env bash
# Submit to Apple notary service and staple. Requires full Xcode and a notarytool profile.
set -euo pipefail
ZIP="${1:?usage: notarize.sh dist/Reline.zip}"
: "${NOTARY_PROFILE:?set NOTARY_PROFILE (xcrun notarytool store-credentials)}"
xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
APP="${ZIP%.zip}.app"
xcrun stapler staple "$APP"
spctl --assess --type execute --verbose "$APP"
