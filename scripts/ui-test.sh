#!/usr/bin/env bash
# XCUITest run (task 7.3/7.4). Requires Xcode. Builds with signing disabled, strips the
# com.apple.provenance / Finder xattrs that make codesign refuse ("detritus"), signs every
# product ad hoc, then runs test-without-building.
set -euo pipefail
cd "$(dirname "$0")/../app"
export PATH="$HOME/.cargo/bin:$PATH"
if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi
[[ -d "${TMPDIR:-/nonexistent}" ]] || export TMPDIR=/tmp
(cd .. && cargo build --release -p recovery-ffi -p recovery-cli >/dev/null)
command -v xcodegen >/dev/null && xcodegen generate >/dev/null
# Synthetic encrypted backups for the cancellation and unsupported-input tests (task 7.4).
# `normal` is large enough that intake reports progress several times; `wal` carries a pending
# Line.sqlite-wal so the current backup is analyzable but not patchable.
FX="$HOME/Library/Caches/Reline/ui-fixtures"
rm -rf "$FX"; mkdir -p "$FX"
CLI=../target/release/reline
"$CLI" "$FX/gen-ws" "{\"op\":\"generate_fixture\",\"output_dir\":\"$FX/normal\",\"spec\":{\"line\":{\"message_count\":60000,\"chat_count\":40,\"current_only_messages\":200}}}" >/dev/null
"$CLI" "$FX/gen-ws" "{\"op\":\"generate_fixture\",\"output_dir\":\"$FX/wal\",\"spec\":{\"pending_wal_in_current\":true}}" >/dev/null
# Build outside the repository: Documents is synced by a File Provider (iCloud Drive), which
# keeps re-adding com.apple.FinderInfo to build products and codesign refuses them as detritus.
DD="${RELINE_DERIVED_DATA:-$HOME/Library/Caches/Reline/DerivedData}"
mkdir -p "$DD"
xattr -cr Info.plist Reline.entitlements Sources Tests 2>/dev/null || true
xcodebuild build-for-testing -project Reline.xcodeproj -scheme Reline \
  -destination 'platform=macOS' -derivedDataPath "$DD" CODE_SIGNING_ALLOWED=NO \
  ENABLE_DEBUG_DYLIB=NO ENABLE_PREVIEWS=NO -quiet
P="$DD/Build/Products/Debug"
# Every codesign writes files that immediately pick up the provenance xattr again, so strip
# right before each outer signature.
sign() { xattr -cr "$P"; codesign --force --sign - "$@"; }
# Nested Mach-O files first. The test app is signed WITHOUT the hardened runtime: ad hoc
# signatures carry no Team ID, so library validation rejects the separately signed
# RecoveryKit.framework ("mapping process and mapped file have different Team IDs") and the
# app aborts at launch (DYLD "Library missing"). The shipped bundle from package-app.sh links
# the core statically and keeps --options runtime.
for dylib in "$P"/Reline.app/Contents/MacOS/*.dylib; do [[ -f "$dylib" ]] && sign "$dylib"; done
sign "$P/Reline.app/Contents/Frameworks/RecoveryKit.framework"
sign --entitlements Reline.entitlements "$P/Reline.app"
sign "$P/RelineUITests-Runner.app/Contents/PlugIns/RelineUITests.xctest"
sign "$P/RelineUITests-Runner.app"
xattr -cr "$P"
codesign --verify --deep --strict "$P/Reline.app"
XCTESTRUN=$(ls "$DD"/Build/Products/Reline_*.xctestrun | head -1)
LOG="${TMPDIR}/RelineUITests-$(date +%s).log"
xcodebuild test-without-building -xctestrun "$XCTESTRUN" -destination 'platform=macOS' \
  -derivedDataPath "$DD" -resultBundlePath "${LOG%.log}.xcresult" >"$LOG" 2>&1 || true
grep -E "Test Case .* (passed|failed)|Executed|TEST (SUCCEEDED|FAILED)|error:|XCTAssert" "$LOG" || true
# xcodebuild's exit status is unreliable for test-without-building; trust the summary line.
grep -q "TEST EXECUTE SUCCEEDED" "$LOG" || { echo "UI tests did not succeed; full log: $LOG" >&2; exit 1; }
