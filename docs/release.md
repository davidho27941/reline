# Release: Build From Source, Signing, Evidence

## Distribution model

Reline is distributed as source. Each user builds the app on their own Mac with
`scripts/package-app.sh --adhoc`; a locally built bundle carries no quarantine flag, so macOS
runs it without Developer ID signing or notarization. This keeps the project free of the
Apple Developer Program and keeps the trust decision with the person whose backups it touches:
they can read and build what runs.

### Build from source (what the README tells users)

Requirements: macOS 13 or newer on Apple Silicon, Xcode Command Line Tools
(`xcode-select --install`) or Xcode, and a Rust toolchain (https://rustup.rs). Then:

```
git clone <repository>
cd reline
scripts/package-app.sh --adhoc      # builds the Rust core and the SwiftUI app, writes dist/Reline.app
open dist/Reline.app
```

`--adhoc` signs with the hardened runtime and the two file-access entitlements and runs
`codesign --verify --deep --strict`. The CI `package` job performs the same build on a clean
GitHub macOS runner on every push.

### If someone receives a prebuilt copy instead

A bundle that arrived by download, AirDrop or a zip/dmg carries the quarantine attribute and is
ad hoc signed, so Gatekeeper refuses it. The recipient either builds from source (preferred) or
clears the flag themselves after deciding to trust the sender:

```
xattr -d com.apple.quarantine /path/to/Reline.app
```

On macOS 15 and later the alternative is System Settings ▸ Privacy & Security ▸ "Open Anyway"
after the first refusal. The project does not publish prebuilt binaries for this reason.

## Optional: Developer ID signing and notarization

The steps below are kept for anyone who holds a Developer ID Application certificate. They
require full Xcode (`notarytool`, `stapler`) and are not a release gate.

## Build

```
scripts/build-universal.sh        # cargo build --release for arm64 (Intel dropped by decision on 2026-10-04)
scripts/package-app.sh            # swift build -c release, assemble Reline.app with Info.plist and entitlements
```

## Sign

```
CODESIGN_IDENTITY="Developer ID Application: <Team>" scripts/package-app.sh --sign
```

`package-app.sh --sign` signs with `--options runtime` (Hardened Runtime), `--timestamp`,
and `app/Reline.entitlements`:

- `com.apple.security.files.user-selected.read-write` (folder pickers)
- `com.apple.security.files.bookmarks.app-scope` (security-scoped bookmarks)
- no network, no camera, no automation entitlements
- `com.apple.security.cs.disable-library-validation` is **not** set; the Rust library is
  statically linked, so there is no embedded dylib to validate separately

Verification performed by the script: `codesign --verify --deep --strict` and
`spctl --assess --type execute`.

## Notarize and staple

```
scripts/notarize.sh dist/Reline.zip   # xcrun notarytool submit --wait, then xcrun stapler staple
```

Requires `NOTARY_PROFILE` (a `notarytool store-credentials` profile).

## Release evidence (task 9.3)

CI (`.github/workflows/ci.yml`) runs the Rust suite, the Swift suite, the fixture reference check and the app packaging on clean GitHub macOS 14/15 runners; those logs are part of the evidence.

For each supported macOS version (Apple Silicon only) record in `docs/release-evidence/<version>.md`:

- `cargo test --workspace --all-features` and `swift test` output
- `reline` CLI run of `scripts/acceptance-real-backup.sh` (user's preserved backups):
  repaired plaintext SHA-256, final re-read SHA-256, source directory digest before/after
- wall-clock and peak RSS for intake, analysis, patching on the real backup sizes
- a cancellation during patching leaving the destination empty
- Gatekeeper acceptance of the downloaded, stapled artifact on a clean machine

## Rollback of a release

Disable the affected adapter in `adapters::registry()`, bump the version, re-sign, re-notarize.
Previously exported backups and preserved originals are unaffected.
