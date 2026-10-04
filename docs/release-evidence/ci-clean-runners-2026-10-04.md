# Release Evidence: clean GitHub-hosted runners, 2026-10-04

Task 9.3. Every suite below ran on freshly provisioned GitHub Actions macOS runners (Apple
Silicon) with no developer-machine state: run
<https://github.com/davidho27941/reline/actions/runs/37184184824>, commit `63c516d`, workflow
`.github/workflows/ci.yml`. All eight jobs succeeded.

| Runner image | Image version |
|---|---|
| `macos-14-arm64` (macOS 14) | 20260831.0302.1 |
| `macos-15-arm64` (macOS 15) | 20260907.0337.1 |

## Jobs

| Job | Runner | Result | Wall clock |
|---|---|---|---|
| `rust` (fmt, clippy `-D warnings`, `cargo test --workspace --all-features`, license audit, arm64 release build) | macOS 14 | success | 2 m 14 s |
| `rust` (same) | macOS 15 | success | 2 m 29 s |
| `sanitizer` (`scripts/check.sh --sanitize`: full check plus AddressSanitizer run of `recovery-core` and `recovery-ffi` on nightly) | macOS 15 | success | 4 m 35 s |
| `swift` (`cargo build --release -p recovery-ffi`, `swift build`, `scripts/swift-test.sh`) | macOS 15 | success | 1 m 57 s |
| `reference` (1,500-message fixture decrypted by the independent `iphone_backup_decrypt` 0.11.2; hashes match) | macOS 15 | success | 44 s |
| `package` (`scripts/package-app.sh --adhoc`, `codesign --verify --deep --strict`; embedded entitlements are exactly `files.user-selected.read-write` and `files.bookmarks.app-scope`) | macOS 15 | success | 1 m 19 s |
| `ui-test` (`scripts/ui-test.sh`: xcodegen project, `xcodebuild build-for-testing`, ad hoc signing, XCUITest) | macOS 15 | success | 4 m 21 s |
| `chain` (`scripts/scale-test.sh /tmp/reline-scale 400000`) | macOS 15 | success | 1 m 56 s |

## XCUITest suite (clean machine)

8 tests, 0 failures, 106.2 s: mutating stages disabled on fresh launch, stage rows expose
accessibility labels with state, keyboard navigation and cancel command when idle, cancel during
intake shows progress and leaves the stage uncommitted, unsupported current backup is explained
and blocks patching, structured failure is presented with code and remedy, language picker
switches live and back, Traditional Chinese localization.

## CLI chain on a 400,000-message fixture (clean machine)

| Step | Wall clock |
|---|---|
| fixture generation (old 72.0 MB, current 73.0 MB, expected 73.0 MB) | 71 s |
| intake old / current | 1 s / 0 s |
| analyze | 6 s |
| analyze + repair + encrypt + round trip + clone + replace + re-read | 17 s |
| export, cleanup | 0 s each |
| result | 227 updates, every gate passed, page_count 17825 → 17908 |

The runner is slower than the developer machine for fixture generation (71 s vs 7 s, dominated
by SQLite inserts on the runner's disk) but within the same bound for the recovery chain itself
(17 s vs 15 s). Cancellation and source immutability are exercised by the Rust test suite in the
`rust` and `sanitizer` jobs (see the developer-machine baseline for the test names).

## Fixes surfaced by the first clean run

The first push (run 37183670172) failed two jobs, both environment defects rather than engine
defects:

- `package`: `app/Reline.entitlements` had been rewritten to an empty dict. Cause: `xcodegen
  generate` regenerates the file from `project.yml`, which declared only `path`. The two keys
  are now declared as `properties`, and `package-app.sh --adhoc` fails with a message when
  either is missing from the signed bundle.
- `sanitizer`: nightly was installed last and became the default toolchain, so `cargo fmt` had
  no rustfmt. Stable is now installed first and nightly only as a secondary toolchain.
