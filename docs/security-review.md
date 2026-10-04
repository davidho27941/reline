# Security Review (MVP)

Scope: `crates/recovery-core`, `crates/recovery-ffi`, `app/`. Reviewed 2026-10-04 against
the design's trust boundaries. Severity: High blocks release; Medium must be fixed or
documented; Low is tracked.

| # | Area | Finding | Severity | Resolution |
|---|---|---|---|---|
| 1 | FFI | A Rust panic unwinding across `extern "C"` is undefined behaviour | High | `recovery_session_execute` wraps the driver call in `catch_unwind`; release profile uses `panic = "abort"`; error JSON never includes the panic payload |
| 2 | FFI | Host could pass dangling pointers | Medium | All entry points are `unsafe` with documented `# Safety` contracts; NULL is tolerated everywhere; strings are copied immediately; passwords are copied into `Password` (zeroizing) before any other work |
| 3 | FFI | Progress callback invoked from the worker thread with a host cookie | Medium | Documented in the header; the Swift wrapper passes an `Unmanaged` box and dispatches to the main actor |
| 4 | Secrets | Passwords, derived keys, class keys, file keys | High | `Password`, `SecretBytes`, `Key256` zeroize on drop and have redacting `Debug`; none implement `Serialize`; keys live only in `SessionState` and are dropped on `Cleanup` or session free; intermediate PBKDF2 buffers are `Zeroizing` |
| 5 | Secrets | Wrong password must not leak derived material | High | Only the RFC 3394 integrity failure is observable; error text is constant; tested by `wrong_password_fails_closed_without_key_material` |
| 6 | Plaintext | Decrypted databases on disk | High | Only inside `<workspace>/plaintext/` (0700/0600), deleted on failure, cancel, cleanup; retained repaired DB is flagged `sensitive` and deleted on cleanup; tests check no plaintext after failure |
| 7 | Plaintext | Memory buffers of decrypted chunks | Medium | Chunk buffers in `payload.rs` are `Zeroizing<Vec<u8>>` |
| 8 | Paths | Destination inside source or vice versa | High | Canonicalized prefix check in `patch::ops::patch` → `invalid_argument`; tested |
| 9 | Paths | `relativePath`/`fileID` from Manifest.db used to build paths | High | Payload path is derived from `fileID`, which is validated as `SHA-1(domain-relativePath)` hex; the two-char shard comes from the validated id, so no traversal is possible |
| 10 | Archive traversal | Symlinks inside a backup directory | Medium | `patch::clone::walk` refuses to follow symlinks (`unsupported_backup`) |
| 11 | Logs | Message text or secrets in logs/reports | High | Reports are built only from `session.json`; plans carry salted public ids; privacy tests scan Markdown, JSON and instructions for password, candidate ids and message text |
| 12 | Crash | Partial outputs after a crash | Medium | Stage commit protocol; restart classifies partial artifacts; never reused |
| 13 | SQLite | `ATTACH` of attacker-controlled paths | Low | Paths come from the session workspace only; attached read-only via URI `mode=ro` |
| 14 | SQLite | Table/column names interpolated into SQL | Low | Only adapter constants and `sqlite_master` names, quoted with `""` escaping |
| 15 | Clone | Running out of space mid-copy | Medium | `statvfs` preflight with margin; copy fallback uses `create_new`; any failure discards the staging clone |
| 16 | Export | Overwriting an existing export | High | Default refuses; overwrite requires a separate explicit flag; staging clone is renamed, not copied, so no half-written final directory exists |
| 17 | Keychain | Password remembered by default | Medium | Default off; disabling deletes the item; reports never include it (app layer) |
| 18 | Network | Any egress | High | No networking dependency in the core; Swift app declares no network entitlement |

Open items (Low): the Rust `rand` crate is only enabled for fixtures; `plist` and `rusqlite`
are the parsing surface for untrusted input and should be fuzzed before 1.0.

Memory-safety verification: `scripts/check.sh --sanitize` runs the test suite under
AddressSanitizer with a nightly toolchain when one is installed (`rustup toolchain install
nightly`); CI runs it on every push.
