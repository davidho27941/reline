# Reline — LINE 聊天紀錄備份修復工具

Offline macOS tool that repairs LINE chat messages lost during an iPhone-to-iPhone migration,
by patching an encrypted Finder backup. It never touches the phone, never talks to the network,
and never modifies the backups you give it: it writes a patched **clone** that you restore
yourself with Finder.

> **繁體中文摘要**：這是一個離線的 macOS 工具，用來修復 iPhone 換機後 LINE 聊天紀錄變成空白
> 佔位符（內容類型 106）的問題。它讀取舊機與新機的加密 Finder 備份副本，比對後只回填被清掉的
> 那幾個欄位，產出一份經過完整驗證的備份副本，由你自己用 Finder 還原。原始備份不會被改動。
> 需要自行從原始碼建置（見下方「Build」），不需要 Apple 開發者帳號。

## What it fixes

After migrating to a new iPhone, LINE can rewrite a set of existing messages in its local
database to content type 106 (an empty placeholder) and clear their text and metadata. The
messages still exist with the same IDs, chats, senders and timestamps. If you still have an
encrypted Finder backup of the **old** phone, this tool:

1. decrypts both backups' `Line.sqlite` read-only (password never leaves memory),
2. matches messages by LINE message ID and validates chat and timestamp relationships,
3. restores exactly three fields (`ZCONTENTTYPE`, `ZTEXT`, `ZCONTENTMETADATA`) for rows that match
   the versioned rule, inside one transaction whose row count must equal the prediction,
4. re-encrypts the repaired database with the backup's own keys, clones the current backup, swaps
   that single payload, and re-reads the clone through the normal intake path before it may be
   exported,
5. writes an audit report (hashes, counts, rule version, every gate) and step-by-step restore
   instructions.

The rule was derived from one real case (227 messages) in October 2026; anything the rule cannot
explain is excluded and reported, never repaired. See `docs/compatibility-matrix.md` for what is
and is not supported.

## Build

Requirements: macOS 13 or newer on Apple Silicon, Xcode Command Line Tools
(`xcode-select --install`) or Xcode, and Rust (https://rustup.rs).

```
git clone https://github.com/davidho27941/reline.git
cd reline
scripts/package-app.sh --adhoc
open dist/Reline.app
```

A bundle you build yourself runs without Developer ID signing or notarization. Prebuilt copies
are deliberately not published; if someone hands you one, build from source instead, or read
`docs/release.md` for the Gatekeeper steps.

The expert CLI (`target/release/reline`) exercises the same engine; `scripts/` holds the
test, scale and acceptance harnesses.

## Languages

The interface is available in English and Traditional Chinese (繁體中文). It follows the
system language; the globe picker in the window toolbar switches between them at any time
without a relaunch.
Reports and restore instructions written by the engine are in English.

## Use

1. Make **copies** of both backup folders from `~/Library/Application Support/MobileSync/Backup/`
   (named after each device UDID) with the iPhone unplugged. Never point the app at MobileSync.
2. In the app: pick the session workspace, the old copy, the current copy, enter the backup
   password, read both backups.
3. Analyze, review the counts, confirm by typing the predicted update count, pick an export
   destination, create the patched clone. Verification runs automatically.
4. Export, then follow `…RESTORE-INSTRUCTIONS.md` in Finder. The app never restores the device.

Full walkthrough: `docs/user-workflow.md`.

## Guarantees and limits

- Sources are hashed before and after every stage; the clone differs from the current backup at
  exactly one path or it is discarded.
- Only databases that pass every post-repair gate (integrity, field equality, protected-field
  stability, page statistics, decrypt-and-hash round trip, full re-read) can be exported.
- Reports never contain the password, keys or message text. The workspace is cleaned up on
  request; plaintext never leaves it.
- Unsupported inputs (pending WAL, unsupported protection class, unknown schema) are explained
  and block patching; analysis still runs for diagnostics.
- No warranty. Keep the original backup until LINE on the restored phone has been checked and a
  new checkpoint backup exists. Details: `docs/security-review.md`, `docs/repair-invariants.md`.

## Development

```
scripts/check.sh            # fmt, clippy, tests, license audit, Swift tests
scripts/ui-test.sh          # XCUITests (needs Xcode; switches the input source to ABC during the run)
scripts/scale-test.sh       # 400k-message timing run on a synthetic fixture
```

Layout: `crates/recovery-core` (engine), `crates/recovery-ffi` (C ABI), `crates/recovery-cli`,
`app/` (SwiftUI shell and RecoveryKit), `docs/`.

## License

MIT, see `LICENSE`. Third-party notices: `THIRD-PARTY-NOTICES.md`.
