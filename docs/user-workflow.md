# User Workflow: Work on Copies, Never on MobileSync

The app never opens `~/Library/Application Support/MobileSync/Backup` for you, never writes
there, and never talks to the iPhone. You select folders; the app reads them read-only and
writes only into the session workspace and the export destination you choose.

## Before you start

1. Make an encrypted Finder backup of the **old** iPhone and of the **current** iPhone.
2. Unplug both devices.
3. In Finder, copy each backup folder (the one named after the device UDID) from
   `MobileSync/Backup` into a folder you own, for example `~/Documents/LINE Recovery/old`
   and `~/Documents/LINE Recovery/current`. If Finder reports "Operation not permitted",
   copy with Finder rather than Terminal; the app itself needs no Full Disk Access.
4. Create two more empty folders: one **workspace** (decrypted material lives here while you
   work and is deleted when you clean up) and one **export destination** (the patched backup
   and reports land here).

## In the app

| Stage | What you do | What the app does |
|---|---|---|
| Intake | pick the old copy, the current copy, the workspace; enter the password (remembering it in Keychain is off by default) | validates structure, unlocks the keybag, extracts `Line.sqlite` for each, proves the sources unchanged |
| Analysis | press Analyze | compares the two databases, produces the plan or a diagnostic report |
| Review | read counts, rule, exclusions, warnings; tick the three confirmations and type the predicted count | nothing until you confirm |
| Patching | pick the export destination, confirm | repairs a working copy, encrypts, clones the current backup, replaces one payload |
| Verification | wait | re-reads the clone like a fresh backup and checks every gate |
| Export | press Export | renames the verified clone into the destination with a new name, writes reports and restore instructions |

Mutating stages stay disabled until every earlier stage is committed and your confirmation
matches the plan exactly. Cancel is available during every long operation; cancelling leaves
the sources untouched and removes partial output.

## Language

The shell is localized in English and Traditional Chinese. It follows the system language by
default; the globe picker in the window toolbar (System / English / 繁體中文) overrides it
immediately and the choice is remembered. Strings produced by the Rust core (paths, hashes, adapter diagnostics, reports,
restore instructions) stay in English; the fixed vocabularies (stage names, states, blockers,
verification gates, error titles) are translated, and each error code has a plain-language
explanation shown above the core's own message. Strings live in
`app/Sources/RelineApp/Resources/<lang>.lproj/Localizable.strings`, keyed by the English
text.

## Progress, cancellation, errors, and unsupported input

- **Progress** appears in a bar above the stage content as soon as an operation starts. It shows
  the stage, a percentage, and the byte count. VoiceOver reads it as "<stage> progress, N percent";
  before the first byte count it reads "<stage> in progress".
- **Cancel** is the button beside the progress bar, the Escape key, or View ▸ Cancel Operation
  (Command-Period). The core stops at the next chunk boundary, removes partial output, and the stage
  row reads "<Stage>, cancelled". Cancellation is shown as an inline notice with a Dismiss button, not
  as an error alert, and the cancelled stage never counts as complete.
- **Errors** are modal alerts with a short title, the message, the affected path when there is one,
  a "What to do" remedy, and the machine-readable code. They never contain the password, keys, or
  message text.
- **Unsupported input** is not an error. A backup whose metadata is outside the supported policy
  (pending `-wal`/`-shm`/`-journal`, unsupported protection class, digest present) completes intake,
  shows "Patchable: No, analysis only" with each reason listed, and keeps Patching blocked. An
  analysis that cannot produce an actionable plan shows "Unsupported: diagnostics only" with its
  reasons. Both groups are single VoiceOver elements that read the reasons in one pass.
- **Keyboard**: the stage list is focusable and arrow keys change the selected stage; every button
  and field is in the Tab order; Command-A runs Analyze when it is enabled.

These behaviours are exercised by `app/Tests/UITests/RelineUITests.swift`
(`scripts/ui-test.sh`, requires Xcode).

## After export

Follow `…RESTORE-INSTRUCTIONS.md`: unplug, move the current `MobileSync/Backup/<UDID>`
aside, copy the patched backup in, restore from Finder, first-launch LINE offline, then make
a checkpoint backup before deleting anything. The report names the preserved original and the
patched output so rollback is a directory swap, performed by you, with the iPhone unplugged.

The in-app instructions are generated from the same template as this document
(`report::ops::restore_instructions`) and the picker flow is tested in
`app/Tests/RecoveryKitTests`.
