# Session Directory Lifecycle and Cleanup Policy

A recovery session lives in one user-selected folder. The core creates it with mode `0700`
and every file it writes with mode `0600`. The folder is the only place decrypted material
ever exists.

```
<workspace>/
  session.json          versioned manifest (manifest_version = 1); replaced atomically
  session.json.tmp      transient; present only during a manifest write
  staging/<stage>/      outputs of a stage that is Running; always partial
  committed/<stage>/    outputs registered in session.json with size and SHA-256
  plaintext/<role>/     decrypted Manifest.db and Line.sqlite for old / current
  plaintext/repaired-unverified.sqlite   kept only when post-repair gates failed
  export/               reports written by the Report request (never plaintext)
```

## Stage states

Each of the six stages (`intake`, `analysis`, `review`, `patching`, `verification`,
`export`) carries exactly one state in `session.json`:

| State | Meaning | On disk |
|---|---|---|
| `pending` | never started | nothing |
| `running` | started, not committed | `staging/<stage>/` may hold partial files |
| `committed` | outputs fsynced, hashed, registered | `committed/<stage>/` matches the manifest |
| `failed` | stopped on an error; secret-free error recorded | staging removed |
| `cancelled` | stopped cooperatively; sensitive partial outputs removed | staging removed |
| `invalidated` | an earlier stage was restarted, so this evidence is stale | files may remain but are never reused |

## Commit protocol

1. `begin_stage` clears `staging/<stage>/`, marks the stage `running`, marks every later stage
   `invalidated`, and persists the manifest.
2. The stage writes its outputs into `staging/<stage>/`.
3. `commit_stage` fsyncs each output, hashes it, renames it into `committed/<stage>/`, fsyncs
   the directory, then writes the manifest: tmp file, fsync, rename, directory fsync.
4. Only after step 3 is the stage `committed`. A crash before it leaves the stage `running`.

## Restart classification

On open, the core never deletes anything. It classifies:

- a stage recorded `running` → `failed` with the error "stage was interrupted before commit";
- every file under `staging/` → partial;
- every file under `committed/` that the manifest does not list with matching size → partial;
- every file under `plaintext/` → sensitive, removable.

The host shows these partial artifacts and offers **Cleanup** or **restart from intake**.
Partial artifacts are never presented as verified evidence. A manifest with an unknown
`manifest_version` is refused rather than migrated.

## Cleanup actions

| Action | Trigger | Effect |
|---|---|---|
| stage failure / cancellation | any error while `running` | `staging/<stage>/` removed; state `failed` or `cancelled` |
| intake failure for a role | authentication or extraction error | `plaintext/<role>/` removed |
| `Cleanup` request | user, or host on quit | `plaintext/` and `staging/` emptied; committed outputs flagged `sensitive` (the repaired database) deleted and dropped from the manifest; non-sensitive evidence and `session.json` kept so a report can still be produced |
| session free | host releases the handle | in-memory keys and the secure plan are zeroized; nothing on disk changes |

Deletion is `unlink` on APFS. The core does not attempt to overwrite file contents, because
copy-on-write storage makes that meaningless; FileVault is the user's at-rest protection.

## Automated coverage

`crates/recovery-core/src/session/workspace.rs` tests exercise every state and action above:
`commit_registers_outputs_and_restart_sees_them_committed`,
`interrupted_stage_is_partial_after_restart`, `tampered_committed_output_detected`,
`fail_stage_removes_staging_and_never_commits`, `cleanup_removes_plaintext_and_sensitive_outputs`,
`begin_stage_invalidates_later_stages`, `unsupported_manifest_version_rejected`, plus
`lifecycle_doc_matches_code`, which fails if a state or action named here disappears from code
or if a code state is missing from this document.
