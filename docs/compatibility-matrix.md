# Compatibility Matrix, Privacy Statement, Limitations, Disclaimer

## Compatibility matrix (what the shipped rule set supports)

| Component | Supported | Notes |
|---|---|---|
| macOS | 13 Ventura and later, Apple Silicon only | Intel is not supported in this release; UI tests require Xcode |
| Backup type | Finder/iTunes **encrypted** local backup, `Manifest.plist` version 10.x, keybag with passcode-wrapped AES class keys | unencrypted backups rejected |
| Protection classes | 1, 3, 4 | class 2 rejected |
| LINE store | `Line.sqlite` under `AppDomainGroup-group.com.linecorp.line` or `AppDomain-jp.naver.line`, path `Library/Application Support/PrivateStore/P_u…/Messages/` | one account auto-selected, several require a choice |
| LINE schema | adapter `line-ios-coredata-v1`: `ZMESSAGE(Z_PK, ZID, ZCHAT, ZSENDER, ZTIMESTAMP, ZCONTENTTYPE, ZTEXT, ZCONTENTMETADATA, ZTHUMBNAIL, ZSENDSTATUS, ZREADCOUNT)`, `ZCHAT(Z_PK, ZMID, ZTYPE)` | other schemas: diagnostics only |
| Corruption rule | `type106-placeholder-restore/2`: current `ZCONTENTTYPE = 106`, old `!= 106`, same `ZID`, same chat MID, same timestamp; restores `ZCONTENTTYPE, ZTEXT, ZCONTENTMETADATA` | proven on one case (227 rows) in October 2026 |
| Identity rule | `ZID` non-NULL and unique in both databases; NULL-ZID rows (local/system rows, content type 0) and rows carrying a duplicated `ZID` are excluded from matching and repair and counted in the plan | version 1 of the rule blocked the whole analysis on these rows, which made every real LINE store unsupported |
| Not supported | WAL pending beside `Line.sqlite`, `Digest` in MBFile, E2EE databases, media files, Keychain items, iCloud backups | fail closed |

## Privacy statement

- Everything runs on your Mac. The app has no network code and no analytics.
- Your backup password is used in memory to unlock the backup keybag and is discarded unless
  you turn on "Remember in Keychain" (off by default; turning it off deletes the item).
- Decrypted data exists only inside the workspace folder you choose and is deleted on cleanup.
- Reports contain hashes, counts, rule versions, paths, device name, UDID and the LINE account
  directory name. They never contain message text, passwords or keys. A redacted report
  replaces UDIDs and account directory names with salted hashes.

## Limitations

- The rule set covers one documented corruption signature. Other LINE versions, other
  content types, or other migration failures are diagnosed but never repaired automatically.
- Without the correct backup password nothing can be recovered.
- Restore is a whole-device operation performed by you in Finder; the app does not touch
  MobileSync or the device.
- Multi-gigabyte backups are hashed twice and cloned; expect minutes, and free space equal to
  the backup size when the destination is on another volume.
- Not distributed through the Mac App Store in this release.

## Recovery disclaimer

This is an offline repair of your own data, not a LINE-supported procedure. A patched backup
that passes every gate is byte-verified to decrypt to the repaired database, but the behaviour
of the LINE app after restore depends on LINE. Keep the preserved original backup and create
a checkpoint backup after a successful restore.

## Incident response

Security or data-safety issues: open a GitHub Issue at
<https://github.com/davidho27941/reline/issues>. Include the report JSON (redacted) and the core version. Do not send backups, passwords or plaintext
databases.
