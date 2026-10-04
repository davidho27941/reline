# Encrypted Finder Backup Format Used by the Recovery Core

This document names every structure and field the Rust core reads or writes when
it handles an encrypted iOS backup created by Finder (or iTunes on older
systems). It is reconstructed from the public `iphone_backup_decrypt` project and
the `iphone-dataprotection` research it builds on, and it is cross-checked
against the proven recovery documented in
`outputs/LINE_iPhone_聊天紀錄修復完整技術報告.md`.

Nothing here is secret. The document deliberately contains no key material,
passwords, or device identifiers from a real backup.

## 1. Directory layout

```
<UDID>/
├── Info.plist          device metadata, XML or binary plist
├── Manifest.plist      encryption metadata and keybag, binary plist
├── Manifest.db         file index, AES-256-CBC encrypted SQLite
├── Status.plist        snapshot state, binary plist
├── 00/ … ff/           payload directories named by the first two hex digits
│   └── <fileID>        encrypted payload
```

`fileID` is the lowercase hex SHA-1 of the UTF-8 string
`<domain> + "-" + <relativePath>`. The payload path is
`<fileID[0..2]>/<fileID>`. Directories and symlinks have Manifest rows but no
payload.

The core reads:

| File | Fields read |
|---|---|
| `Info.plist` | `Device Name`, `Product Version`, `Product Type`, `Unique Identifier`, `Last Backup Date` |
| `Status.plist` | `BackupState`, `Date`, `IsFullBackup`, `SnapshotState`, `UUID`, `Version` |
| `Manifest.plist` | `IsEncrypted`, `Version`, `BackupKeyBag`, `ManifestKey`, `Lockdown.DeviceName`, `Lockdown.ProductVersion`, `Lockdown.UniqueDeviceID`, `Date` |

Intake rules:

- All four files must exist and parse.
- `IsEncrypted` must be `true`. Unencrypted backups carry no keybag and are out of scope.
- `SnapshotState` must equal `finished`. `IsFullBackup = 0` is normal for an incremental snapshot and is **not** a failure.
- `Manifest.db` cannot be validated before the password is known because it is encrypted.

## 2. Keybag (`BackupKeyBag`)

A flat sequence of TLV records: 4 ASCII bytes tag, 4-byte big-endian length,
value. Integer values are 4-byte big-endian.

Header records (appear once, in this order):

| Tag | Type | Meaning |
|---|---|---|
| `VERS` | u32 | keybag version (backup keybags observed as 3 or 4) |
| `TYPE` | u32 | 1 = backup keybag |
| `UUID` | 16 bytes | keybag UUID |
| `HMCK` | 40 bytes | HMAC key (not used by the core) |
| `WRAP` | u32 | wrap flags for the keybag |
| `SALT` | 20 bytes | PBKDF2-SHA1 salt |
| `ITER` | u32 | PBKDF2-SHA1 iteration count |
| `DPWT` | u32 | optional, present with double protection |
| `DPIC` | u32 | optional, PBKDF2-SHA256 iteration count |
| `DPSL` | 20 bytes | optional, PBKDF2-SHA256 salt |

Class-key records. Each starts at a `UUID` tag that follows the header:

| Tag | Type | Meaning |
|---|---|---|
| `UUID` | 16 bytes | class key UUID |
| `CLAS` | u32 | protection class number |
| `WRAP` | u32 | bit 0 = wrapped with device key (unusable off device), bit 1 = wrapped with passcode key |
| `KTYP` | u32 | 0 = AES, 1 = Curve25519 |
| `WPKY` | 40 bytes | wrapped class key |
| `PBKY` | 32 bytes | optional, public key for asymmetric classes |

### 2.1 Passcode key derivation

```
if DPSL and DPIC present:
    tmp = PBKDF2-HMAC-SHA256(password_utf8, DPSL, DPIC, 32)
    passcode_key = PBKDF2-HMAC-SHA1(tmp, SALT, ITER, 32)
else:
    passcode_key = PBKDF2-HMAC-SHA1(password_utf8, SALT, ITER, 32)
```

### 2.2 Class-key unwrapping

For every class record with `WRAP & 2` and `KTYP == 0`:

```
class_key[CLAS] = AES-KeyUnwrap(RFC 3394, kek = passcode_key, WPKY)   # 40 → 32 bytes
```

RFC 3394 unwrap uses the default integrity check value `A6A6A6A6A6A6A6A6`. An
integrity-check failure is the only signal of a wrong password; it must be
reported as an authentication failure without exposing `passcode_key` or any
intermediate value.

Supported classes for payload work: **1, 3, 4**. Class 2 (`KTYP = 1`,
`PBKY` present) wraps file keys asymmetrically and is rejected. Classes above
4 are Keychain classes and are never touched.

## 3. `Manifest.db`

`ManifestKey` in `Manifest.plist` is 44 bytes:

```
bytes 0..4   protection class, little-endian u32
bytes 4..44  wrapped 32-byte key (40 bytes, RFC 3394)
```

```
manifest_key = AES-KeyUnwrap(class_key[class], wrapped)
plaintext    = AES-256-CBC-Decrypt(manifest_key, IV = 16 zero bytes, ciphertext)
```

The decrypted bytes are written to the session workspace as a SQLite file.
The last block is PKCS#7 padding that SQLite ignores; the core removes it when
the final byte is a valid pad length and otherwise reports a malformed index.

Schema the core relies on:

```sql
CREATE TABLE Files (
    fileID TEXT PRIMARY KEY,
    domain TEXT,
    relativePath TEXT,
    flags INTEGER,      -- 1 = regular file, 2 = directory, 4 = symlink
    file BLOB           -- NSKeyedArchiver binary plist, root class MBFile
);
CREATE TABLE Properties (key TEXT PRIMARY KEY, value BLOB);
```

## 4. `MBFile` record (the `file` BLOB)

An NSKeyedArchiver binary plist: top-level dict with `$version`, `$archiver`
(`NSKeyedArchiver`), `$top` (`root` → UID 1), `$objects` (array). The object at
index 1 is the `MBFile` dictionary. Fields read by the core:

| Key | Type | Meaning |
|---|---|---|
| `Size` | integer | size recorded at backup time; for live SQLite stores it routinely differs from the decrypted size and is **not** an error |
| `ProtectionClass` | integer | data-protection class of the file |
| `EncryptionKey` | UID → dict with `NS.data` | 44 bytes: class LE u32 + 40-byte wrapped file key |
| `Digest` | UID → data, optional | SHA-1 of the plaintext when present |
| `Mode` | integer | POSIX mode; the core uses `S_IFMT` to confirm a regular file |
| `RelativePath` | UID → string | same as the `relativePath` column |
| `LastModified`, `Birth`, `InodeNumber`, `UserID`, `GroupID`, `Flags` | integer | reported only |

Payload decryption:

```
file_key  = AES-KeyUnwrap(class_key[EncryptionKey.class], EncryptionKey[4..44])
plaintext = PKCS7-Unpad(AES-256-CBC-Decrypt(file_key, IV = 0, payload))
```

Payload encryption (patching):

```
payload = AES-256-CBC-Encrypt(file_key, IV = 0, PKCS7-Pad(plaintext))
```

PKCS#7 always appends a full 16-byte block when the plaintext is block-aligned,
which is why the proven payload was exactly 16 bytes longer than the database.

## 5. Metadata policy supported by the MVP

| Field | Supported value | Anything else |
|---|---|---|
| `ProtectionClass` | 1, 3, 4 | unsupported |
| `EncryptionKey` | 44 bytes, class matches `ProtectionClass` | unsupported |
| `Digest` | absent | unsupported |
| `Size` | any; left unchanged | — |
| `Manifest.db`, `Manifest.plist` | left byte-identical | — |
| `Status.plist.SnapshotState` | `finished` | unsupported |
| sibling `-wal` / `-journal` | absent, or zero size and empty payload | unsupported for patching |

## 6. LINE payload discovery

Domains searched, in order:

1. `AppDomainGroup-group.com.linecorp.line`
2. `AppDomain-jp.naver.line`

Relative path pattern:

```
Library/Application Support/PrivateStore/P_u<hex>/Messages/Line.sqlite
```

Each `P_u<hex>` directory is one LINE account. The core reports every match
and never picks one automatically when there is more than one. Sibling stores in
the same directory (`E2EEData.sqlite`, `MediaMessageData.sqlite`,
`MessageExt.sqlite`, `UserDataModel.sqlite`) are listed but never modified.

## 7. Reference implementation used for cross-checks

- https://github.com/jsharkey13/iphone_backup_decrypt (tested version 0.11.2 in the proven case)
- https://github.com/jsharkey13/iphone_backup_decrypt/blob/master/src/iphone_backup_decrypt/iphone_backup.py
