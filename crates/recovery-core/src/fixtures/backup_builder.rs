//! Build a synthetic encrypted Finder backup from plaintext files. Mirrors `docs/backup-format.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aes_kw::KwAes256;
use cipher::block_padding::Pkcs7;
use cipher::{BlockModeEncrypt, KeyInit, KeyIvInit};
use plist::{Dictionary, Uid, Value};

use crate::fixtures::prng::Prng;
use crate::hash::backup_file_id;
use crate::{RecoveryError, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

/// One file to place in the backup.
#[derive(Debug, Clone)]
pub struct FixtureFile {
    pub domain: String,
    pub relative_path: String,
    pub plaintext: Vec<u8>,
    pub protection_class: u32,
    /// Emit a `Digest` field (SHA-1 of plaintext) — unsupported by the patcher on purpose.
    pub with_digest: bool,
    /// Override the Manifest `Size` field (live databases often differ). `None` = actual size.
    pub declared_size: Option<u64>,
    /// Emit a Manifest row without a payload (directory entry).
    pub is_directory: bool,
}

impl FixtureFile {
    pub fn regular(
        domain: &str,
        relative_path: &str,
        plaintext: Vec<u8>,
        protection_class: u32,
    ) -> Self {
        Self {
            domain: domain.into(),
            relative_path: relative_path.into(),
            plaintext,
            protection_class,
            with_digest: false,
            declared_size: None,
            is_directory: false,
        }
    }

    pub fn directory(domain: &str, relative_path: &str) -> Self {
        Self {
            domain: domain.into(),
            relative_path: relative_path.into(),
            plaintext: Vec::new(),
            protection_class: 4,
            with_digest: false,
            declared_size: None,
            is_directory: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackupSpec {
    pub password: String,
    pub udid: String,
    pub device_name: String,
    pub product_version: String,
    pub product_type: String,
    /// Unix seconds of the Status.plist Date.
    pub backup_date: i64,
    pub snapshot_state: String,
    pub is_full_backup: bool,
    pub is_encrypted: bool,
    /// Use the double PBKDF2 (DPSL/DPIC) layout of iOS 10.2+.
    pub double_protection: bool,
    /// PBKDF2 iterations (small for tests; real keybags use 10_000_000 / 10_000).
    pub sha256_iterations: u32,
    pub sha1_iterations: u32,
    /// Protection class under which Manifest.db is wrapped.
    pub manifest_key_class: u32,
    pub files: Vec<FixtureFile>,
    pub seed: u64,
}

impl Default for BackupSpec {
    fn default() -> Self {
        Self {
            password: "fixture-password".into(),
            udid: "00000000-FIXTURE00000000".into(),
            device_name: "Fixture iPhone".into(),
            product_version: "18.0".into(),
            product_type: "iPhone17,1".into(),
            backup_date: 1_791_000_397,
            snapshot_state: "finished".into(),
            is_full_backup: false,
            is_encrypted: true,
            double_protection: true,
            sha256_iterations: 1_000,
            sha1_iterations: 1_000,
            manifest_key_class: 3,
            files: Vec::new(),
            seed: 1,
        }
    }
}

/// What the builder produced, for `expected.json`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BuiltBackup {
    pub backup_dir: PathBuf,
    pub udid: String,
    pub files: BTreeMap<String, BuiltFile>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BuiltFile {
    pub file_id: String,
    pub plaintext_size: u64,
    pub payload_size: u64,
    pub plaintext_sha256: String,
}

fn tlv(out: &mut Vec<u8>, tag: &[u8; 4], val: &[u8]) {
    out.extend_from_slice(tag);
    out.extend_from_slice(&(val.len() as u32).to_be_bytes());
    out.extend_from_slice(val);
}

fn tlv_u32(out: &mut Vec<u8>, tag: &[u8; 4], v: u32) {
    tlv(out, tag, &v.to_be_bytes());
}

fn wrap(kek: &[u8; 32], key: &[u8; 32]) -> Vec<u8> {
    let kw = KwAes256::new(&(*kek).into());
    let mut buf = [0u8; 40];
    kw.wrap_key(key, &mut buf).expect("wrap").to_vec()
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    Aes256CbcEnc::new(&(*key).into(), &Default::default()).encrypt_padded_vec::<Pkcs7>(plaintext)
}

fn now_date(secs: i64) -> Value {
    let st = if secs >= 0 {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64)
    } else {
        std::time::UNIX_EPOCH - std::time::Duration::from_secs((-secs) as u64)
    };
    Value::Date(plist::Date::from(st))
}

/// NSKeyedArchiver-encoded MBFile.
fn mbfile_blob(
    f: &FixtureFile,
    encryption_key: Option<&[u8]>,
    digest: Option<&[u8]>,
    mode: u32,
    inode: u64,
    last_modified: i64,
) -> Vec<u8> {
    let mut objects: Vec<Value> = vec![Value::String("$null".into())];
    let mut root = Dictionary::new();
    // indexes: 1 root, 2 relpath, 3 NSMutableData class, 4 MBFile class, 5.. optional
    objects.push(Value::Dictionary(Dictionary::new())); // placeholder root at 1
    objects.push(Value::String(f.relative_path.clone())); // 2
    let mut nsdata_class = Dictionary::new();
    nsdata_class.insert("$classname".into(), Value::String("NSMutableData".into()));
    nsdata_class.insert(
        "$classes".into(),
        Value::Array(vec![
            Value::String("NSMutableData".into()),
            Value::String("NSData".into()),
            Value::String("NSObject".into()),
        ]),
    );
    objects.push(Value::Dictionary(nsdata_class)); // 3
    let mut mbfile_class = Dictionary::new();
    mbfile_class.insert("$classname".into(), Value::String("MBFile".into()));
    mbfile_class.insert(
        "$classes".into(),
        Value::Array(vec![
            Value::String("MBFile".into()),
            Value::String("NSObject".into()),
        ]),
    );
    objects.push(Value::Dictionary(mbfile_class)); // 4

    root.insert("$class".into(), Value::Uid(Uid::new(4)));
    root.insert("RelativePath".into(), Value::Uid(Uid::new(2)));
    root.insert(
        "Size".into(),
        Value::Integer(f.declared_size.unwrap_or(f.plaintext.len() as u64).into()),
    );
    root.insert(
        "ProtectionClass".into(),
        Value::Integer(u64::from(f.protection_class).into()),
    );
    root.insert("Mode".into(), Value::Integer(u64::from(mode).into()));
    root.insert("InodeNumber".into(), Value::Integer(inode.into()));
    root.insert("UserID".into(), Value::Integer(501u64.into()));
    root.insert("GroupID".into(), Value::Integer(501u64.into()));
    root.insert("LastModified".into(), Value::Integer(last_modified.into()));
    root.insert(
        "LastStatusChange".into(),
        Value::Integer(last_modified.into()),
    );
    root.insert(
        "Birth".into(),
        Value::Integer((last_modified - 86_400).into()),
    );
    root.insert("Flags".into(), Value::Integer(0u64.into()));
    root.insert("ExtendedAttributes".into(), Value::Uid(Uid::new(0)));
    if let Some(ek) = encryption_key {
        let mut d = Dictionary::new();
        d.insert("NS.data".into(), Value::Data(ek.to_vec()));
        d.insert("$class".into(), Value::Uid(Uid::new(3)));
        objects.push(Value::Dictionary(d));
        root.insert(
            "EncryptionKey".into(),
            Value::Uid(Uid::new(objects.len() as u64 - 1)),
        );
    }
    if let Some(dg) = digest {
        objects.push(Value::Data(dg.to_vec()));
        root.insert(
            "Digest".into(),
            Value::Uid(Uid::new(objects.len() as u64 - 1)),
        );
    }
    objects[1] = Value::Dictionary(root);

    let mut top = Dictionary::new();
    top.insert("root".into(), Value::Uid(Uid::new(1)));
    let mut archive = Dictionary::new();
    archive.insert("$version".into(), Value::Integer(100_000u64.into()));
    archive.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
    archive.insert("$top".into(), Value::Dictionary(top));
    archive.insert("$objects".into(), Value::Array(objects));
    let mut cur = std::io::Cursor::new(Vec::new());
    Value::Dictionary(archive)
        .to_writer_binary(&mut cur)
        .expect("binary plist");
    cur.into_inner()
}

/// Build the backup under `<out_root>/<UDID>/`.
pub fn build(out_root: &Path, spec: &BackupSpec) -> Result<BuiltBackup> {
    let mut rng = Prng::seeded(spec.seed);
    let backup_dir = out_root.join(&spec.udid);
    std::fs::create_dir_all(&backup_dir).map_err(|e| RecoveryError::io(e, &backup_dir))?;

    // --- Keybag ---
    let salt = rng.bytes(20);
    let dpsl = rng.bytes(20);
    let mut passcode_key = [0u8; 32];
    if spec.double_protection {
        let mut tmp = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            spec.password.as_bytes(),
            &dpsl,
            spec.sha256_iterations,
            &mut tmp,
        );
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&tmp, &salt, spec.sha1_iterations, &mut passcode_key);
    } else {
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            spec.password.as_bytes(),
            &salt,
            spec.sha1_iterations,
            &mut passcode_key,
        );
    }
    let mut class_keys: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    for c in 1..=11u32 {
        let mut k = [0u8; 32];
        rng.fill(&mut k);
        class_keys.insert(c, k);
    }
    let mut kb = Vec::new();
    tlv_u32(&mut kb, b"VERS", 4);
    tlv_u32(&mut kb, b"TYPE", 1);
    tlv(&mut kb, b"UUID", &rng.bytes(16));
    tlv(&mut kb, b"HMCK", &rng.bytes(40));
    tlv_u32(&mut kb, b"WRAP", 1);
    tlv(&mut kb, b"SALT", &salt);
    tlv_u32(&mut kb, b"ITER", spec.sha1_iterations);
    if spec.double_protection {
        tlv_u32(&mut kb, b"DPWT", 0);
        tlv_u32(&mut kb, b"DPIC", spec.sha256_iterations);
        tlv(&mut kb, b"DPSL", &dpsl);
    }
    for (c, key) in &class_keys {
        tlv(&mut kb, b"UUID", &rng.bytes(16));
        tlv_u32(&mut kb, b"CLAS", *c);
        match c {
            // Classes 1,3,4 and keychain-ish 6,7,8,9,10,11: passcode wrapped, AES.
            1 | 3 | 4 | 6 | 7 | 8 | 9 | 10 | 11 => {
                tlv_u32(&mut kb, b"WRAP", 2);
                tlv_u32(&mut kb, b"KTYP", 0);
                tlv(&mut kb, b"WPKY", &wrap(&passcode_key, key));
            }
            // Class 2: asymmetric (Curve25519) — public key present, private key wrapped.
            2 => {
                tlv_u32(&mut kb, b"WRAP", 2);
                tlv_u32(&mut kb, b"KTYP", 1);
                tlv(&mut kb, b"WPKY", &wrap(&passcode_key, key));
                tlv(&mut kb, b"PBKY", &rng.bytes(32));
            }
            // Class 5: device-wrapped only (unusable off device).
            _ => {
                tlv_u32(&mut kb, b"WRAP", 1);
                tlv_u32(&mut kb, b"KTYP", 0);
                tlv(&mut kb, b"WPKY", &rng.bytes(40));
            }
        }
    }

    // --- Manifest.db plaintext ---
    let mut manifest_key = [0u8; 32];
    rng.fill(&mut manifest_key);
    let mut manifest_key_blob = spec.manifest_key_class.to_le_bytes().to_vec();
    manifest_key_blob
        .extend_from_slice(&wrap(&class_keys[&spec.manifest_key_class], &manifest_key));

    let tmp_db = backup_dir.join("Manifest.db.plain.tmp");
    let _ = std::fs::remove_file(&tmp_db);
    let mut built_files = BTreeMap::new();
    {
        let conn = rusqlite::Connection::open(&tmp_db)?;
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE;
             CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);
             CREATE TABLE Properties (key TEXT PRIMARY KEY, value BLOB);
             CREATE INDEX FilesDomainIdx ON Files(domain);
             CREATE INDEX FilesRelativePathIdx ON Files(relativePath);",
        )?;
        let mut inode = 1000u64;
        for f in &spec.files {
            inode += 1;
            let file_id = backup_file_id(&f.domain, &f.relative_path);
            let (flags, mode, ek, dg, payload_size) = if f.is_directory {
                (2i64, 0o040_755u32, None, None, 0u64)
            } else {
                let mut file_key = [0u8; 32];
                rng.fill(&mut file_key);
                let mut ek = f.protection_class.to_le_bytes().to_vec();
                ek.extend_from_slice(&wrap(&class_keys[&f.protection_class], &file_key));
                let payload = encrypt(&file_key, &f.plaintext);
                let shard = backup_dir.join(&file_id[..2]);
                std::fs::create_dir_all(&shard).map_err(|e| RecoveryError::io(e, &shard))?;
                let p = shard.join(&file_id);
                std::fs::write(&p, &payload).map_err(|e| RecoveryError::io(e, &p))?;
                let dg = f
                    .with_digest
                    .then(|| hex::decode(crate::hash::sha1_hex(&f.plaintext)).expect("hex"));
                (1i64, 0o100_644u32, Some(ek), dg, payload.len() as u64)
            };
            let blob = mbfile_blob(
                f,
                ek.as_deref(),
                dg.as_deref(),
                mode,
                inode,
                spec.backup_date - 3600,
            );
            conn.execute(
                "INSERT INTO Files (fileID, domain, relativePath, flags, file) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![file_id, f.domain, f.relative_path, flags, blob],
            )?;
            built_files.insert(
                format!("{}|{}", f.domain, f.relative_path),
                BuiltFile {
                    file_id,
                    plaintext_size: f.plaintext.len() as u64,
                    payload_size,
                    plaintext_sha256: crate::hash::Sha256Hex::of_bytes(&f.plaintext).0,
                },
            );
        }
        conn.execute(
            "INSERT INTO Properties (key, value) VALUES ('salt', ?1)",
            [rng.bytes(16)],
        )?;
    }
    let plain = std::fs::read(&tmp_db).map_err(|e| RecoveryError::io(e, &tmp_db))?;
    std::fs::remove_file(&tmp_db).map_err(|e| RecoveryError::io(e, &tmp_db))?;
    let manifest_db_path = backup_dir.join("Manifest.db");
    if spec.is_encrypted {
        std::fs::write(&manifest_db_path, encrypt(&manifest_key, &plain))
            .map_err(|e| RecoveryError::io(e, &manifest_db_path))?;
    } else {
        std::fs::write(&manifest_db_path, &plain)
            .map_err(|e| RecoveryError::io(e, &manifest_db_path))?;
    }

    // --- Manifest.plist ---
    let mut lockdown = Dictionary::new();
    lockdown.insert("DeviceName".into(), Value::String(spec.device_name.clone()));
    lockdown.insert(
        "ProductVersion".into(),
        Value::String(spec.product_version.clone()),
    );
    lockdown.insert(
        "ProductType".into(),
        Value::String(spec.product_type.clone()),
    );
    lockdown.insert("UniqueDeviceID".into(), Value::String(spec.udid.clone()));
    let mut mp = Dictionary::new();
    mp.insert("IsEncrypted".into(), Value::Boolean(spec.is_encrypted));
    mp.insert("Version".into(), Value::String("10.0".into()));
    mp.insert("Date".into(), now_date(spec.backup_date - 60));
    mp.insert("SystemDomainsVersion".into(), Value::String("24.0".into()));
    mp.insert("WasPasscodeSet".into(), Value::Boolean(true));
    mp.insert("Lockdown".into(), Value::Dictionary(lockdown));
    mp.insert("Applications".into(), Value::Dictionary(Dictionary::new()));
    if spec.is_encrypted {
        mp.insert("BackupKeyBag".into(), Value::Data(kb));
        mp.insert("ManifestKey".into(), Value::Data(manifest_key_blob));
    }
    let p = backup_dir.join("Manifest.plist");
    Value::Dictionary(mp).to_file_binary(&p)?;

    // --- Status.plist ---
    let mut st = Dictionary::new();
    st.insert("BackupState".into(), Value::String("new".into()));
    st.insert("Date".into(), now_date(spec.backup_date));
    st.insert("IsFullBackup".into(), Value::Boolean(spec.is_full_backup));
    st.insert(
        "SnapshotState".into(),
        Value::String(spec.snapshot_state.clone()),
    );
    st.insert(
        "UUID".into(),
        Value::String(
            format!(
                "{}-{}-{}-{}-{}",
                rng.hex(4),
                rng.hex(2),
                rng.hex(2),
                rng.hex(2),
                rng.hex(6)
            )
            .to_uppercase(),
        ),
    );
    st.insert("Version".into(), Value::String("3.3".into()));
    Value::Dictionary(st).to_file_binary(backup_dir.join("Status.plist"))?;

    // --- Info.plist (XML, like real backups) ---
    let mut info = Dictionary::new();
    info.insert(
        "Device Name".into(),
        Value::String(spec.device_name.clone()),
    );
    info.insert(
        "Product Version".into(),
        Value::String(spec.product_version.clone()),
    );
    info.insert(
        "Product Type".into(),
        Value::String(spec.product_type.clone()),
    );
    info.insert("Unique Identifier".into(), Value::String(spec.udid.clone()));
    info.insert("Last Backup Date".into(), now_date(spec.backup_date));
    info.insert("iTunes Version".into(), Value::String("12.13".into()));
    Value::Dictionary(info).to_file_xml(backup_dir.join("Info.plist"))?;

    Ok(BuiltBackup {
        backup_dir,
        udid: spec.udid.clone(),
        files: built_files,
    })
}
