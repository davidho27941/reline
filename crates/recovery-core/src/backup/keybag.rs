//! Backup keybag parsing and unlocking. See `docs/backup-format.md` §2.

use std::collections::HashMap;

use aes_kw::KwAes256;
use cipher::KeyInit;

use crate::secret::{Key256, Password, SecretBytes};
use crate::{ErrorCode, RecoveryError, Result};

/// Protection classes whose file keys the core can unwrap (symmetric AES key wrap).
pub const SUPPORTED_CLASSES: [u32; 3] = [1, 3, 4];

const WRAP_PASSCODE: u32 = 2;
const KTYP_AES: u32 = 0;

/// (CLAS, WRAP, KTYP, WPKY, has PBKY) while a class record is being parsed.
type PendingClass = (Option<u32>, Option<u32>, Option<u32>, Option<Vec<u8>>, bool);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassKeyRecord {
    pub class: u32,
    pub wrap: u32,
    pub ktyp: u32,
    pub has_public_key: bool,
    wrapped: Vec<u8>,
}

/// Parsed (still locked) keybag.
#[derive(Debug, Clone)]
pub struct Keybag {
    pub version: u32,
    pub kb_type: u32,
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub dp_salt: Option<Vec<u8>>,
    pub dp_iterations: Option<u32>,
    pub class_keys: Vec<ClassKeyRecord>,
}

fn be_u32(v: &[u8]) -> Result<u32> {
    let arr: [u8; 4] = v.try_into().map_err(|_| {
        RecoveryError::new(
            ErrorCode::MalformedMetadata,
            "keybag integer field is not 4 bytes",
        )
    })?;
    Ok(u32::from_be_bytes(arr))
}

impl Keybag {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let mut version = None;
        let mut kb_type = None;
        let mut salt = None;
        let mut iterations = None;
        let mut dp_salt = None;
        let mut dp_iterations = None;
        let mut class_keys: Vec<ClassKeyRecord> = Vec::new();
        let mut current: Option<PendingClass> = None;
        let mut seen_header_uuid = false;

        let bad =
            |m: &str| RecoveryError::new(ErrorCode::MalformedMetadata, format!("keybag: {m}"));
        while pos + 8 <= bytes.len() {
            let tag = &bytes[pos..pos + 4];
            let len = be_u32(&bytes[pos + 4..pos + 8])? as usize;
            pos += 8;
            if pos + len > bytes.len() {
                return Err(bad("record length exceeds data"));
            }
            let val = &bytes[pos..pos + len];
            pos += len;
            match tag {
                b"VERS" => version = Some(be_u32(val)?),
                b"TYPE" => kb_type = Some(be_u32(val)?),
                b"SALT" => salt = Some(val.to_vec()),
                b"ITER" => iterations = Some(be_u32(val)?),
                b"DPSL" => dp_salt = Some(val.to_vec()),
                b"DPIC" => dp_iterations = Some(be_u32(val)?),
                b"HMCK" | b"WRAP" | b"DPWT" if current.is_none() => {}
                b"UUID" => {
                    if !seen_header_uuid {
                        seen_header_uuid = true;
                    } else {
                        if let Some(rec) = current.take() {
                            class_keys.push(finish_record(rec)?);
                        }
                        current = Some((None, None, None, None, false));
                    }
                }
                b"CLAS" => {
                    if current.is_none() {
                        current = Some((None, None, None, None, false));
                    }
                    current.as_mut().expect("set").0 = Some(be_u32(val)?);
                }
                b"WRAP" => {
                    current
                        .as_mut()
                        .ok_or_else(|| bad("WRAP outside class record"))?
                        .1 = Some(be_u32(val)?)
                }
                b"KTYP" => {
                    current
                        .as_mut()
                        .ok_or_else(|| bad("KTYP outside class record"))?
                        .2 = Some(be_u32(val)?)
                }
                b"WPKY" => {
                    current
                        .as_mut()
                        .ok_or_else(|| bad("WPKY outside class record"))?
                        .3 = Some(val.to_vec())
                }
                b"PBKY" => {
                    current
                        .as_mut()
                        .ok_or_else(|| bad("PBKY outside class record"))?
                        .4 = true
                }
                _ => {} // unknown tags are ignored (forward compatible, never mutated)
            }
        }
        if pos != bytes.len() {
            return Err(bad("trailing bytes"));
        }
        if let Some(rec) = current.take() {
            class_keys.push(finish_record(rec)?);
        }
        let salt = salt.ok_or_else(|| bad("missing SALT"))?;
        if salt.len() != 20 {
            return Err(bad("SALT is not 20 bytes"));
        }
        if let Some(s) = &dp_salt {
            if s.len() != 20 {
                return Err(bad("DPSL is not 20 bytes"));
            }
        }
        if dp_salt.is_some() != dp_iterations.is_some() {
            return Err(bad("DPSL and DPIC must appear together"));
        }
        Ok(Self {
            version: version.ok_or_else(|| bad("missing VERS"))?,
            kb_type: kb_type.ok_or_else(|| bad("missing TYPE"))?,
            salt,
            iterations: iterations.ok_or_else(|| bad("missing ITER"))?,
            dp_salt,
            dp_iterations,
            class_keys,
        })
    }

    /// Derive the passcode key and unwrap every passcode-wrapped symmetric class key.
    /// A wrong password surfaces as `AuthenticationFailed` with no key material in the error.
    pub fn unlock(&self, password: &Password) -> Result<UnlockedKeybag> {
        if self.iterations == 0 || self.iterations > 50_000_000 {
            return Err(RecoveryError::new(
                ErrorCode::MalformedMetadata,
                "keybag iteration count out of range",
            ));
        }
        let mut passcode_key = zeroize::Zeroizing::new([0u8; 32]);
        match (&self.dp_salt, self.dp_iterations) {
            (Some(dpsl), Some(dpic)) => {
                if dpic == 0 || dpic > 50_000_000 {
                    return Err(RecoveryError::new(
                        ErrorCode::MalformedMetadata,
                        "keybag DPIC out of range",
                    ));
                }
                let mut tmp = zeroize::Zeroizing::new([0u8; 32]);
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), dpsl, dpic, tmp.as_mut());
                pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
                    tmp.as_ref(),
                    &self.salt,
                    self.iterations,
                    passcode_key.as_mut(),
                );
            }
            _ => {
                pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
                    password.as_bytes(),
                    &self.salt,
                    self.iterations,
                    passcode_key.as_mut(),
                );
            }
        }
        let kek = KwAes256::new(&(*passcode_key).into());
        let mut class_keys = HashMap::new();
        let mut any_passcode_wrapped = false;
        for rec in &self.class_keys {
            if rec.wrap & WRAP_PASSCODE == 0 || rec.ktyp != KTYP_AES {
                continue;
            }
            // Device-wrapped keys (bit 0) cannot be unwrapped off-device; skip them.
            if rec.wrap & 1 != 0 {
                continue;
            }
            any_passcode_wrapped = true;
            if rec.wrapped.len() != 40 {
                return Err(RecoveryError::new(
                    ErrorCode::MalformedMetadata,
                    format!("class {} wrapped key is not 40 bytes", rec.class),
                ));
            }
            let mut out = zeroize::Zeroizing::new([0u8; 32]);
            match kek.unwrap_key(&rec.wrapped, out.as_mut()) {
                Ok(_) => {
                    class_keys.insert(
                        rec.class,
                        Key256::from_slice(out.as_ref()).expect("32 bytes"),
                    );
                }
                Err(_) => {
                    return Err(RecoveryError::new(
                        ErrorCode::AuthenticationFailed,
                        "backup password rejected",
                    )
                    .with_remedy("Check the encrypted-backup password. Nothing was changed."));
                }
            }
        }
        if !any_passcode_wrapped {
            return Err(RecoveryError::new(
                ErrorCode::MalformedMetadata,
                "keybag contains no passcode-wrapped class keys",
            ));
        }
        Ok(UnlockedKeybag { class_keys })
    }
}

fn finish_record(rec: PendingClass) -> Result<ClassKeyRecord> {
    let bad = |m: &str| {
        RecoveryError::new(
            ErrorCode::MalformedMetadata,
            format!("keybag class record: {m}"),
        )
    };
    Ok(ClassKeyRecord {
        class: rec.0.ok_or_else(|| bad("missing CLAS"))?,
        wrap: rec.1.ok_or_else(|| bad("missing WRAP"))?,
        ktyp: rec.2.unwrap_or(KTYP_AES),
        has_public_key: rec.4,
        wrapped: rec.3.ok_or_else(|| bad("missing WPKY"))?,
    })
}

/// Unlocked class keys. Never serialized; zeroized on drop through `Key256`.
pub struct UnlockedKeybag {
    class_keys: HashMap<u32, Key256>,
}

impl std::fmt::Debug for UnlockedKeybag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut classes: Vec<_> = self.class_keys.keys().copied().collect();
        classes.sort_unstable();
        f.debug_struct("UnlockedKeybag")
            .field("classes", &classes)
            .finish()
    }
}

impl UnlockedKeybag {
    pub fn has_class(&self, class: u32) -> bool {
        self.class_keys.contains_key(&class)
    }

    /// Unwrap a 40-byte wrapped key under `class`. Fails closed for unsupported classes.
    pub fn unwrap_key(&self, class: u32, wrapped: &[u8]) -> Result<Key256> {
        if !SUPPORTED_CLASSES.contains(&class) {
            return Err(RecoveryError::new(
                ErrorCode::UnsupportedMetadata,
                format!("protection class {class} is not supported (supported: 1, 3, 4)"),
            ));
        }
        let class_key = self.class_keys.get(&class).ok_or_else(|| {
            RecoveryError::new(
                ErrorCode::UnsupportedMetadata,
                format!("keybag has no usable key for protection class {class}"),
            )
        })?;
        if wrapped.len() != 40 {
            return Err(RecoveryError::new(
                ErrorCode::MalformedMetadata,
                format!("wrapped key has {} bytes, expected 40", wrapped.len()),
            ));
        }
        let kek = KwAes256::new(&(*class_key.as_bytes()).into());
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        kek.unwrap_key(wrapped, out.as_mut()).map_err(|_| {
            RecoveryError::new(
                ErrorCode::CryptoFailure,
                format!("key unwrap integrity check failed for class {class}"),
            )
        })?;
        Ok(Key256::from_slice(out.as_ref()).expect("32 bytes"))
    }

    /// Unwrap the `ManifestKey` (4-byte LE class + 40-byte wrapped key).
    pub fn unwrap_manifest_key(&self, manifest_key: &[u8]) -> Result<Key256> {
        if manifest_key.len() != 44 {
            return Err(RecoveryError::new(
                ErrorCode::MalformedMetadata,
                "ManifestKey is not 44 bytes",
            ));
        }
        let class = u32::from_le_bytes(manifest_key[..4].try_into().expect("4 bytes"));
        self.unwrap_key(class, &manifest_key[4..])
    }

    /// Unwrap an `MBFile.EncryptionKey` (same layout as ManifestKey) and check the class
    /// matches the record's `ProtectionClass`.
    pub fn unwrap_file_key(
        &self,
        protection_class: u32,
        encryption_key: &SecretBytes,
    ) -> Result<Key256> {
        let ek = encryption_key.as_slice();
        if ek.len() != 44 {
            return Err(RecoveryError::new(
                ErrorCode::UnsupportedMetadata,
                format!("EncryptionKey has {} bytes, expected 44", ek.len()),
            ));
        }
        let class = u32::from_le_bytes(ek[..4].try_into().expect("4 bytes"));
        if class != protection_class {
            return Err(RecoveryError::new(
                ErrorCode::UnsupportedMetadata,
                format!(
                    "EncryptionKey class {class} does not match ProtectionClass {protection_class}"
                ),
            ));
        }
        self.unwrap_key(class, &ek[4..])
    }
}
