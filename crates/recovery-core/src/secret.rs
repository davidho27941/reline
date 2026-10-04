//! Zeroizing secret containers with redacting `Debug`.
//!
//! Secrets never implement `Serialize`, so they cannot reach the session manifest, reports,
//! or FFI JSON by accident.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owned secret byte string (passwords, derived keys, wrapped/unwrapped keys).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison; lengths leak but are not secret here.
        if self.0.len() != other.0.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for SecretBytes {}

/// A fixed 32-byte AES-256 key.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Key256([u8; 32]);

impl Key256 {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(bytes);
        Some(Self(k))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Key256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key256(<redacted>)")
    }
}

/// Backup password as supplied by the user.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Password(Vec<u8>);

impl Password {
    pub fn new(utf8: &str) -> Self {
        Self(utf8.as_bytes().to_vec())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// Scratch buffer that zeroizes on drop; used for decrypted chunks of sensitive data.
pub type ScratchBuf = Zeroizing<Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts() {
        let s = SecretBytes::from_slice(b"hunter2");
        assert_eq!(format!("{s:?}"), "SecretBytes(<7 bytes redacted>)");
        let p = Password::new("hunter2");
        assert!(!format!("{p:?}").contains("hunter2"));
        let k = Key256::from_slice(&[1u8; 32]).unwrap();
        assert_eq!(format!("{k:?}"), "Key256(<redacted>)");
    }

    #[test]
    fn constant_time_eq() {
        assert_eq!(
            SecretBytes::from_slice(b"ab"),
            SecretBytes::from_slice(b"ab")
        );
        assert_ne!(
            SecretBytes::from_slice(b"ab"),
            SecretBytes::from_slice(b"ac")
        );
        assert_ne!(
            SecretBytes::from_slice(b"ab"),
            SecretBytes::from_slice(b"abc")
        );
    }
}
