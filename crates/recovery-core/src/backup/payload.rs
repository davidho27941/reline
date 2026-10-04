//! Streaming AES-256-CBC (zero IV, PKCS#7) for backup payloads. See `docs/backup-format.md` §4.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use cipher::consts::U16;
use cipher::{Array, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use sha2::{Digest, Sha256};

use crate::hash::{Sha256Hex, CHUNK_SIZE};
use crate::progress::{ProgressSink, Stage};
use crate::secret::Key256;
use crate::session::workspace::create_private_file;
use crate::{ErrorCode, RecoveryError, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub const BLOCK: usize = 16;

/// Result of a streaming crypto operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StreamResult {
    pub input_size: u64,
    pub output_size: u64,
    /// SHA-256 of the bytes written.
    pub output_sha256: Sha256Hex,
}

fn zero_iv() -> Array<u8, U16> {
    Array::default()
}

/// Decrypt `src` (ciphertext) into `dst` (0600). Validates PKCS#7 padding strictly.
pub fn decrypt_file(
    src: &Path,
    dst: &Path,
    key: &Key256,
    progress: &dyn ProgressSink,
    stage: Stage,
) -> Result<StreamResult> {
    let mut input = File::open(src).map_err(|e| RecoveryError::io(e, src))?;
    let total = input
        .metadata()
        .map_err(|e| RecoveryError::io(e, src))?
        .len();
    if total == 0 || total % BLOCK as u64 != 0 {
        return Err(RecoveryError::new(
            ErrorCode::CryptoFailure,
            format!("ciphertext length {total} is not a positive multiple of 16"),
        )
        .with_path(src));
    }
    let mut output = create_private_file(dst)?;
    let mut dec = Aes256CbcDec::new(&(*key.as_bytes()).into(), &zero_iv());
    let mut hasher = Sha256::new();
    // Keep the last block back until EOF so padding can be validated and stripped.
    let mut buf = zeroize::Zeroizing::new(vec![0u8; CHUNK_SIZE + BLOCK]);
    let mut held = 0usize; // bytes of decrypted data held at buf[..held] awaiting EOF decision
    let mut read_total = 0u64;
    let mut written = 0u64;
    loop {
        progress.check_cancelled()?;
        let n = input
            .read(&mut buf[held..held + CHUNK_SIZE])
            .map_err(|e| RecoveryError::io(e, src))?;
        if n == 0 {
            break;
        }
        read_total += n as u64;
        let avail = held + n;
        let whole = avail - avail % BLOCK;
        {
            let (blocks, _) = Array::<u8, U16>::slice_as_chunks_mut(&mut buf[held..whole]);
            dec.decrypt_blocks(blocks);
        }
        // Emit everything except the final block of the file; we only know it is final at EOF,
        // so always keep one block back.
        let keep = if read_total == total {
            BLOCK
        } else {
            BLOCK.min(whole)
        };
        let emit = whole.saturating_sub(keep);
        if emit > 0 {
            output
                .write_all(&buf[..emit])
                .map_err(|e| RecoveryError::io(e, dst))?;
            hasher.update(&buf[..emit]);
            written += emit as u64;
        }
        // Shift remainder (kept decrypted block + partial undecrypted tail) to the front.
        buf.copy_within(emit..avail, 0);
        held = avail - emit;
        progress.report(stage, read_total, total);
        if read_total == total {
            break;
        }
    }
    if held != BLOCK {
        return Err(
            RecoveryError::new(ErrorCode::CryptoFailure, "ciphertext ended mid-block")
                .with_path(src),
        );
    }
    let last = &buf[..BLOCK];
    let pad = last[BLOCK - 1] as usize;
    if pad == 0 || pad > BLOCK || !last[BLOCK - pad..].iter().all(|&b| b as usize == pad) {
        return Err(RecoveryError::new(
            ErrorCode::CryptoFailure,
            "invalid PKCS#7 padding (wrong key or corrupt payload)",
        )
        .with_path(src));
    }
    let tail = &last[..BLOCK - pad];
    output
        .write_all(tail)
        .map_err(|e| RecoveryError::io(e, dst))?;
    hasher.update(tail);
    written += tail.len() as u64;
    output.sync_all().map_err(|e| RecoveryError::io(e, dst))?;
    Ok(StreamResult {
        input_size: total,
        output_size: written,
        output_sha256: Sha256Hex(hex::encode(hasher.finalize())),
    })
}

/// Encrypt `src` (plaintext) into `dst` (0600) with PKCS#7 (always appends 1..=16 bytes).
pub fn encrypt_file(
    src: &Path,
    dst: &Path,
    key: &Key256,
    progress: &dyn ProgressSink,
    stage: Stage,
) -> Result<StreamResult> {
    let mut input = File::open(src).map_err(|e| RecoveryError::io(e, src))?;
    let total = input
        .metadata()
        .map_err(|e| RecoveryError::io(e, src))?
        .len();
    let mut output = create_private_file(dst)?;
    let mut enc = Aes256CbcEnc::new(&(*key.as_bytes()).into(), &zero_iv());
    let mut hasher = Sha256::new();
    let mut buf = zeroize::Zeroizing::new(vec![0u8; CHUNK_SIZE + BLOCK]);
    let mut held = 0usize;
    let mut read_total = 0u64;
    let mut written = 0u64;
    loop {
        progress.check_cancelled()?;
        let n = input
            .read(&mut buf[held..held + CHUNK_SIZE])
            .map_err(|e| RecoveryError::io(e, src))?;
        let avail = held + n;
        if n == 0 {
            // Final: pad and encrypt the remainder.
            let pad = BLOCK - (avail % BLOCK);
            for b in &mut buf[avail..avail + pad] {
                *b = pad as u8;
            }
            let end = avail + pad;
            let (blocks, _) = Array::<u8, U16>::slice_as_chunks_mut(&mut buf[..end]);
            enc.encrypt_blocks(blocks);
            output
                .write_all(&buf[..end])
                .map_err(|e| RecoveryError::io(e, dst))?;
            hasher.update(&buf[..end]);
            written += end as u64;
            break;
        }
        read_total += n as u64;
        let whole = avail - avail % BLOCK;
        {
            let (blocks, _) = Array::<u8, U16>::slice_as_chunks_mut(&mut buf[..whole]);
            enc.encrypt_blocks(blocks);
        }
        output
            .write_all(&buf[..whole])
            .map_err(|e| RecoveryError::io(e, dst))?;
        hasher.update(&buf[..whole]);
        written += whole as u64;
        buf.copy_within(whole..avail, 0);
        held = avail - whole;
        progress.report(stage, read_total, total);
    }
    output.sync_all().map_err(|e| RecoveryError::io(e, dst))?;
    Ok(StreamResult {
        input_size: total,
        output_size: written,
        output_sha256: Sha256Hex(hex::encode(hasher.finalize())),
    })
}

/// Expected ciphertext length for a plaintext of `n` bytes.
pub fn ciphertext_len(n: u64) -> u64 {
    n + (BLOCK as u64 - n % BLOCK as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::NoProgress;
    use cipher::block_padding::Pkcs7;

    fn roundtrip(len: usize) {
        let dir = tempfile::tempdir().unwrap();
        let pt = dir.path().join("pt");
        let ct = dir.path().join("ct");
        let back = dir.path().join("back");
        let data: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
        std::fs::write(&pt, &data).unwrap();
        let key = Key256::from_slice(&[0x42; 32]).unwrap();
        let e = encrypt_file(&pt, &ct, &key, &NoProgress, Stage::Patching).unwrap();
        assert_eq!(e.output_size, ciphertext_len(len as u64));
        // Reference: one-shot RustCrypto with the same parameters.
        let reference = Aes256CbcEnc::new(&(*key.as_bytes()).into(), &zero_iv())
            .encrypt_padded_vec::<Pkcs7>(&data);
        assert_eq!(std::fs::read(&ct).unwrap(), reference, "len {len}");
        let d = decrypt_file(&ct, &back, &key, &NoProgress, Stage::Patching).unwrap();
        assert_eq!(d.output_size, len as u64);
        assert_eq!(std::fs::read(&back).unwrap(), data);
        assert_eq!(d.output_sha256, Sha256Hex::of_bytes(&data));
    }

    #[test]
    fn roundtrip_sizes_across_chunk_boundaries() {
        for len in [
            0usize,
            1,
            15,
            16,
            17,
            4096,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            CHUNK_SIZE + 16,
            2 * CHUNK_SIZE + 5,
        ] {
            roundtrip(len);
        }
    }

    #[test]
    fn block_aligned_plaintext_gets_full_padding_block() {
        // Proven case: 580706304-byte DB -> 580706320-byte payload.
        assert_eq!(ciphertext_len(580_706_304), 580_706_320);
        assert_eq!(ciphertext_len(580_714_496), 580_714_512);
    }

    #[test]
    fn one_bit_flip_in_key_or_ciphertext_is_rejected_or_differs() {
        let dir = tempfile::tempdir().unwrap();
        let pt = dir.path().join("pt");
        let ct = dir.path().join("ct");
        let data = vec![9u8; 4096];
        std::fs::write(&pt, &data).unwrap();
        let key = Key256::from_slice(&[0x42; 32]).unwrap();
        encrypt_file(&pt, &ct, &key, &NoProgress, Stage::Patching).unwrap();
        // Wrong key: padding check fails (overwhelmingly likely) or plaintext hash differs.
        let mut kb = [0x42u8; 32];
        kb[0] ^= 1;
        let bad_key = Key256::from_slice(&kb).unwrap();
        let out = dir.path().join("out");
        match decrypt_file(&ct, &out, &bad_key, &NoProgress, Stage::Patching) {
            Err(e) => assert_eq!(e.code, ErrorCode::CryptoFailure),
            Ok(r) => assert_ne!(r.output_sha256, Sha256Hex::of_bytes(&data)),
        }
        // Flip a bit in the last ciphertext block: padding breaks.
        let mut c = std::fs::read(&ct).unwrap();
        let n = c.len();
        c[n - 1] ^= 1;
        std::fs::write(&ct, &c).unwrap();
        match decrypt_file(&ct, &out, &key, &NoProgress, Stage::Patching) {
            Err(e) => assert_eq!(e.code, ErrorCode::CryptoFailure),
            Ok(r) => assert_ne!(r.output_sha256, Sha256Hex::of_bytes(&data)),
        }
        // Truncated ciphertext.
        std::fs::write(&ct, &c[..n - 3]).unwrap();
        assert_eq!(
            decrypt_file(&ct, &out, &key, &NoProgress, Stage::Patching)
                .unwrap_err()
                .code,
            ErrorCode::CryptoFailure
        );
    }

    #[test]
    fn cancellation_stops_mid_stream() {
        let dir = tempfile::tempdir().unwrap();
        let pt = dir.path().join("pt");
        let ct = dir.path().join("ct");
        std::fs::write(&pt, vec![1u8; 3 * CHUNK_SIZE]).unwrap();
        let key = Key256::from_slice(&[1; 32]).unwrap();
        let sink = crate::progress::CancelAfter::new(1);
        let err = encrypt_file(&pt, &ct, &key, &sink, Stage::Patching).unwrap_err();
        assert!(err.is_cancelled());
    }
}
