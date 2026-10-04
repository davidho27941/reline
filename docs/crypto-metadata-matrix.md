# Supported Cryptographic and Metadata Combinations

| Dimension | Supported | Test (accept) | Unsupported | Test (reject) |
|---|---|---|---|---|
| Keybag derivation | double PBKDF2 (`DPSL`/`DPIC` SHA-256 then `SALT`/`ITER` SHA-1) | `intake.rs::intake_succeeds_and_source_is_byte_identical` | — | — |
| Keybag derivation | single PBKDF2-SHA1 (`SALT`/`ITER` only) | `intake.rs::single_pbkdf2_keybag_layout_is_supported` | malformed TLV, missing SALT/ITER, DPSL without DPIC | `keybag.rs` parser errors (`malformed_metadata`) |
| Class key wrap | RFC 3394 AES-256 key wrap, `WRAP & 2`, `KTYP = 0` | RFC 3394 §6.4 vector in `/tmp` probe and fixture round trip via Python reference | device-wrapped (`WRAP & 1`), Curve25519 (`KTYP = 1`) | skipped at unlock; class 2 rejected by `unsupported_metadata_fails_closed` |
| File protection class | 1, 3, 4 | `intake.rs::unsupported_metadata_fails_closed` (classes 1, 4) and default fixtures (class 3) | 2 and any other | `unsupported_metadata_fails_closed` |
| `EncryptionKey` layout | 44 bytes: LE u32 class + 40-byte wrapped key; class must equal `ProtectionClass` | all intake tests | other lengths, class mismatch | `keybag.rs::unwrap_file_key` → `unsupported_metadata` |
| Payload cipher | AES-256-CBC, zero IV, PKCS#7 (full block when aligned) | `payload.rs::roundtrip_sizes_across_chunk_boundaries`, `block_aligned_plaintext_gets_full_padding_block` | wrong key, flipped bit, truncation | `one_bit_flip_in_key_or_ciphertext_is_rejected_or_differs` |
| `Digest` in MBFile | absent | default fixtures | present | `unsupported_metadata_fails_closed` (Digest) |
| Manifest `Size` | any value; left unchanged | fixtures use an oversized declared size | — | — |
| `Manifest.db` / `Manifest.plist` | left byte-identical | `e2e.rs::full_chain_produces_verified_export_with_227_repairs` | — | — |
| `Status.plist.SnapshotState` | `finished` | all intake tests | anything else | `invalid_structures_are_rejected_before_password` |
| Sibling `-wal` / `-journal` | absent or empty | default fixtures | non-empty | `pending_wal_blocks_patching_but_allows_diagnostics`, `e2e.rs::non_patchable_current_backup_blocks_patching` |
| Round trip | mandatory decrypt-and-hash of generated payload; clone re-read through intake | `e2e.rs::full_chain_produces_verified_export_with_227_repairs`, `clone_verification_rejects_a_tampered_payload` | — | — |

Known-answer sources: RFC 3394 (AES key wrap), RFC 6070 (PBKDF2-HMAC-SHA1), the PBKDF2-SHA256
vector `password/salt/4096`, and the independent decryption of generated fixtures by
`iphone_backup_decrypt 0.11.2` (`scripts/verify_fixture_reference.py`).
