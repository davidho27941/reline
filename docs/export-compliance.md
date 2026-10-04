# Dependency Licensing and Cryptography Export Compliance

## Third-party notices

`THIRD-PARTY-NOTICES.md` is generated from `cargo metadata` by `scripts/gen-licenses.py` and
checked in. `scripts/gen-licenses.py --check` fails when any resolved dependency is missing
or its license changed; CI runs it. All bundled Rust dependencies are MIT, Apache-2.0,
BSD-3-Clause, or Unicode-3.0 licensed; SQLite is public domain. The Swift package has no
third-party dependencies.

## Cryptography

The application implements AES-256-CBC, AES key wrap (RFC 3394), PBKDF2-HMAC-SHA1/SHA-256,
SHA-1 and SHA-256 through the RustCrypto crates to read and re-encrypt the user's own
encrypted iOS backups. Cryptography is used for data protection of the user's own files and
performs no key exchange, no communications security, and no network transmission.

For distribution outside the Mac App Store, Apple's App Store Connect export-compliance
questionnaire does not apply, but U.S. EAR rules do. The use case falls under the mass-market
note (standard, published algorithms; no custom cryptography) and is self-classified as
ECCN 5D992.c with the License Exception ENC; an annual self-classification report is filed
when required. If the app is later submitted to the App Store, answer "Yes" to using
encryption and claim the exemption for encryption that protects the user's own stored data,
and set `ITSAppUsesNonExemptEncryption` accordingly in `Info.plist`.
