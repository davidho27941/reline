#!/usr/bin/env python3
"""Independent reference check for synthetic fixtures (task 1.6).

Decrypts a generated fixture backup with the public `iphone_backup_decrypt` library (the same
library used in the proven manual recovery) and compares the extracted Line.sqlite SHA-256 with
the value the Rust fixture generator recorded in expected.json.

Usage:
    uv run --with iphone_backup_decrypt==0.11.2 --with pycryptodome \
        scripts/verify_fixture_reference.py <fixture-dir>
"""
import hashlib
import json
import sys
from pathlib import Path

from iphone_backup_decrypt import EncryptedBackup


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    fixture = Path(sys.argv[1])
    expected = json.loads((fixture / "expected.json").read_text())
    password = expected["spec"]["password"]
    ok = True
    for role, key in (("old", "old_line_sha256"), ("current", "current_line_sha256")):
        backup_dir = Path(expected[f"{role}_backup_dir"])
        out = fixture / f"reference_{role}_Line.sqlite"
        backup = EncryptedBackup(backup_directory=str(backup_dir), passphrase=password)
        backup.extract_file(
            relative_path=expected["line_relative_path"],
            domain_like=expected["line_domain"],
            output_filename=str(out),
        )
        got = sha256(out)
        match = got == expected[key]
        ok &= match
        print(f"{role}: reference sha256 {got} expected {expected[key]} -> {'MATCH' if match else 'MISMATCH'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
