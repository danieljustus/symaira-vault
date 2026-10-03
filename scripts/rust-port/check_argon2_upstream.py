#!/usr/bin/env python3
"""Reject upstream drift outside the explicit Go legacy parameter constructor."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2] / "third_party/argon2"
metadata = json.loads((root / "UPSTREAM.json").read_text())
assert metadata["crate_sha256"] == "3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072"
for name, expected in metadata["original_files"].items():
    raw = (root / name).read_bytes()
    if name == "src/params.rs":
        begin = raw.index(b"    /// Constructs parameters solely for Go")
        end = raw.index(b"    /// Memory size, expressed in kibibytes.", begin)
        raw = raw[:begin] + raw[end:]
    assert hashlib.sha256(raw).hexdigest() == expected, name
print("PASS upstream Argon2 source hashes; only explicit legacy constructor added")
