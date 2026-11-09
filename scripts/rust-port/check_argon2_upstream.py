#!/usr/bin/env python3
"""Reject upstream drift outside the explicit, hash-pinned local patches.

Local patches: the Go legacy memory constructor (src/params.rs, excised before
hashing) and the lane-parallel block filling (src/lib.rs, pinned by the
`local_patches` hash in UPSTREAM.json, since it rewrites fill_blocks).
"""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2] / "third_party/argon2"
metadata = json.loads((root / "UPSTREAM.json").read_text())
assert metadata["crate_sha256"] == "3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072"
local = metadata["local_patches"]
for name, expected in metadata["original_files"].items():
    raw = (root / name).read_bytes()
    if "patched_sha256" in local.get(name, {}):
        # Patched file: the upstream hash is kept in original_files for
        # provenance; the retained patch is pinned by its own hash.
        assert hashlib.sha256(raw).hexdigest() == local[name]["patched_sha256"], name
        continue
    if name == "src/params.rs":
        begin = raw.index(b"    /// Constructs parameters solely for Go")
        end = raw.index(b"    /// Memory size, expressed in kibibytes.", begin)
        raw = raw[:begin] + raw[end:]
    assert hashlib.sha256(raw).hexdigest() == expected, name
print("PASS upstream Argon2 source hashes; only the legacy constructor and pinned lane-parallel fill added")
