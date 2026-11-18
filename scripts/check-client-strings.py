#!/usr/bin/env python3
"""Checks that every text of the macOS and iOS apps has a German translation.

Both apps look texts up with L("..."); the catalogs are
client/Sources/SymvaultFeature/Resources/Localizable.xcstrings (macOS) and
client/Sources/SymvaultIOS/Localizable.xcstrings (iOS app bundle). A text without
an entry would show in English in a German interface, an entry without a text
is dead weight, and differing placeholders crash String(format:). Exits 1 on
any of them.
"""
import json
import pathlib
import re
import sys

sources = pathlib.Path(__file__).resolve().parent.parent / "client" / "Sources"
targets = [
    (sources / "SymvaultFeature", sources / "SymvaultFeature" / "Resources" / "Localizable.xcstrings"),
    (sources / "SymvaultIOS", sources / "SymvaultIOS" / "Localizable.xcstrings"),
]
problems = []
counts = []
for root, catalog_path in targets:
    used = set()
    for source in root.glob("*.swift"):
        used.update(re.findall(r'\bL\(\s*"((?:[^"\\]|\\.)*)"', source.read_text()))
    catalog = json.loads(catalog_path.read_text())["strings"]
    translated = {
        key
        for key, entry in catalog.items()
        if entry.get("localizations", {}).get("de", {}).get("stringUnit", {}).get("value")
    }
    name = root.name
    problems += [f"{name}: no German text: {key}" for key in sorted(used - translated)]
    problems += [f"{name}: not used any more: {key}" for key in sorted(set(catalog) - used)]
    for key in sorted(used & translated):
        german = catalog[key]["localizations"]["de"]["stringUnit"]["value"]
        if re.findall(r"%[@d]", key) != re.findall(r"%[@d]", german):
            problems.append(f"{name}: placeholders differ: {key}")
    counts.append(f"{name} {len(used)}")
print("\n".join(problems) if problems else "all translated: " + ", ".join(counts))
sys.exit(1 if problems else 0)
