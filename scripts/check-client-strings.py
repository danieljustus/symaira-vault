#!/usr/bin/env python3
"""Checks that every text of the macOS app has a German translation.

The app looks texts up with L("..."); the catalog is
client/Sources/SymvaultFeature/Resources/Localizable.xcstrings. A text without
an entry would show in English in a German interface, an entry without a text
is dead weight, and differing placeholders crash String(format:). Exits 1 on
any of them.
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent / "client" / "Sources" / "SymvaultFeature"
used = set()
for source in root.glob("*.swift"):
    used.update(re.findall(r'\bL\(\s*"((?:[^"\\]|\\.)*)"', source.read_text()))
catalog = json.loads((root / "Resources" / "Localizable.xcstrings").read_text())["strings"]
translated = {
    key
    for key, entry in catalog.items()
    if entry.get("localizations", {}).get("de", {}).get("stringUnit", {}).get("value")
}
problems = [f"no German text: {key}" for key in sorted(used - translated)]
problems += [f"not used any more: {key}" for key in sorted(set(catalog) - used)]
for key in sorted(used & translated):
    german = catalog[key]["localizations"]["de"]["stringUnit"]["value"]
    if re.findall(r"%[@d]", key) != re.findall(r"%[@d]", german):
        problems.append(f"placeholders differ: {key}")
print("\n".join(problems) if problems else f"{len(used)} texts, all translated")
sys.exit(1 if problems else 0)
