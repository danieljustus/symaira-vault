#!/usr/bin/env python3
"""Generate crates/symvault-core/src/config_schema.rs from the Go config structs.

`symvault config set` re-reads the written file with yaml.v3 into the typed
`config.Config` struct; the Rust port needs the same field types to reproduce
yaml.v3's `cannot unmarshal !!int ... into time.Duration` errors. The table is
read from every non-test file of internal/config so it cannot drift silently:

    python3 scripts/rust-port/gen_config_schema.py          # rewrite
    python3 scripts/rust-port/gen_config_schema.py --check  # fail on drift

Only the structs reachable from `Config` through the field types matter; a
field's Go type is recorded verbatim (`*time.Duration`, `[]string`,
`map[string]AgentProfile`, ...).

A field the script cannot turn into a table row is an error, never a silent
omission: a field line it cannot parse, a yaml tag flag the table cannot model
(`,inline`), a tag of the legacy raw form, an embedded or multi-name exported
field, and a field type that crates/symvault-core/src/config_typed.rs does not
decode. The key is yaml.v3's own: the first element of the `yaml:"..."` tag
wherever it sits in the tag string, else the lower-cased field name;
`yaml:"-"` and unexported fields are not part of the document.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "internal/config"
TARGET = ROOT / "crates/symvault-core/src/config_schema.rs"
ROOT_STRUCT = "Config"

# Scalar and library types config_typed.rs decodes; every other name in a
# reachable field type must be a struct of the package.
MODELED_TYPES = {"string", "bool", "int", "int64", "time.Duration", "time.Time"}

STRUCT = re.compile(r"^type (\w+) struct \{\n(.*?)^\}", re.S | re.M)
# `Name Type `tags`` / `A, B Type` / embedded `*pkg.Type `tags``, then an
# optional line comment. Types have no spaces (`map[string][]string`).
FIELD = re.compile(
    r"^\s*(?:(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+)?"
    r"(?P<type>[*\[\]\w.]+)"
    r"\s*(?:`(?P<tag>[^`]*)`)?\s*(?://.*)?$"
)
YAML_TAG = re.compile(r'(?:^|\s)yaml:"((?:[^"\\]|\\.)*)"')
TYPE_WORD = re.compile(r"(?<![\w.])([A-Za-z_]\w*)")


class SchemaError(Exception):
    pass


UNMARSHALER = re.compile(r"^func \(\s*\w*\s*\*?(\w+)\s*\)\s*(UnmarshalYAML|UnmarshalText)\(", re.M)


def source_files():
    files = sorted(p for p in CONFIG_DIR.glob("*.go") if not p.name.endswith("_test.go"))
    if not files:
        raise SchemaError(f"no Go files below {CONFIG_DIR}")
    return files


def struct_bodies():
    """`{struct name: (file, body)}` of every struct of the package."""
    found = {}
    for path in source_files():
        for name, body in STRUCT.findall(path.read_text()):
            if name in found:
                raise SchemaError(f"struct {name} is defined in {found[name][0].name} and {path.name}")
            found[name] = (path, body)
    return found


def field_key(where, name, tag):
    """The yaml key of an exported field, or None when yaml.v3 skips it."""
    if tag is None:
        return name.lower()
    match = YAML_TAG.search(tag)
    if not match:
        if tag.strip() and ":" not in tag:
            raise SchemaError(f'{where}: legacy raw struct tag `{tag}` (yaml.v3 reads it as the yaml tag); write yaml:"..."')
        return name.lower()
    value = match.group(1)
    if value == "-":
        return None
    parts = value.split(",")
    for flag in parts[1:]:
        if flag not in ("omitempty", "flow"):
            raise SchemaError(f"{where}: yaml tag flag {flag!r} in `{tag}` is not modeled by the config schema table")
    return parts[0] or name.lower()


def check_type(where, go_type, bodies):
    """Fail unless config_typed.rs can decode every part of `go_type`."""
    inner = go_type
    while True:
        for prefix in ("*", "[]", "map[string]"):
            if inner.startswith(prefix):
                inner = inner[len(prefix):]
                break
        else:
            break
    if inner not in MODELED_TYPES and inner not in bodies:
        raise SchemaError(f"{where}: field type {go_type!r} is not decoded by crates/symvault-core/src/config_typed.rs")


def parse_struct(name, path, body, bodies):
    fields = []
    where = f"{path.relative_to(ROOT)}: struct {name}"
    for line in body.splitlines():
        text = line.strip()
        if not text or text.startswith("//"):
            continue
        if text.endswith("{") or text.startswith("}"):
            raise SchemaError(f"{where}: nested or anonymous struct field `{text}` is not supported")
        match = FIELD.match(line)
        if not match:
            raise SchemaError(f"{where}: cannot parse field line `{text}`")
        names, go_type, tag = match.group("names"), match.group("type"), match.group("tag")
        if names is None:
            # An embedded type: yaml.v3 reads an exported one as a field named
            # after the type (or inlines it); neither is modeled.
            embedded = go_type.lstrip("*").split(".")[-1]
            if embedded[:1].isupper():
                raise SchemaError(f"{where}: embedded exported field `{text}` is not supported")
            continue
        listed = [item.strip() for item in names.split(",")]
        if not any(item[:1].isupper() for item in listed):
            continue
        if len(listed) > 1:
            raise SchemaError(f"{where}: multi-name exported field `{text}` is not supported")
        key = field_key(f"{where}.{listed[0]}", listed[0], tag)
        if key is None:
            continue
        if any(key == seen for seen, _ in fields):
            # yaml.v3 refuses such a struct at decode time.
            raise SchemaError(f"{where}: duplicate yaml key '{key}'")
        check_type(f"{where}.{listed[0]}", go_type, bodies)
        fields.append((key, go_type))
    return fields


def structs():
    bodies = struct_bodies()
    if ROOT_STRUCT not in bodies:
        raise SchemaError(f"struct {ROOT_STRUCT} not found below {CONFIG_DIR}")
    found = {}
    pending = [ROOT_STRUCT]
    while pending:
        name = pending.pop()
        if name in found:
            continue
        path, body = bodies[name]
        found[name] = parse_struct(name, path, body, bodies)
        for _, go_type in found[name]:
            for word in TYPE_WORD.findall(go_type):
                if word in bodies and word not in found:
                    pending.append(word)
    reached = set(found)
    for fields in found.values():
        for _, go_type in fields:
            reached.update(TYPE_WORD.findall(go_type))
    for path in source_files():
        for receiver, method in UNMARSHALER.findall(path.read_text()):
            if receiver in reached:
                # A custom decoder changes what yaml.v3 accepts; the table
                # cannot model it.
                raise SchemaError(f"{path.relative_to(ROOT)}: {receiver}.{method} is not supported")
    return found


def render(found):
    out = [
        "// @generated by scripts/rust-port/gen_config_schema.py from",
        "// the non-test files of internal/config; do not edit.",
        "// `make config-cli-differential` fails when this file drifts from the Go source.",
        "",
        "/// `(struct name, [(yaml key, Go type)])` of every struct reachable from the Go",
        "/// `Config`, the types verbatim (`*time.Duration`, `[]string`, ...).",
        "#[rustfmt::skip]",
        "pub(crate) const GO_CONFIG_STRUCTS: &[(&str, &[(&str, &str)])] = &[",
    ]
    for name in sorted(found):
        out.append(f'    ("{name}", &[')
        for key, go_type in found[name]:
            out.append(f'        ("{key}", "{go_type}"),')
        out.append("    ]),")
    out.append("];")
    return "\n".join(out) + "\n"


def main():
    try:
        rendered = render(structs())
    except SchemaError as error:
        sys.exit(f"gen_config_schema.py: {error}")
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text() != rendered:
            sys.exit(f"{TARGET.relative_to(ROOT)} is stale; run scripts/rust-port/gen_config_schema.py")
        print(f"PASS {TARGET.relative_to(ROOT)} matches the Go config structs")
        return
    TARGET.write_text(rendered)
    print(f"WROTE {TARGET.relative_to(ROOT)}")


main()
