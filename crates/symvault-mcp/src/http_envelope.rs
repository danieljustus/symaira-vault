//! Go-compatible decoding of the HTTP `/mcp` JSON-RPC envelope.
//!
//! The Go HTTP handler decodes the first JSON value of a request body into
//! `transport.Message` with `encoding/json` and hands it straight to the
//! protocol handler. It does **not** apply the stdio loop's `jsonrpc == "2.0"`
//! / method-required guards. This module reproduces the decoder's observable
//! rules so the HTTP adapter can dispatch the same messages:
//!
//! * the top level must be a JSON object or `null` (`null` decodes to the zero
//!   message); arrays and scalars fail;
//! * the member rules (case-insensitive names with Go's simple Unicode
//!   folding, `null` no-ops, raw `id`/`params`/`result`, the `error` object)
//!   live in [`crate::envelope`], shared with the stdio loop; this transport
//!   asks for Go's last-wins on a repeated member.
//!
//! Rust still requires exactly one complete JSON value (ADR 0017): trailing
//! input is a rejection rather than silently ignored.
use crate::Message;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

/// Stream-validates one top-level JSON object or `null` without keeping it.
struct Entries;

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntriesVisitor;
        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = Entries;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object or null")
            }

            fn visit_unit<E>(self) -> Result<Entries, E> {
                Ok(Entries)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Entries, A::Error> {
                while map.next_key::<String>()?.is_some() {
                    map.next_value::<Box<RawValue>>()?;
                }
                Ok(Entries)
            }
        }
        deserializer.deserialize_any(EntriesVisitor)
    }
}

/// Decodes one complete request body as Go's `transport.Message`. Go's own
/// last-wins rule applies to repeated members (the stdio loop rejects them, the
/// HTTP handler never did); both share [`crate::envelope`].
pub(super) fn decode(body: &str) -> Result<Message, ()> {
    if crate::max_nesting_depth(body) > crate::MAX_ACCEPTED_NESTING_DEPTH {
        return Err(());
    }
    crate::envelope::decode(body, crate::envelope::Duplicates::LastWins).map_err(|_| ())
}

/// Whether a bounded prefix is a definitive syntax/type error (not merely
/// incomplete), mirroring the streaming decoder's early rejection.
pub(super) fn prefix_is_definitively_invalid(prefix: &[u8]) -> bool {
    serde_json::from_slice::<Entries>(prefix).is_err_and(|error| !error.is_eof())
}

/// Streaming variant of [`prefix_is_definitively_invalid`] for a bounded reader.
pub(super) fn parse_reader<R: std::io::Read>(reader: R) -> Result<(), serde_json::Error> {
    serde_json::from_reader::<_, Entries>(reader).map(|_| ())
}
