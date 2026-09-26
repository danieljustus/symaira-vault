//! Streaming validation for untrusted decrypted entry JSON.

use serde::de::{Deserialize, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

use crate::{MAX_ARRAY_ITEMS, MAX_ENTRY_DEPTH, MAX_ENTRY_FIELDS, MAX_VALUE_BYTES, StoreError};

struct Budget {
    violation: Option<&'static str>,
    top_level_fields: usize,
    nested_fields: usize,
}

impl Budget {
    fn fail(&mut self, reason: &'static str) {
        if self.violation.is_none() {
            self.violation = Some(reason);
        }
    }
}

/// Validates `data` while traversing JSON tokens, before an entry `Value` is
/// materialized. Duplicate keys are counted as Go's token decoder counts them.
pub(crate) fn validate(bytes: &[u8], path: &str) -> Result<(), StoreError> {
    let mut budget = Budget {
        violation: None,
        top_level_fields: 0,
        nested_fields: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = RootSeed(&mut budget)
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end());
    if let Some(reason) = budget.violation {
        return Err(StoreError::ValueLimit(reason.into()));
    }
    parsed.map_err(|error| StoreError::Entry {
        path: path.to_owned(),
        detail: error.to_string(),
    })
}

struct RootSeed<'a>(&'a mut Budget);

impl<'de> DeserializeSeed<'de> for RootSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(RootVisitor(self.0))
    }
}

struct RootVisitor<'a>(&'a mut Budget);

impl<'de> Visitor<'de> for RootVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON entry envelope")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen_data = false;
        while let Some(key) = map.next_key::<String>()? {
            if key.eq_ignore_ascii_case("data") {
                if seen_data {
                    self.0.fail("duplicate data fields");
                    map.next_value::<IgnoredAny>()?;
                } else {
                    seen_data = true;
                    map.next_value_seed(DataSeed(self.0))?;
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}

struct DataSeed<'a>(&'a mut Budget);

impl<'de> DeserializeSeed<'de> for DataSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(DataVisitor(self.0))
    }
}

struct DataVisitor<'a>(&'a mut Budget);

impl<'de> Visitor<'de> for DataVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object or null for entry data")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            self.0.top_level_fields = self.0.top_level_fields.saturating_add(1);
            if self.0.top_level_fields > MAX_ENTRY_FIELDS {
                self.0.fail("too many top-level fields");
            }
            if key.len() > MAX_VALUE_BYTES {
                self.0.fail("field name too large");
            }
            map.next_value_seed(ValueSeed {
                budget: self.0,
                depth: 1,
            })?;
        }
        Ok(())
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        self.0.fail("entry data must be an object");
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        self.0.fail("entry data must be an object");
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        self.0.fail("entry data must be an object");
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        self.0.fail("entry data must be an object");
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        self.0.fail("entry data must be an object");
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, _: String) -> Result<(), E> {
        self.0.fail("entry data must be an object");
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.0.fail("entry data must be an object");
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }
}

struct ValueSeed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.depth > MAX_ENTRY_DEPTH {
            self.budget.fail("maximum nesting depth exceeded");
            return IgnoredAny::deserialize(deserializer).map(|_| ());
        }
        deserializer.deserialize_any(ValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct ValueVisitor<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON entry value")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() > MAX_VALUE_BYTES {
            self.budget.fail("string value too large");
        }
        Ok(())
    }

    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<(), E> {
        self.visit_str(value)
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<(), E> {
        self.visit_str(&value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut items = 0usize;
        while let Some(()) = seq.next_element_seed(ValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            items = items.saturating_add(1);
            if items > MAX_ARRAY_ITEMS {
                self.budget.fail("array has too many items");
            }
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_VALUE_BYTES {
                self.budget.fail("field name too large");
            }
            self.budget.nested_fields = self.budget.nested_fields.saturating_add(1);
            if self.budget.nested_fields > MAX_ENTRY_FIELDS {
                self.budget.fail("too many fields");
            }
            map.next_value_seed(ValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
}
