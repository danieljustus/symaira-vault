//! Whole-envelope validation before metadata or unknown JSON is materialized.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;

use crate::{MAX_ARRAY_ITEMS, MAX_ENTRY_PLAINTEXT_BYTES_V1, MAX_VALUE_BYTES, StoreError};

const MAX_DEPTH: usize = 34;
const MAX_KEYS: usize = 4096;
const MAX_VALUES: usize = 65_536;

#[derive(Default)]
struct Budget {
    cost: usize,
    keys: usize,
    values: usize,
    exceeded: bool,
    index_remaining: Option<usize>,
}

impl Budget {
    fn limit<E: serde::de::Error>(&mut self) -> E {
        self.exceeded = true;
        E::custom("vault resource limit exceeded")
    }
    fn charge<E: serde::de::Error>(&mut self, cost: usize) -> Result<(), E> {
        self.cost += cost;
        if let Some(remaining) = self.index_remaining {
            if cost > remaining {
                return Err(self.limit());
            }
            self.index_remaining = Some(remaining - cost);
        }
        Ok(())
    }
}

pub(crate) fn validate(bytes: &[u8], path: &str) -> Result<(), StoreError> {
    if bytes.len() as u64 > MAX_ENTRY_PLAINTEXT_BYTES_V1 {
        return Err(StoreError::ResourceLimit);
    }
    validate_budget(bytes, path, Budget::default()).map(|_| ())
}

pub(crate) fn validate_with_batch(
    bytes: &[u8],
    path: &str,
    batch: Option<&crate::read_admission::Batch>,
) -> Result<(), StoreError> {
    if batch.is_none() {
        return validate(bytes, path);
    }
    if bytes.len() as u64 > MAX_ENTRY_PLAINTEXT_BYTES_V1 {
        return Err(StoreError::ResourceLimit);
    }
    let cost = validate_budget(bytes, path, Budget::default())?;
    if let Some(batch) = batch {
        batch.consume_decoded(cost)?;
    }
    Ok(())
}

pub(crate) fn validate_index(bytes: &[u8], path: &str) -> Result<(), StoreError> {
    if bytes.len() > crate::read_admission::MAX_INDEX_BYTES {
        return Err(StoreError::ResourceLimit);
    }
    validate_budget(
        bytes,
        path,
        Budget {
            index_remaining: Some(crate::read_admission::MAX_INDEX_BYTES),
            ..Default::default()
        },
    )
    .map(|_| ())
}

pub(crate) fn validate_journal(bytes: &[u8], path: &str) -> Result<(), StoreError> {
    if bytes.len() as u64 > MAX_ENTRY_PLAINTEXT_BYTES_V1 {
        return Err(StoreError::ResourceLimit);
    }
    validate_budget(
        bytes,
        path,
        Budget {
            index_remaining: Some(MAX_ENTRY_PLAINTEXT_BYTES_V1 as usize),
            ..Default::default()
        },
    )
    .map(|_| ())
}

fn validate_budget(bytes: &[u8], path: &str, mut budget: Budget) -> Result<usize, StoreError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let result = ValueSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .and_then(|()| decoder.end());
    if budget.exceeded {
        return Err(StoreError::ResourceLimit);
    }
    result
        .map(|()| budget.cost)
        .map_err(|error| StoreError::Entry {
            path: path.to_owned(),
            detail: error.to_string(),
        })
}

struct ValueSeed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        self.budget.values += 1;
        if self.depth > MAX_DEPTH
            || (self.budget.index_remaining.is_none() && self.budget.values > MAX_VALUES)
        {
            return Err(self.budget.limit());
        }
        self.budget.charge(256)?;
        decoder.deserialize_any(ValueVisitor {
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

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            self.budget.keys += 1;
            if (self.budget.index_remaining.is_none() && self.budget.keys > MAX_KEYS)
                || key.len() > MAX_VALUE_BYTES
            {
                return Err(self.budget.limit());
            }
            self.budget.charge(256 + 6 * key.len())?;
            map.next_value_seed(ValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut items = 0;
        while seq
            .next_element_seed(ValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?
            .is_some()
        {
            items += 1;
            if self.budget.index_remaining.is_none() && items > MAX_ARRAY_ITEMS {
                return Err(self.budget.limit());
            }
        }
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() > MAX_VALUE_BYTES {
            return Err(self.budget.limit());
        }
        self.budget.charge(6 * value.len())
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<(), E> {
        self.visit_str(value)
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<(), E> {
        self.visit_str(&value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_and_unknown_fields_share_the_shape_budget() {
        for field in ["meta", "future"] {
            for count in [MAX_ARRAY_ITEMS, MAX_ARRAY_ITEMS + 1] {
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "data": {}, field: {"tags": vec!["public-fixture"; count]}
                }))
                .unwrap();
                let result = validate(&bytes, "fixture");
                if count == MAX_ARRAY_ITEMS {
                    result.unwrap();
                } else {
                    assert!(matches!(result, Err(StoreError::ResourceLimit)));
                }
            }
        }
    }

    #[test]
    fn raw_duplicate_keys_and_nested_small_values_are_counted() {
        let raw = format!("{{{}}}", vec!["\"future\":null"; MAX_KEYS].join(","));
        validate(raw.as_bytes(), "fixture").unwrap();
        let raw = format!("{{{}}}", vec!["\"future\":null"; MAX_KEYS + 1].join(","));
        assert!(matches!(
            validate(raw.as_bytes(), "fixture"),
            Err(StoreError::ResourceLimit)
        ));
        let bytes =
            serde_json::to_vec(&serde_json::json!({"future": vec![vec![0; 1024]; 65]})).unwrap();
        assert!(matches!(
            validate(&bytes, "fixture"),
            Err(StoreError::ResourceLimit)
        ));
    }
}
