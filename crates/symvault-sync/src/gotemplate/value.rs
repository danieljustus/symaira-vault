//! The reflect-free value model: exactly the dynamic types a template over
//! `RenderData` and the repo's function map can ever observe.

use super::gostr::Bytes;
use std::collections::BTreeMap;
use std::rc::Rc;

pub type StrMap = BTreeMap<Bytes, Bytes>;

/// `template.RenderData`.
#[derive(Clone, Debug, Default)]
pub struct RenderData {
    pub name: Bytes,
    pub refs: Rc<StrMap>,
    pub values: Rc<StrMap>,
}

#[derive(Clone, Debug)]
pub enum Value {
    /// `reflect.Value{}` / a nil interface.
    Invalid,
    Bool(bool),
    /// Go `int`.
    Int(i64),
    /// Go `uint8` (what indexing a string yields).
    Uint8(u8),
    Float(f64),
    Complex(f64, f64),
    Str(Bytes),
    /// `map[string]string`.
    Map(Rc<StrMap>),
    /// `template.RenderData`.
    Data(Rc<RenderData>),
    /// An `error` value; only used as a formatting argument.
    Err(Bytes),
}

impl Value {
    pub fn str(s: &str) -> Self {
        Value::Str(s.as_bytes().to_vec())
    }

    /// `reflect.Type.String()`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Invalid => "<nil>",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Uint8(_) => "uint8",
            Value::Float(_) => "float64",
            Value::Complex(..) => "complex128",
            Value::Str(_) => "string",
            Value::Map(_) => "map[string]string",
            Value::Data(_) => "template.RenderData",
            Value::Err(_) => "*fmt.wrapError",
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self, Value::Invalid)
    }
}
