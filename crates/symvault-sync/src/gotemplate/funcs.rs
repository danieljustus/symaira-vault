//! The function table: Go's `text/template` builtins plus the repo's
//! `DefaultFuncMap` (`b64enc b64url upper lower tojson`), implemented over
//! the reflect-free value model.

use super::gofmt::{sprint, sprintf, sprintln};
use super::gostr::{Bytes, decode_rune, to_lower, to_upper};
use super::strconv::{format_float, is_print};
use super::value::Value;
use base64::{Engine as _, engine::general_purpose};

/// A parameter type, as far as `evalArg`/`validateType` distinguish them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PType {
    /// `string`
    Str,
    /// `interface{}`
    Any,
    /// `reflect.Value`
    Rv,
}

impl PType {
    pub fn name(self) -> &'static str {
        match self {
            PType::Str => "string",
            PType::Any => "interface {}",
            PType::Rv => "reflect.Value",
        }
    }

    pub fn can_be_nil(self) -> bool {
        !matches!(self, PType::Str)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Func {
    B64enc,
    B64url,
    Upper,
    Lower,
    Tojson,
    And,
    Or,
    Call,
    Html,
    Index,
    Slice,
    Js,
    Len,
    Not,
    Print,
    Printf,
    Println,
    Urlquery,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

pub struct Sig {
    pub params: &'static [PType],
    pub variadic: bool,
}

use PType::{Any, Rv, Str};

impl Func {
    /// `findFunction`: the custom map is consulted first (no overlap with
    /// the builtins here), then the builtins.
    pub fn find(name: &[u8]) -> Option<(Func, bool)> {
        let f = match name {
            b"b64enc" => (Func::B64enc, false),
            b"b64url" => (Func::B64url, false),
            b"upper" => (Func::Upper, false),
            b"lower" => (Func::Lower, false),
            b"tojson" => (Func::Tojson, false),
            b"and" => (Func::And, true),
            b"or" => (Func::Or, true),
            b"call" => (Func::Call, true),
            b"html" => (Func::Html, true),
            b"index" => (Func::Index, true),
            b"slice" => (Func::Slice, true),
            b"js" => (Func::Js, true),
            b"len" => (Func::Len, true),
            b"not" => (Func::Not, true),
            b"print" => (Func::Print, true),
            b"printf" => (Func::Printf, true),
            b"println" => (Func::Println, true),
            b"urlquery" => (Func::Urlquery, true),
            b"eq" => (Func::Eq, true),
            b"ne" => (Func::Ne, true),
            b"lt" => (Func::Lt, true),
            b"le" => (Func::Le, true),
            b"gt" => (Func::Gt, true),
            b"ge" => (Func::Ge, true),
            _ => return None,
        };
        Some(f)
    }

    pub fn sig(self) -> Sig {
        match self {
            Func::B64enc | Func::B64url | Func::Upper | Func::Lower => Sig {
                params: &[Str],
                variadic: false,
            },
            Func::Tojson => Sig {
                params: &[Any],
                variadic: false,
            },
            Func::And | Func::Or | Func::Call | Func::Index | Func::Slice | Func::Eq => Sig {
                params: &[Rv, Rv],
                variadic: true,
            },
            Func::Html | Func::Js | Func::Urlquery | Func::Print | Func::Println => Sig {
                params: &[Any],
                variadic: true,
            },
            Func::Printf => Sig {
                params: &[Str, Any],
                variadic: true,
            },
            Func::Len | Func::Not => Sig {
                params: &[Rv],
                variadic: false,
            },
            Func::Ne | Func::Lt | Func::Le | Func::Gt | Func::Ge => Sig {
                params: &[Rv, Rv],
                variadic: false,
            },
        }
    }
}

/// `truth(arg)` / `isTrue`.
pub fn is_true(v: &Value) -> bool {
    match v {
        Value::Invalid => false,
        Value::Bool(b) => *b,
        Value::Int(i) => *i != 0,
        Value::Uint8(u) => *u != 0,
        Value::Float(f) => *f != 0.0,
        Value::Complex(re, im) => *re != 0.0 || *im != 0.0,
        Value::Str(s) => !s.is_empty(),
        Value::Map(m) => !m.is_empty(),
        Value::Data(_) | Value::Err(_) => true,
    }
}

type FResult = Result<Value, Bytes>;

fn msg(s: &str) -> Bytes {
    s.as_bytes().to_vec()
}

fn fmt_err(format: &str, args: &[Value]) -> Bytes {
    super::gofmt::errorf(format.as_bytes(), args)
}

fn as_str(v: &Value) -> &[u8] {
    match v {
        Value::Str(s) => s,
        _ => &[],
    }
}

/// Dispatch for every function that is not special-cased by `evalCall`
/// (`and`, `or`, `call`).
pub fn call(f: Func, argv: &[Value]) -> FResult {
    match f {
        Func::B64enc => Ok(Value::Str(
            general_purpose::STANDARD
                .encode(as_str(&argv[0]))
                .into_bytes(),
        )),
        Func::B64url => Ok(Value::Str(
            general_purpose::URL_SAFE
                .encode(as_str(&argv[0]))
                .into_bytes(),
        )),
        Func::Upper => Ok(Value::Str(to_upper(as_str(&argv[0])))),
        Func::Lower => Ok(Value::Str(to_lower(as_str(&argv[0])))),
        Func::Tojson => Ok(Value::Str(to_json(&argv[0]).unwrap_or_default())),
        Func::Html => Ok(Value::Str(html_escape(&eval_args(argv)))),
        Func::Js => Ok(Value::Str(js_escape(&eval_args(argv)))),
        Func::Urlquery => Ok(Value::Str(query_escape(&eval_args(argv)))),
        Func::Print => Ok(Value::Str(sprint(argv))),
        Func::Println => Ok(Value::Str(sprintln(argv))),
        Func::Printf => Ok(Value::Str(sprintf(as_str(&argv[0]), &argv[1..]))),
        Func::Index => index(&argv[0], &argv[1..]),
        Func::Slice => slice(&argv[0], &argv[1..]),
        Func::Len => length(&argv[0]),
        Func::Not => Ok(Value::Bool(!is_true(&argv[0]))),
        Func::Eq => eq(&argv[0], &argv[1..]).map(Value::Bool),
        Func::Ne => eq(&argv[0], &argv[1..2]).map(|b| Value::Bool(!b)),
        Func::Lt => lt(&argv[0], &argv[1]).map(Value::Bool),
        Func::Le => le(&argv[0], &argv[1]).map(Value::Bool),
        Func::Gt => le(&argv[0], &argv[1]).map(|b| Value::Bool(!b)),
        Func::Ge => lt(&argv[0], &argv[1]).map(|b| Value::Bool(!b)),
        Func::And | Func::Or | Func::Call => Err(msg("unreachable")),
    }
}

/// `call(name, fn, args...)`: no template value is ever a function.
pub fn call_builtin_call(name: &[u8], argv: &[Value]) -> FResult {
    // argv[0] is fn (indirectInterface is a no-op here).
    let f = &argv[0];
    if !f.is_valid() {
        return Err(msg("call of nil"));
    }
    let mut e = b"non-function ".to_vec();
    e.extend_from_slice(name);
    e.extend_from_slice(b" of type ");
    e.extend_from_slice(f.type_name().as_bytes());
    Err(e)
}

/// `evalArgs`.
fn eval_args(args: &[Value]) -> Bytes {
    if let [Value::Str(s)] = args {
        return s.clone();
    }
    let converted: Vec<Value> = args
        .iter()
        .map(|a| {
            if a.is_valid() {
                a.clone()
            } else {
                Value::str("<no value>")
            }
        })
        .collect();
    sprint(&converted)
}

pub fn html_escape(s: &[u8]) -> Bytes {
    let mut out = Bytes::with_capacity(s.len());
    for &c in s {
        match c {
            0 => out.extend_from_slice("\u{FFFD}".as_bytes()),
            b'"' => out.extend_from_slice(b"&#34;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn js_is_special(r: u32) -> bool {
    matches!(
        char::from_u32(r),
        Some('\\' | '\'' | '"' | '<' | '>' | '&' | '=')
    ) || !(0x20..0x80).contains(&r)
}

pub fn js_escape(s: &[u8]) -> Bytes {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Bytes::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !js_is_special(u32::from(c)) {
            out.push(c);
            i += 1;
            continue;
        }
        if c < 0x80 {
            match c {
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'\'' => out.extend_from_slice(b"\\'"),
                b'"' => out.extend_from_slice(b"\\\""),
                b'<' => out.extend_from_slice(b"\\u003C"),
                b'>' => out.extend_from_slice(b"\\u003E"),
                b'&' => out.extend_from_slice(b"\\u0026"),
                b'=' => out.extend_from_slice(b"\\u003D"),
                _ => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[(c >> 4) as usize]);
                    out.push(HEX[(c & 0xF) as usize]);
                }
            }
            i += 1;
        } else {
            let (r, size) = decode_rune(&s[i..]);
            if is_print(r) {
                out.extend_from_slice(&s[i..i + size]);
            } else {
                out.extend_from_slice(format!("\\u{r:04X}").as_bytes());
            }
            i += size;
        }
    }
    out
}

/// `url.QueryEscape`.
pub fn query_escape(s: &[u8]) -> Bytes {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Bytes::with_capacity(s.len());
    for &c in s {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(c),
            b' ' => out.push(b'+'),
            _ => {
                out.push(b'%');
                out.push(HEX[(c >> 4) as usize]);
                out.push(HEX[(c & 0xF) as usize]);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// index / slice / len
// ---------------------------------------------------------------------------

fn index_arg(index: &Value, cap: usize) -> Result<usize, Bytes> {
    let x: i64 = match index {
        Value::Int(i) => *i,
        Value::Uint8(u) => i64::from(*u),
        Value::Invalid => return Err(msg("cannot index slice/array with nil")),
        other => {
            return Err(fmt_err(
                "cannot index slice/array with type %s",
                &[Value::str(other.type_name())],
            ));
        }
    };
    if x < 0 || (x as u64) > cap as u64 {
        return Err(fmt_err("index out of range: %d", &[Value::Int(x)]));
    }
    Ok(x as usize)
}

fn index(item: &Value, indexes: &[Value]) -> FResult {
    if !item.is_valid() {
        return Err(msg("index of untyped nil"));
    }
    let mut item = item.clone();
    for index in indexes {
        match &item {
            Value::Str(s) => {
                let x = index_arg(index, s.len())?;
                if x >= s.len() {
                    return Err(msg("reflect: string index out of range"));
                }
                item = Value::Uint8(s[x]);
            }
            Value::Map(m) => {
                let key = match index {
                    Value::Invalid => {
                        return Err(msg("value is nil; should be of type string"));
                    }
                    Value::Str(k) => k,
                    other => {
                        return Err(fmt_err(
                            "value has type %s; should be string",
                            &[Value::str(other.type_name())],
                        ));
                    }
                };
                item = Value::Str(m.get(key).cloned().unwrap_or_default());
            }
            other => {
                return Err(fmt_err(
                    "can't index item of type %s",
                    &[Value::str(other.type_name())],
                ));
            }
        }
    }
    Ok(item)
}

fn slice(item: &Value, indexes: &[Value]) -> FResult {
    if !item.is_valid() {
        return Err(msg("slice of untyped nil"));
    }
    if indexes.len() > 3 {
        return Err(fmt_err(
            "too many slice indexes: %d",
            &[Value::Int(indexes.len() as i64)],
        ));
    }
    let Value::Str(s) = item else {
        return Err(fmt_err(
            "can't slice item of type %s",
            &[Value::str(item.type_name())],
        ));
    };
    if indexes.len() == 3 {
        return Err(msg("cannot 3-index slice a string"));
    }
    let cap = s.len();
    let mut idx = [0usize, s.len(), 0];
    for (i, index) in indexes.iter().enumerate() {
        idx[i] = index_arg(index, cap)?;
    }
    if idx[0] > idx[1] {
        return Err(fmt_err(
            "invalid slice index: %d > %d",
            &[Value::Int(idx[0] as i64), Value::Int(idx[1] as i64)],
        ));
    }
    Ok(Value::Str(s[idx[0]..idx[1]].to_vec()))
}

fn length(item: &Value) -> FResult {
    match item {
        Value::Str(s) => Ok(Value::Int(s.len() as i64)),
        Value::Map(m) => Ok(Value::Int(m.len() as i64)),
        Value::Invalid => Err(msg("reflect: call of reflect.Value.Type on zero Value")),
        other => Err(fmt_err("len of type %s", &[Value::str(other.type_name())])),
    }
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Invalid,
    Bool,
    Complex,
    Int,
    Float,
    Str,
    Uint,
}

fn basic_kind(v: &Value) -> Kind {
    match v {
        Value::Bool(_) => Kind::Bool,
        Value::Int(_) => Kind::Int,
        Value::Uint8(_) => Kind::Uint,
        Value::Float(_) => Kind::Float,
        Value::Complex(..) => Kind::Complex,
        Value::Str(_) => Kind::Str,
        _ => Kind::Invalid,
    }
}

fn as_i64(v: &Value) -> i64 {
    match v {
        Value::Int(i) => *i,
        _ => 0,
    }
}

fn as_u64(v: &Value) -> u64 {
    match v {
        Value::Uint8(u) => u64::from(*u),
        _ => 0,
    }
}

fn as_f64(v: &Value) -> f64 {
    match v {
        Value::Float(f) => *f,
        _ => 0.0,
    }
}

/// Go's `reflect.Value.Kind()` family for `canCompare`.
fn reflect_kind(v: &Value) -> u8 {
    match v {
        Value::Invalid => 0,
        Value::Bool(_) => 1,
        Value::Int(_) => 2,
        Value::Uint8(_) => 3,
        Value::Float(_) => 4,
        Value::Complex(..) => 5,
        Value::Str(_) => 6,
        Value::Map(_) => 7,
        Value::Data(_) => 8,
        Value::Err(_) => 9,
    }
}

fn eq(arg1: &Value, rest: &[Value]) -> Result<bool, Bytes> {
    if rest.is_empty() {
        return Err(msg("missing argument for comparison"));
    }
    let k1 = basic_kind(arg1);
    for arg in rest {
        let k2 = basic_kind(arg);
        let mut truth = false;
        if k1 == k2 {
            match k1 {
                Kind::Bool => {
                    truth = matches!((arg1, arg), (Value::Bool(a), Value::Bool(b)) if a == b);
                }
                Kind::Complex => {
                    truth = matches!((arg1, arg), (Value::Complex(a, b), Value::Complex(c, d)) if a == c && b == d);
                }
                Kind::Float => truth = as_f64(arg1) == as_f64(arg),
                Kind::Int => truth = as_i64(arg1) == as_i64(arg),
                Kind::Str => truth = as_str(arg1) == as_str(arg),
                Kind::Uint => truth = as_u64(arg1) == as_u64(arg),
                Kind::Invalid => {
                    let (r1, r2) = (reflect_kind(arg1), reflect_kind(arg));
                    if !(r1 == r2 || r1 == 0 || r2 == 0) {
                        return Err(fmt_err(
                            "non-comparable types %s: %v, %s: %v",
                            &[
                                arg1.clone(),
                                Value::str(arg1.type_name()),
                                Value::str(arg.type_name()),
                                arg.clone(),
                            ],
                        ));
                    }
                    // isNil is true only for an invalid value (maps are never nil here).
                    let n1 = !arg1.is_valid();
                    let n2 = !arg.is_valid();
                    if n1 || n2 {
                        truth = n1 == n2;
                    } else {
                        // Maps and structs holding maps are not comparable.
                        return Err(fmt_err(
                            "non-comparable type %s: %v",
                            &[arg.clone(), Value::str(arg.type_name())],
                        ));
                    }
                }
            }
        } else {
            match (k1, k2) {
                (Kind::Int, Kind::Uint) => {
                    truth = as_i64(arg1) >= 0 && as_i64(arg1) as u64 == as_u64(arg);
                }
                (Kind::Uint, Kind::Int) => {
                    truth = as_i64(arg) >= 0 && as_u64(arg1) == as_i64(arg) as u64;
                }
                _ => {
                    if arg1.is_valid() && arg.is_valid() {
                        return Err(fmt_err(
                            "incompatible types for comparison: %v and %v",
                            &[Value::str(arg1.type_name()), Value::str(arg.type_name())],
                        ));
                    }
                }
            }
        }
        if truth {
            return Ok(true);
        }
    }
    Ok(false)
}

fn lt(arg1: &Value, arg2: &Value) -> Result<bool, Bytes> {
    let k1 = basic_kind(arg1);
    if k1 == Kind::Invalid {
        return Err(msg("invalid type for comparison"));
    }
    let k2 = basic_kind(arg2);
    if k2 == Kind::Invalid {
        return Err(msg("invalid type for comparison"));
    }
    if k1 != k2 {
        return match (k1, k2) {
            (Kind::Int, Kind::Uint) => Ok(as_i64(arg1) < 0 || (as_i64(arg1) as u64) < as_u64(arg2)),
            (Kind::Uint, Kind::Int) => Ok(as_i64(arg2) >= 0 && as_u64(arg1) < as_i64(arg2) as u64),
            _ => Err(fmt_err(
                "incompatible types for comparison: %v and %v",
                &[Value::str(arg1.type_name()), Value::str(arg2.type_name())],
            )),
        };
    }
    match k1 {
        Kind::Bool | Kind::Complex => Err(msg("invalid type for comparison")),
        Kind::Float => Ok(as_f64(arg1) < as_f64(arg2)),
        Kind::Int => Ok(as_i64(arg1) < as_i64(arg2)),
        Kind::Str => Ok(as_str(arg1) < as_str(arg2)),
        Kind::Uint => Ok(as_u64(arg1) < as_u64(arg2)),
        Kind::Invalid => Err(msg("invalid type for comparison")),
    }
}

fn le(arg1: &Value, arg2: &Value) -> Result<bool, Bytes> {
    let less = lt(arg1, arg2)?;
    if less {
        return Ok(true);
    }
    eq(arg1, std::slice::from_ref(arg2))
}

// ---------------------------------------------------------------------------
// encoding/json for `tojson`
// ---------------------------------------------------------------------------

fn json_string(out: &mut Bytes, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b < 0x80 {
            match b {
                b'\\' | b'"' => {
                    out.push(b'\\');
                    out.push(b);
                }
                0x08 => out.extend_from_slice(b"\\b"),
                0x0C => out.extend_from_slice(b"\\f"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'<' | b'>' | b'&' | 0..=0x1F => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[(b >> 4) as usize]);
                    out.push(HEX[(b & 0xF) as usize]);
                }
                _ => out.push(b),
            }
            i += 1;
            continue;
        }
        let (r, size) = decode_rune(&s[i..]);
        if r == 0xFFFD && size == 1 {
            out.extend_from_slice(b"\\ufffd");
        } else if r == 0x2028 || r == 0x2029 {
            out.extend_from_slice(if r == 0x2028 { b"\\u2028" } else { b"\\u2029" });
        } else {
            out.extend_from_slice(&s[i..i + size]);
        }
        i += size;
    }
    out.push(b'"');
}

fn json_float(out: &mut Bytes, f: f64) -> Result<(), ()> {
    if f.is_infinite() || f.is_nan() {
        return Err(());
    }
    let abs = f.abs();
    let mut fmt = b'f';
    if abs != 0.0 && (abs < 1e-6 || abs >= 1e21) {
        fmt = b'e';
    }
    let mut b = format_float(f, fmt, -1);
    if fmt == b'e' {
        let n = b.len();
        if n >= 4 && b[n - 4] == b'e' && b[n - 3] == b'-' && b[n - 2] == b'0' {
            b[n - 2] = b[n - 1];
            b.truncate(n - 1);
        }
    }
    out.extend_from_slice(&b);
    Ok(())
}

fn json_map(out: &mut Bytes, m: &super::value::StrMap) {
    out.push(b'{');
    for (i, (k, v)) in m.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json_string(out, k);
        out.push(b':');
        json_string(out, v);
    }
    out.push(b'}');
}

fn json_value(out: &mut Bytes, v: &Value) -> Result<(), ()> {
    match v {
        Value::Invalid => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Value::Uint8(u) => out.extend_from_slice(u.to_string().as_bytes()),
        Value::Float(f) => json_float(out, *f)?,
        Value::Str(s) => json_string(out, s),
        Value::Map(m) => json_map(out, m),
        Value::Data(d) => {
            out.extend_from_slice(b"{\"Name\":");
            json_string(out, &d.name);
            out.extend_from_slice(b",\"Refs\":");
            json_map(out, &d.refs);
            out.extend_from_slice(b",\"Values\":");
            json_map(out, &d.values);
            out.push(b'}');
        }
        Value::Complex(..) | Value::Err(_) => return Err(()),
    }
    Ok(())
}

/// `json.Marshal` of a template value; `Err` is any marshal failure.
pub fn to_json(v: &Value) -> Result<Bytes, ()> {
    let mut out = Bytes::new();
    json_value(&mut out, v)?;
    Ok(out)
}
