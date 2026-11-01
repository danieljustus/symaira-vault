//! A Go `text/template`-compatible interpreter for the data shape the CLI and
//! MCP expose (`RenderData{Name, Refs, Values}`) and the repo's function map
//! (`b64enc b64url upper lower tojson`) plus Go's builtins.
//!
//! The lexer, parser and executor are ports of Go 1.26's `text/template`
//! (`parse/lex.go`, `parse/parse.go`, `parse/node.go`, `exec.go`, `funcs.go`),
//! with `fmt`, `strconv` and the escapers reimplemented for the value model in
//! `value.rs`. Output and error texts are byte-identical to Go's; the
//! differential corpus in `testdata/port/template/gotemplate-corpus.json`
//! pins that against the real Go implementation.

mod exec;
mod funcs;
mod gofmt;
pub mod gostr;
mod lex;
mod node;
mod parse;
mod strconv;
mod unicode_tables;
mod value;

pub use gostr::Bytes;
pub use value::StrMap;

use std::rc::Rc;

/// Thread-safe `RenderData`.
#[derive(Clone, Debug, Default)]
pub struct PlainData {
    pub name: Bytes,
    pub refs: StrMap,
    pub values: StrMap,
}

/// Go's `exec` recurses once per nested `{{template}}` call, up to 100000
/// deep; give the interpreter a stack that carries that, as Go's growable
/// goroutine stack does.
const STACK_BYTES: usize = 1 << 30;

fn render_inner(name: &[u8], src: &[u8], data: PlainData) -> Result<Bytes, Bytes> {
    let parsed = parse::parse(name, src, &|n| funcs::Func::find(n).is_some()).map_err(|e| {
        gofmt::errorf(
            b"parse template %q: %w",
            &[value::Value::Str(name.to_vec()), value::Value::Err(e)],
        )
    })?;
    let tmpl = exec::Template {
        parse_name: parsed.parse_name,
        text: parsed.text,
        trees: parsed.trees,
    };
    let data = value::RenderData {
        name: data.name,
        refs: Rc::new(data.refs),
        values: Rc::new(data.values),
    };
    exec::execute(&tmpl, name, data).map_err(|e| {
        gofmt::errorf(
            b"execute template %q: %w",
            &[value::Value::Str(name.to_vec()), value::Value::Err(e)],
        )
    })
}

/// `template.New(name).Funcs(DefaultFuncMap()).Parse(src)` followed by
/// `Execute(RenderData)`, with `Engine.Render`'s error wrapping
/// (`parse template "<name>": ...` / `execute template "<name>": ...`).
pub fn render(name: &[u8], src: &[u8], data: PlainData) -> Result<Bytes, Bytes> {
    let (name_owned, src_owned) = (name.to_vec(), src.to_vec());
    let spawned = std::thread::Builder::new()
        .name("gotemplate".to_owned())
        .stack_size(STACK_BYTES)
        .spawn(move || render_inner(&name_owned, &src_owned, data));
    match spawned {
        Ok(handle) => handle
            .join()
            .unwrap_or_else(|_| Err(b"template engine failed".to_vec())),
        Err(_) => Err(b"template engine could not start".to_vec()),
    }
}

/// Go's `fmt.Sprintf("%v", v)` for a decoded JSON value (the conversion
/// `ResolveRef` applies to non-string fields). `null` is rejected by the
/// caller before this is reached.
pub fn sprint_json_value(v: &serde_json::Value) -> Bytes {
    use serde_json::Value as J;
    match v {
        J::Null => b"<nil>".to_vec(),
        J::Bool(b) => {
            if *b {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            }
        }
        J::Number(n) => {
            // encoding/json decodes every number into float64.
            let f = n.as_f64().unwrap_or(0.0);
            strconv::format_float(f, b'g', -1)
        }
        J::String(s) => s.as_bytes().to_vec(),
        J::Array(items) => {
            let mut out = vec![b'['];
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                out.extend_from_slice(&sprint_json_value(item));
            }
            out.push(b']');
            out
        }
        J::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = b"map[".to_vec();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                out.extend_from_slice(key.as_bytes());
                out.push(b':');
                out.extend_from_slice(&sprint_json_value(&map[*key]));
            }
            out.push(b']');
            out
        }
    }
}
