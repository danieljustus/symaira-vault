//! Port of `text/template/parse/node.go`: the parse tree and its `String()`
//! forms (used verbatim in execution error messages).

use super::gofmt::sprintf;
use super::gostr::Bytes;
use super::strconv;
use super::value::Value;

pub type Pos = usize;

#[derive(Clone, Debug)]
pub struct ListNode {
    pub pos: Pos,
    pub nodes: Vec<Node>,
}

#[derive(Clone, Debug)]
pub struct PipeNode {
    pub pos: Pos,
    pub is_assign: bool,
    pub decl: Vec<VariableNode>,
    pub cmds: Vec<CommandNode>,
}

#[derive(Clone, Debug)]
pub struct CommandNode {
    pub pos: Pos,
    pub args: Vec<Node>,
}

#[derive(Clone, Debug)]
pub struct VariableNode {
    pub pos: Pos,
    pub ident: Vec<Bytes>,
}

#[derive(Clone, Debug)]
pub struct NumberNode {
    pub pos: Pos,
    pub is_int: bool,
    pub is_uint: bool,
    pub is_float: bool,
    pub is_complex: bool,
    pub int64: i64,
    pub uint64: u64,
    pub float64: f64,
    pub complex128: (f64, f64),
    pub text: Bytes,
}

#[derive(Clone, Debug)]
pub struct BranchNode {
    pub pos: Pos,
    pub pipe: PipeNode,
    pub list: ListNode,
    pub else_list: Option<ListNode>,
}

#[derive(Clone, Debug)]
pub struct TemplateNode {
    pub pos: Pos,
    pub name: Bytes,
    pub pipe: Option<PipeNode>,
}

#[derive(Clone, Debug)]
pub enum Node {
    Text {
        pos: Pos,
        text: Bytes,
    },
    Action {
        pos: Pos,
        pipe: PipeNode,
    },
    Break {
        pos: Pos,
    },
    Continue {
        pos: Pos,
    },
    If(Box<BranchNode>),
    Range(Box<BranchNode>),
    With(Box<BranchNode>),
    Template(Box<TemplateNode>),
    Pipe(PipeNode),
    Identifier {
        pos: Pos,
        ident: Bytes,
    },
    Variable(VariableNode),
    Dot {
        pos: Pos,
    },
    Nil {
        pos: Pos,
    },
    Field {
        pos: Pos,
        ident: Vec<Bytes>,
    },
    Chain {
        pos: Pos,
        node: Box<Node>,
        field: Vec<Bytes>,
    },
    Bool {
        pos: Pos,
        value: bool,
    },
    Number(Box<NumberNode>),
    String {
        pos: Pos,
        quoted: Bytes,
        text: Bytes,
    },
    /// `{{end}}`; never part of a finished tree.
    End {
        pos: Pos,
    },
    /// `{{else}}`; never part of a finished tree.
    Else {
        pos: Pos,
    },
}

impl Node {
    pub fn position(&self) -> Pos {
        match self {
            Node::Text { pos, .. }
            | Node::Action { pos, .. }
            | Node::Break { pos }
            | Node::Continue { pos }
            | Node::Identifier { pos, .. }
            | Node::Dot { pos }
            | Node::Nil { pos }
            | Node::Field { pos, .. }
            | Node::Chain { pos, .. }
            | Node::Bool { pos, .. }
            | Node::String { pos, .. }
            | Node::End { pos }
            | Node::Else { pos } => *pos,
            Node::If(b) | Node::Range(b) | Node::With(b) => b.pos,
            Node::Template(t) => t.pos,
            Node::Pipe(p) => p.pos,
            Node::Variable(v) => v.pos,
            Node::Number(n) => n.pos,
        }
    }

    /// `Node.String()`.
    pub fn string(&self) -> Bytes {
        let mut out = Bytes::new();
        self.write_to(&mut out);
        out
    }

    pub fn write_to(&self, sb: &mut Bytes) {
        match self {
            Node::Text { text, .. } => {
                // fmt.Sprintf("%s", []byte)
                sb.extend_from_slice(text);
            }
            Node::Action { pipe, .. } => {
                sb.extend_from_slice(b"{{");
                pipe.write_to(sb);
                sb.extend_from_slice(b"}}");
            }
            Node::Break { .. } => sb.extend_from_slice(b"{{break}}"),
            Node::Continue { .. } => sb.extend_from_slice(b"{{continue}}"),
            Node::If(b) => b.write_to(sb, b"if"),
            Node::Range(b) => b.write_to(sb, b"range"),
            Node::With(b) => b.write_to(sb, b"with"),
            Node::Template(t) => {
                sb.extend_from_slice(b"{{template ");
                sb.extend_from_slice(&strconv::quote(&t.name));
                if let Some(p) = &t.pipe {
                    sb.push(b' ');
                    p.write_to(sb);
                }
                sb.extend_from_slice(b"}}");
            }
            Node::Pipe(p) => p.write_to(sb),
            Node::Identifier { ident, .. } => sb.extend_from_slice(ident),
            Node::Variable(v) => v.write_to(sb),
            Node::Dot { .. } => sb.push(b'.'),
            Node::Nil { .. } => sb.extend_from_slice(b"nil"),
            Node::Field { ident, .. } => {
                for id in ident {
                    sb.push(b'.');
                    sb.extend_from_slice(id);
                }
            }
            Node::Chain { node, field, .. } => {
                if let Node::Pipe(_) = **node {
                    sb.push(b'(');
                    node.write_to(sb);
                    sb.push(b')');
                } else {
                    node.write_to(sb);
                }
                for f in field {
                    sb.push(b'.');
                    sb.extend_from_slice(f);
                }
            }
            Node::Bool { value, .. } => {
                sb.extend_from_slice(if *value { b"true" } else { b"false" });
            }
            Node::Number(n) => sb.extend_from_slice(&n.text),
            Node::String { quoted, .. } => sb.extend_from_slice(quoted),
            Node::End { .. } => sb.extend_from_slice(b"{{end}}"),
            Node::Else { .. } => sb.extend_from_slice(b"{{else}}"),
        }
    }
}

impl ListNode {
    pub fn write_to(&self, sb: &mut Bytes) {
        for n in &self.nodes {
            n.write_to(sb);
        }
    }
}

impl PipeNode {
    pub fn write_to(&self, sb: &mut Bytes) {
        if !self.decl.is_empty() {
            for (i, v) in self.decl.iter().enumerate() {
                if i > 0 {
                    sb.extend_from_slice(b", ");
                }
                v.write_to(sb);
            }
            sb.extend_from_slice(if self.is_assign { b" = " } else { b" := " });
        }
        for (i, c) in self.cmds.iter().enumerate() {
            if i > 0 {
                sb.extend_from_slice(b" | ");
            }
            c.write_to(sb);
        }
    }
}

impl CommandNode {
    pub fn write_to(&self, sb: &mut Bytes) {
        for (i, arg) in self.args.iter().enumerate() {
            if i > 0 {
                sb.push(b' ');
            }
            if let Node::Pipe(p) = arg {
                sb.push(b'(');
                p.write_to(sb);
                sb.push(b')');
                continue;
            }
            arg.write_to(sb);
        }
    }
}

impl VariableNode {
    pub fn write_to(&self, sb: &mut Bytes) {
        for (i, id) in self.ident.iter().enumerate() {
            if i > 0 {
                sb.push(b'.');
            }
            sb.extend_from_slice(id);
        }
    }
}

impl BranchNode {
    fn write_to(&self, sb: &mut Bytes, name: &[u8]) {
        sb.extend_from_slice(b"{{");
        sb.extend_from_slice(name);
        sb.push(b' ');
        self.pipe.write_to(sb);
        sb.extend_from_slice(b"}}");
        self.list.write_to(sb);
        if let Some(e) = &self.else_list {
            sb.extend_from_slice(b"{{else}}");
            e.write_to(sb);
        }
        sb.extend_from_slice(b"{{end}}");
    }
}

// ---------------------------------------------------------------------------
// Number construction (Tree.newNumber)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NumberKind {
    Plain,
    CharConstant,
    Complex,
}

// Go's float->integer conversion of an out-of-range value is architecture
// defined; the pinned oracle runs on arm64 where it saturates (and NaN is 0),
// which is exactly Rust's `as`.
fn f64_to_i64(f: f64) -> i64 {
    f as i64
}

fn f64_to_u64(f: f64) -> u64 {
    f as u64
}

impl NumberNode {
    fn simplify_complex(&mut self) {
        self.is_float = self.complex128.1 == 0.0;
        if self.is_float {
            self.float64 = self.complex128.0;
            self.is_int = (f64_to_i64(self.float64) as f64) == self.float64;
            if self.is_int {
                self.int64 = f64_to_i64(self.float64);
            }
            self.is_uint = (f64_to_u64(self.float64) as f64) == self.float64;
            if self.is_uint {
                self.uint64 = f64_to_u64(self.float64);
            }
        }
    }

    /// `Tree.newNumber`; the error is the plain error text.
    pub fn new(pos: Pos, text: &[u8], kind: NumberKind) -> Result<NumberNode, Bytes> {
        let mut n = NumberNode {
            pos,
            is_int: false,
            is_uint: false,
            is_float: false,
            is_complex: false,
            int64: 0,
            uint64: 0,
            float64: 0.0,
            complex128: (0.0, 0.0),
            text: text.to_vec(),
        };
        match kind {
            NumberKind::CharConstant => {
                let quote = text[0];
                let (r, _, tail) = strconv::unquote_char(&text[1..], quote)
                    .map_err(|()| b"invalid syntax".to_vec())?;
                if tail != b"'" {
                    let mut e = b"malformed character constant: ".to_vec();
                    e.extend_from_slice(text);
                    return Err(e);
                }
                n.int64 = i64::from(r);
                n.is_int = true;
                n.uint64 = u64::from(r);
                n.is_uint = true;
                n.float64 = f64::from(r);
                n.is_float = true;
                return Ok(n);
            }
            NumberKind::Complex => {
                n.complex128 = scan_complex(text)?;
                n.is_complex = true;
                n.simplify_complex();
                return Ok(n);
            }
            NumberKind::Plain => {}
        }
        if text.last() == Some(&b'i')
            && let Ok(f) = strconv::parse_float(&text[..text.len() - 1])
        {
            n.is_complex = true;
            n.complex128 = (0.0, f);
            n.simplify_complex();
            return Ok(n);
        }
        let u = strconv::parse_uint(text);
        if let Ok(u) = u {
            n.is_uint = true;
            n.uint64 = u;
        }
        if let Ok(i) = strconv::parse_int(text) {
            n.is_int = true;
            n.int64 = i;
            if i == 0 {
                n.is_uint = true;
                n.uint64 = u.unwrap_or(0);
            }
        }
        if n.is_int {
            n.is_float = true;
            n.float64 = n.int64 as f64;
        } else if n.is_uint {
            n.is_float = true;
            n.float64 = n.uint64 as f64;
        } else if let Ok(f) = strconv::parse_float(text) {
            if !text.iter().any(|c| b".eEpP".contains(c)) {
                return Err(sprintf(
                    b"integer overflow: %q",
                    &[Value::Str(text.to_vec())],
                ));
            }
            n.is_float = true;
            n.float64 = f;
            if !n.is_int && (f64_to_i64(f) as f64) == f {
                n.is_int = true;
                n.int64 = f64_to_i64(f);
            }
            if !n.is_uint && (f64_to_u64(f) as f64) == f {
                n.is_uint = true;
                n.uint64 = f64_to_u64(f);
            }
        }
        if !n.is_int && !n.is_uint && !n.is_float {
            return Err(sprintf(
                b"illegal number syntax: %q",
                &[Value::Str(text.to_vec())],
            ));
        }
        Ok(n)
    }
}

struct ScanState<'a> {
    s: &'a [u8],
    i: usize,
    buf: Bytes,
}

impl ScanState<'_> {
    fn accept(&mut self, set: &[u8]) -> bool {
        if let Some(&c) = self.s.get(self.i)
            && set.contains(&c)
        {
            self.buf.push(c);
            self.i += 1;
            return true;
        }
        false
    }

    fn float_token(&mut self) -> Bytes {
        self.buf.clear();
        if self.accept(b"nN") && self.accept(b"aA") && self.accept(b"nN") {
            return self.buf.clone();
        }
        self.accept(b"+-");
        if self.accept(b"iI") && self.accept(b"nN") && self.accept(b"fF") {
            return self.buf.clone();
        }
        let mut digits: &[u8] = b"0123456789_";
        let mut exp: &[u8] = b"eEpP";
        if self.accept(b"0") && self.accept(b"xX") {
            digits = b"0123456789aAbBcCdDeEfF_";
            exp = b"pP";
        }
        while self.accept(digits) {}
        if self.accept(b".") {
            while self.accept(digits) {}
        }
        if self.accept(exp) {
            self.accept(b"+-");
            while self.accept(b"0123456789_") {}
        }
        self.buf.clone()
    }
}

fn convert_float(token: &[u8]) -> Result<f64, Bytes> {
    strconv::parse_float(token).map_err(|e| {
        let reason: &[u8] = if e == strconv::NumErr::Range {
            b"value out of range"
        } else {
            b"invalid syntax"
        };
        let mut msg = sprintf(
            b"strconv.ParseFloat: parsing %q: ",
            &[Value::Str(token.to_vec())],
        );
        msg.extend_from_slice(reason);
        msg
    })
}

/// `fmt.Sscan(text, &complex128)` (`ss.complexTokens` + `convertFloat`).
fn scan_complex(text: &[u8]) -> Result<(f64, f64), Bytes> {
    const ERR_COMPLEX: &[u8] = b"syntax error scanning complex number";
    let mut st = ScanState {
        s: text,
        i: 0,
        buf: Vec::new(),
    };
    let parens = st.accept(b"(");
    let real = st.float_token();
    st.buf.clear();
    if !st.accept(b"+-") {
        return Err(ERR_COMPLEX.to_vec());
    }
    let mut imag = st.buf.clone();
    imag.extend_from_slice(&st.float_token());
    if !st.accept(b"i") {
        return Err(ERR_COMPLEX.to_vec());
    }
    if parens && !st.accept(b")") {
        return Err(ERR_COMPLEX.to_vec());
    }
    let re = convert_float(&real)?;
    let im = convert_float(&imag)?;
    Ok((re, im))
}
