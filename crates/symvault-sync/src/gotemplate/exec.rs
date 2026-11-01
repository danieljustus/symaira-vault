//! Port of `text/template/exec.go` (Go 1.26) over the reflect-free value
//! model. Control flow that Go implements with panics (`break`, `continue`,
//! exec errors) is carried by `Flow`.

use super::funcs::{self, Func, PType, is_true};
use super::gofmt::{errorf, sprint, sprintf};
use super::gostr::{Bytes, last_index_of};
use super::node::{BranchNode, CommandNode, ListNode, Node, NumberNode, PipeNode, VariableNode};
use super::value::{RenderData, Value};
use std::collections::HashMap;

const MAX_EXEC_DEPTH: usize = 100_000;

/// A parsed template set, ready to execute.
pub struct Template {
    pub parse_name: Bytes,
    pub text: Bytes,
    pub trees: HashMap<Bytes, ListNode>,
}

pub enum Flow {
    Err(Bytes),
    Break,
    Continue,
}

type R<T> = Result<T, Flow>;

#[derive(Clone, Copy)]
enum NodeRef<'a> {
    Node(&'a Node),
    Pipe(&'a PipeNode),
    Command(&'a CommandNode),
    Var(&'a VariableNode),
    List(&'a ListNode),
}

impl NodeRef<'_> {
    fn position(&self) -> usize {
        match self {
            NodeRef::Node(n) => n.position(),
            NodeRef::Pipe(p) => p.pos,
            NodeRef::Command(c) => c.pos,
            NodeRef::Var(v) => v.pos,
            NodeRef::List(l) => l.pos,
        }
    }

    fn string(&self) -> Bytes {
        let mut out = Bytes::new();
        match self {
            NodeRef::Node(n) => n.write_to(&mut out),
            NodeRef::Pipe(p) => p.write_to(&mut out),
            NodeRef::Command(c) => c.write_to(&mut out),
            NodeRef::Var(v) => v.write_to(&mut out),
            NodeRef::List(l) => l.write_to(&mut out),
        }
        out
    }
}

fn double_percent(s: &[u8]) -> Bytes {
    let mut out = Bytes::with_capacity(s.len());
    for &c in s {
        out.push(c);
        if c == b'%' {
            out.push(b'%');
        }
    }
    out
}

struct State<'a> {
    tmpl: &'a Template,
    name: Bytes,
    wr: Bytes,
    node: Option<NodeRef<'a>>,
    vars: Vec<(Bytes, Value)>,
    depth: usize,
}

/// `Template.Execute` on the template named `name` with `data` as dot.
pub fn execute(tmpl: &Template, name: &[u8], data: RenderData) -> Result<Bytes, Bytes> {
    let value = Value::Data(std::rc::Rc::new(data));
    let mut state = State {
        tmpl,
        name: name.to_vec(),
        wr: Bytes::new(),
        node: None,
        vars: vec![(b"$".to_vec(), value.clone())],
        depth: 0,
    };
    let Some(root) = tmpl.trees.get(name) else {
        return Err(sprintf(
            b"template: %s: %q is an incomplete or empty template",
            &[Value::Str(double_percent(name)), Value::Str(name.to_vec())],
        ));
    };
    match state.walk_list(&value, root) {
        Ok(()) => Ok(state.wr),
        Err(Flow::Err(e)) => Err(e),
        // break/continue outside range cannot be parsed.
        Err(_) => Err(b"unexpected break or continue".to_vec()),
    }
}

fn arg_str(s: &[u8]) -> Value {
    Value::Str(s.to_vec())
}

impl<'a> State<'a> {
    // ---- variables ------------------------------------------------------

    fn push(&mut self, name: &[u8], value: Value) {
        self.vars.push((name.to_vec(), value));
    }

    fn mark(&self) -> usize {
        self.vars.len()
    }

    fn pop(&mut self, mark: usize) {
        self.vars.truncate(mark);
    }

    fn set_var(&mut self, name: &[u8], value: Value) -> R<()> {
        for i in (0..self.vars.len()).rev() {
            if self.vars[i].0 == name {
                self.vars[i].1 = value;
                return Ok(());
            }
        }
        Err(self.errorf(b"undefined variable: %s", &[arg_str(name)]))
    }

    fn set_top_var(&mut self, n: usize, value: Value) {
        let len = self.vars.len();
        self.vars[len - n].1 = value;
    }

    fn var_value(&self, name: &[u8]) -> R<Value> {
        for i in (0..self.vars.len()).rev() {
            if self.vars[i].0 == name {
                return Ok(self.vars[i].1.clone());
            }
        }
        Err(self.errorf(b"undefined variable: %s", &[arg_str(name)]))
    }

    // ---- errors ---------------------------------------------------------

    fn at(&mut self, node: NodeRef<'a>) {
        self.node = Some(node);
    }

    fn error_context(&self, n: NodeRef<'a>) -> (Bytes, Bytes) {
        let pos = n.position().min(self.tmpl.text.len());
        let text = &self.tmpl.text[..pos];
        let byte_num = match last_index_of(text, b"\n") {
            None => pos,
            Some(i) => pos - (i + 1),
        };
        let line_num = 1 + text.iter().filter(|&&c| c == b'\n').count();
        let location = sprintf(
            b"%s:%d:%d",
            &[
                Value::Str(self.tmpl.parse_name.clone()),
                Value::Int(line_num as i64),
                Value::Int(byte_num as i64),
            ],
        );
        (location, n.string())
    }

    fn errorf(&self, format: &[u8], args: &[Value]) -> Flow {
        let name = double_percent(&self.name);
        let full = match self.node {
            None => sprintf(
                b"template: %s: %s",
                &[Value::Str(name), Value::Str(format.to_vec())],
            ),
            Some(n) => {
                let (location, context) = self.error_context(n);
                sprintf(
                    b"template: %s: executing %q at <%s>: %s",
                    &[
                        Value::Str(location),
                        Value::Str(name),
                        Value::Str(double_percent(&context)),
                        Value::Str(format.to_vec()),
                    ],
                )
            }
        };
        Flow::Err(errorf(&full, args))
    }

    // ---- walking ----------------------------------------------------------

    fn walk_list(&mut self, dot: &Value, list: &'a ListNode) -> R<()> {
        self.at(NodeRef::List(list));
        for n in &list.nodes {
            self.walk(dot, n)?;
        }
        Ok(())
    }

    fn walk(&mut self, dot: &Value, node: &'a Node) -> R<()> {
        self.at(NodeRef::Node(node));
        match node {
            Node::Action { pipe, .. } => {
                let val = self.eval_pipeline(dot, Some(pipe))?;
                if pipe.decl.is_empty() {
                    self.print_value(node, &val);
                }
                Ok(())
            }
            Node::Break { .. } => Err(Flow::Break),
            Node::Continue { .. } => Err(Flow::Continue),
            Node::If(b) => self.walk_if_or_with(false, dot, b),
            Node::With(b) => self.walk_if_or_with(true, dot, b),
            Node::Range(b) => self.walk_range(dot, node, b),
            Node::Template(t) => self.walk_template(dot, node, t),
            Node::Text { text, .. } => {
                self.wr.extend_from_slice(text);
                Ok(())
            }
            other => Err(self.errorf(b"unknown node: %s", &[Value::Str(other.string())])),
        }
    }

    fn walk_if_or_with(&mut self, is_with: bool, dot: &Value, b: &'a BranchNode) -> R<()> {
        let mark = self.mark();
        let r = self.walk_if_or_with_inner(is_with, dot, b);
        self.pop(mark);
        r
    }

    fn walk_if_or_with_inner(&mut self, is_with: bool, dot: &Value, b: &'a BranchNode) -> R<()> {
        let val = self.eval_pipeline(dot, Some(&b.pipe))?;
        if is_true(&val) {
            if is_with {
                self.walk_list(&val, &b.list)
            } else {
                self.walk_list(dot, &b.list)
            }
        } else if let Some(else_list) = &b.else_list {
            self.walk_list(dot, else_list)
        } else {
            Ok(())
        }
    }

    fn walk_range(&mut self, dot: &Value, node: &'a Node, b: &'a BranchNode) -> R<()> {
        self.at(NodeRef::Node(node));
        let mark = self.mark();
        let r = self.walk_range_inner(dot, b);
        self.pop(mark);
        match r {
            Err(Flow::Break) => Ok(()),
            other => other,
        }
    }

    fn one_iteration(
        &mut self,
        b: &'a BranchNode,
        mark: usize,
        index: Value,
        elem: Value,
    ) -> R<()> {
        let pipe = &b.pipe;
        if !pipe.decl.is_empty() {
            if pipe.is_assign {
                if pipe.decl.len() > 1 {
                    self.set_var(&pipe.decl[0].ident[0], index.clone())?;
                } else {
                    self.set_var(&pipe.decl[0].ident[0], elem.clone())?;
                }
            } else {
                self.set_top_var(1, elem.clone());
            }
        }
        if pipe.decl.len() > 1 {
            if pipe.is_assign {
                self.set_var(&pipe.decl[1].ident[0], elem.clone())?;
            } else {
                self.set_top_var(2, index);
            }
        }
        let r = self.walk_list(&elem, &b.list);
        self.pop(mark);
        match r {
            Err(Flow::Continue) => Ok(()),
            other => other,
        }
    }

    fn walk_range_inner(&mut self, dot: &Value, b: &'a BranchNode) -> R<()> {
        let val = self.eval_pipeline(dot, Some(&b.pipe))?;
        let mark = self.mark();
        let ndecl = b.pipe.decl.len();
        match &val {
            Value::Int(_) | Value::Uint8(_) => {
                if ndecl > 1 {
                    return Err(self.errorf(
                        b"can't use %v to iterate over more than one variable",
                        std::slice::from_ref(&val),
                    ));
                }
                let count: i64 = match &val {
                    Value::Int(n) => *n,
                    Value::Uint8(n) => i64::from(*n),
                    _ => 0,
                };
                if count > 0 {
                    for i in 0..count {
                        let elem = match &val {
                            Value::Uint8(_) => Value::Uint8(i as u8),
                            _ => Value::Int(i),
                        };
                        self.one_iteration(b, mark, Value::Invalid, elem)?;
                    }
                    return Ok(());
                }
            }
            Value::Map(m) => {
                if !m.is_empty() {
                    let m = m.clone();
                    for (k, v) in m.iter() {
                        self.one_iteration(b, mark, Value::Str(k.clone()), Value::Str(v.clone()))?;
                    }
                    return Ok(());
                }
            }
            Value::Invalid => {}
            _ => {
                return Err(self.errorf(b"range can't iterate over %v", std::slice::from_ref(&val)));
            }
        }
        if let Some(else_list) = &b.else_list {
            self.walk_list(dot, else_list)?;
        }
        Ok(())
    }

    fn walk_template(
        &mut self,
        dot: &Value,
        node: &'a Node,
        t: &'a super::node::TemplateNode,
    ) -> R<()> {
        self.at(NodeRef::Node(node));
        let Some(root) = self.tmpl.trees.get(&t.name) else {
            return Err(self.errorf(b"template %q not defined", &[arg_str(&t.name)]));
        };
        if self.depth == MAX_EXEC_DEPTH {
            return Err(self.errorf(
                b"exceeded maximum template depth (%v)",
                &[Value::Int(MAX_EXEC_DEPTH as i64)],
            ));
        }
        let dot = self.eval_pipeline(dot, t.pipe.as_ref())?;
        let saved_vars = std::mem::replace(&mut self.vars, vec![(b"$".to_vec(), dot.clone())]);
        let saved_name = std::mem::replace(&mut self.name, t.name.clone());
        let saved_node = self.node;
        self.depth += 1;
        let r = self.walk_list(&dot, root);
        self.depth -= 1;
        self.name = saved_name;
        self.vars = saved_vars;
        self.node = saved_node;
        r
    }

    // ---- evaluation -------------------------------------------------------

    fn eval_pipeline(&mut self, dot: &Value, pipe: Option<&'a PipeNode>) -> R<Value> {
        let Some(pipe) = pipe else {
            return Ok(Value::Invalid);
        };
        self.at(NodeRef::Pipe(pipe));
        let mut value: Option<Value> = None;
        for cmd in &pipe.cmds {
            value = Some(self.eval_command(dot, cmd, value.take())?);
        }
        // A pipeline always has at least one command.
        let value = value.unwrap_or(Value::Invalid);
        for variable in &pipe.decl {
            if pipe.is_assign {
                self.set_var(&variable.ident[0], value.clone())?;
            } else {
                self.push(&variable.ident[0], value.clone());
            }
        }
        Ok(value)
    }

    fn not_a_function(&self, args: &[Node], final_: &Option<Value>) -> R<()> {
        if args.len() > 1 || final_.is_some() {
            let first = args.first().map(Node::string).unwrap_or_default();
            return Err(self.errorf(
                b"can't give argument to non-function %s",
                &[Value::Str(first)],
            ));
        }
        Ok(())
    }

    fn eval_command(
        &mut self,
        dot: &Value,
        cmd: &'a CommandNode,
        final_: Option<Value>,
    ) -> R<Value> {
        let first = &cmd.args[0];
        match first {
            Node::Field { .. } => return self.eval_field_node(dot, first, &cmd.args, final_),
            Node::Chain { .. } => return self.eval_chain_node(dot, first, &cmd.args, final_),
            Node::Identifier { .. } => {
                return self.eval_function(dot, first, NodeRef::Command(cmd), &cmd.args, final_);
            }
            Node::Pipe(p) => {
                self.not_a_function(&cmd.args, &final_)?;
                return self.eval_pipeline(dot, Some(p));
            }
            Node::Variable(v) => return self.eval_variable_node(dot, v, &cmd.args, final_),
            _ => {}
        }
        self.at(NodeRef::Node(first));
        self.not_a_function(&cmd.args, &final_)?;
        match first {
            Node::Bool { value, .. } => Ok(Value::Bool(*value)),
            Node::Dot { .. } => Ok(dot.clone()),
            Node::Nil { .. } => Err(self.errorf(b"nil is not a command", &[])),
            Node::Number(n) => self.ideal_constant(first, n),
            Node::String { text, .. } => Ok(Value::Str(text.clone())),
            other => Err(self.errorf(b"can't evaluate command %q", &[Value::Str(other.string())])),
        }
    }

    fn ideal_constant(&mut self, node: &'a Node, constant: &NumberNode) -> R<Value> {
        self.at(NodeRef::Node(node));
        let text = &constant.text;
        if constant.is_complex {
            return Ok(Value::Complex(constant.complex128.0, constant.complex128.1));
        }
        let is_rune_int = !text.is_empty() && text[0] == b'\'';
        let is_hex_int = text.len() > 2
            && text[0] == b'0'
            && (text[1] == b'x' || text[1] == b'X')
            && !text.iter().any(|c| *c == b'p' || *c == b'P');
        if constant.is_float
            && !is_hex_int
            && !is_rune_int
            && text.iter().any(|c| b".eEpP".contains(c))
        {
            return Ok(Value::Float(constant.float64));
        }
        if constant.is_int {
            return Ok(Value::Int(constant.int64));
        }
        if constant.is_uint {
            return Err(self.errorf(b"%s overflows int", &[arg_str(text)]));
        }
        Ok(Value::Invalid)
    }

    fn eval_field_node(
        &mut self,
        dot: &Value,
        field: &'a Node,
        args: &'a [Node],
        final_: Option<Value>,
    ) -> R<Value> {
        self.at(NodeRef::Node(field));
        let Node::Field { ident, .. } = field else {
            return Ok(Value::Invalid);
        };
        self.eval_field_chain(dot, dot.clone(), ident, args.len(), final_)
    }

    fn eval_chain_node(
        &mut self,
        dot: &Value,
        chain: &'a Node,
        args: &'a [Node],
        final_: Option<Value>,
    ) -> R<Value> {
        self.at(NodeRef::Node(chain));
        let Node::Chain { node, field, .. } = chain else {
            return Ok(Value::Invalid);
        };
        if field.is_empty() {
            return Err(self.errorf(b"internal error: no fields in evalChainNode", &[]));
        }
        if matches!(**node, Node::Nil { .. }) {
            return Err(self.errorf(
                b"indirection through explicit nil in %s",
                &[Value::Str(chain.string())],
            ));
        }
        let pipe = self.eval_arg(dot, None, node)?;
        self.eval_field_chain(dot, pipe, field, args.len(), final_)
    }

    fn eval_variable_node(
        &mut self,
        dot: &Value,
        variable: &'a VariableNode,
        args: &'a [Node],
        final_: Option<Value>,
    ) -> R<Value> {
        self.at(NodeRef::Var(variable));
        let value = self.var_value(&variable.ident[0])?;
        if variable.ident.len() == 1 {
            self.not_a_function(args, &final_)?;
            return Ok(value);
        }
        self.eval_field_chain(dot, value, &variable.ident[1..], args.len(), final_)
    }

    /// `args_len` mirrors `len(args)` of the Go slice (`0` for a nil slice).
    fn eval_field_chain(
        &mut self,
        _dot: &Value,
        receiver: Value,
        ident: &[Bytes],
        args_len: usize,
        final_: Option<Value>,
    ) -> R<Value> {
        let n = ident.len();
        let mut receiver = receiver;
        for name in &ident[..n - 1] {
            receiver = self.eval_field(name, false, receiver)?;
        }
        let has_args = args_len > 1 || final_.is_some();
        self.eval_field(&ident[n - 1], has_args, receiver)
    }

    fn eval_function(
        &mut self,
        dot: &Value,
        node: &'a Node,
        cmd: NodeRef<'a>,
        args: &'a [Node],
        final_: Option<Value>,
    ) -> R<Value> {
        self.at(NodeRef::Node(node));
        let Node::Identifier { ident, .. } = node else {
            return Ok(Value::Invalid);
        };
        let Some((f, is_builtin)) = Func::find(ident) else {
            return Err(self.errorf(b"%q is not a defined function", &[arg_str(ident)]));
        };
        self.eval_call(dot, f, is_builtin, cmd, ident, args, final_)
    }

    fn eval_field(&mut self, field_name: &[u8], has_args: bool, receiver: Value) -> R<Value> {
        if !receiver.is_valid() {
            return Ok(Value::Invalid);
        }
        match &receiver {
            Value::Data(d) => {
                let field = match field_name {
                    b"Name" => Some(Value::Str(d.name.clone())),
                    b"Refs" => Some(Value::Map(d.refs.clone())),
                    b"Values" => Some(Value::Map(d.values.clone())),
                    _ => None,
                };
                if let Some(field) = field {
                    if has_args {
                        return Err(self.errorf(
                            b"%s has arguments but cannot be invoked as function",
                            &[arg_str(field_name)],
                        ));
                    }
                    return Ok(field);
                }
            }
            Value::Map(m) => {
                if has_args {
                    return Err(self.errorf(
                        b"%s is not a method but has arguments",
                        &[arg_str(field_name)],
                    ));
                }
                return Ok(m
                    .get(field_name)
                    .map_or(Value::Invalid, |v| Value::Str(v.clone())));
            }
            _ => {}
        }
        Err(self.errorf(
            b"can't evaluate field %s in type %s",
            &[arg_str(field_name), Value::str(receiver.type_name())],
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_call(
        &mut self,
        dot: &Value,
        f: Func,
        is_builtin: bool,
        node: NodeRef<'a>,
        name: &[u8],
        args: &'a [Node],
        final_: Option<Value>,
    ) -> R<Value> {
        let args: &'a [Node] = if args.is_empty() { args } else { &args[1..] };
        let sig = f.sig();
        let typ_num_in = sig.params.len();
        let mut num_in = args.len();
        if final_.is_some() {
            num_in += 1;
        }
        let mut num_fixed = args.len();
        if sig.variadic {
            num_fixed = typ_num_in - 1;
            if num_in < num_fixed {
                return Err(self.errorf(
                    b"wrong number of args for %s: want at least %d got %d",
                    &[
                        arg_str(name),
                        Value::Int(typ_num_in as i64 - 1),
                        Value::Int(args.len() as i64),
                    ],
                ));
            }
        } else if num_in != typ_num_in {
            return Err(self.errorf(
                b"wrong number of args for %s: want %d got %d",
                &[
                    arg_str(name),
                    Value::Int(typ_num_in as i64),
                    Value::Int(num_in as i64),
                ],
            ));
        }

        if is_builtin && (f == Func::And || f == Func::Or) {
            let mut v = Value::Invalid;
            for arg in args {
                v = self.eval_arg(dot, Some(PType::Rv), arg)?;
                if is_true(&v) == (f == Func::Or) {
                    return Ok(v);
                }
            }
            if let Some(fin) = final_ {
                v = self.validate_type(fin, Some(PType::Rv))?;
            }
            return Ok(v);
        }

        let mut argv: Vec<Value> = Vec::with_capacity(num_in);
        let mut i = 0;
        while i < num_fixed && i < args.len() {
            let v = self.eval_arg(dot, Some(sig.params[i]), &args[i])?;
            argv.push(v);
            i += 1;
        }
        if sig.variadic {
            let arg_type = sig.params[typ_num_in - 1];
            while i < args.len() {
                let v = self.eval_arg(dot, Some(arg_type), &args[i])?;
                argv.push(v);
                i += 1;
            }
        }
        let callee_name = if is_builtin && f == Func::Call {
            Some(match (args.first(), &final_) {
                (Some(a), _) => a.string(),
                (None, Some(Value::Str(s))) => s.clone(),
                (None, Some(Value::Invalid)) => b"<invalid Value>".to_vec(),
                (None, Some(other)) => format!("<{} Value>", other.type_name()).into_bytes(),
                (None, None) => Vec::new(),
            })
        } else {
            None
        };
        if let Some(fin) = final_ {
            let mut t = sig.params[typ_num_in - 1];
            if sig.variadic && num_in - 1 < num_fixed {
                t = sig.params[num_in - 1];
            }
            let v = self.validate_type(fin, Some(t))?;
            argv.push(v);
        }

        let result = match callee_name {
            Some(callee) => funcs::call_builtin_call(&callee, &argv),
            None => funcs::call(f, &argv),
        };
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                self.at(node);
                Err(self.errorf(b"error calling %s: %w", &[arg_str(name), Value::Err(e)]))
            }
        }
    }

    fn validate_type(&self, value: Value, typ: Option<PType>) -> R<Value> {
        if !value.is_valid() {
            return match typ {
                None => Ok(Value::Invalid),
                Some(t) if t.can_be_nil() => Ok(Value::Invalid),
                Some(t) => Err(self.errorf(b"invalid value; expected %s", &[Value::str(t.name())])),
            };
        }
        if typ == Some(PType::Str) && !matches!(value, Value::Str(_)) {
            return Err(self.errorf(
                b"wrong type for value; expected %s; got %s",
                &[Value::str("string"), Value::str(value.type_name())],
            ));
        }
        Ok(value)
    }

    fn eval_arg(&mut self, dot: &Value, typ: Option<PType>, n: &'a Node) -> R<Value> {
        self.at(NodeRef::Node(n));
        match n {
            Node::Dot { .. } => return self.validate_type(dot.clone(), typ),
            Node::Nil { .. } => {
                return match typ {
                    Some(t) if !t.can_be_nil() => {
                        Err(self.errorf(b"cannot assign nil to %s", &[Value::str(t.name())]))
                    }
                    _ => Ok(Value::Invalid),
                };
            }
            Node::Field { .. } => {
                let v = self.eval_field_node(dot, n, std::slice::from_ref(n), None)?;
                return self.validate_type(v, typ);
            }
            Node::Variable(v) => {
                let r = self.eval_variable_node(dot, v, &[], None)?;
                return self.validate_type(r, typ);
            }
            Node::Pipe(p) => {
                let r = self.eval_pipeline(dot, Some(p))?;
                return self.validate_type(r, typ);
            }
            Node::Identifier { .. } => {
                let r = self.eval_function(dot, n, NodeRef::Node(n), &[], None)?;
                return self.validate_type(r, typ);
            }
            Node::Chain { .. } => {
                let r = self.eval_chain_node(dot, n, &[], None)?;
                return self.validate_type(r, typ);
            }
            _ => {}
        }
        match typ {
            Some(PType::Any | PType::Rv) => self.eval_empty_interface(dot, n),
            Some(PType::Str) => {
                if let Node::String { text, .. } = n {
                    Ok(Value::Str(text.clone()))
                } else {
                    Err(self.errorf(b"expected string; found %s", &[Value::Str(n.string())]))
                }
            }
            None => Err(self.errorf(
                b"can't handle %s for arg of type %s",
                &[Value::Str(n.string()), Value::str("<nil>")],
            )),
        }
    }

    fn eval_empty_interface(&mut self, dot: &Value, n: &'a Node) -> R<Value> {
        self.at(NodeRef::Node(n));
        match n {
            Node::Bool { value, .. } => Ok(Value::Bool(*value)),
            Node::Dot { .. } => Ok(dot.clone()),
            Node::Field { .. } => self.eval_field_node(dot, n, &[], None),
            Node::Identifier { .. } => self.eval_function(dot, n, NodeRef::Node(n), &[], None),
            Node::Nil { .. } => Err(self.errorf(b"evalEmptyInterface: nil (can't happen)", &[])),
            Node::Number(num) => self.ideal_constant(n, num),
            Node::String { text, .. } => Ok(Value::Str(text.clone())),
            Node::Variable(v) => self.eval_variable_node(dot, v, &[], None),
            Node::Pipe(p) => self.eval_pipeline(dot, Some(p)),
            other => Err(self.errorf(
                b"can't handle assignment of %s to empty interface argument",
                &[Value::Str(other.string())],
            )),
        }
    }

    fn print_value(&mut self, n: &'a Node, v: &Value) {
        self.at(NodeRef::Node(n));
        if !v.is_valid() {
            self.wr.extend_from_slice(b"<no value>");
            return;
        }
        let out = sprint(std::slice::from_ref(v));
        self.wr.extend_from_slice(&out);
    }
}
