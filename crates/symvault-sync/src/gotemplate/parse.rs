//! Port of `text/template/parse/parse.go` (Go 1.26).

use super::gofmt::{errorf, sprintf};
use super::gostr::{Bytes, is_blank};
use super::lex::{Item, ItemType, Lexer};
use super::node::{
    BranchNode, CommandNode, ListNode, Node, NumberKind, NumberNode, PipeNode, TemplateNode,
    VariableNode,
};
use super::strconv;
use super::value::Value;
use std::collections::HashMap;

type PResult<T> = Result<T, Bytes>;

const MAX_STACK_DEPTH: usize = 10_000;

/// Result of parsing one template text: all named trees.
pub struct Parsed {
    pub parse_name: Bytes,
    pub text: Bytes,
    pub trees: HashMap<Bytes, ListNode>,
}

struct TreeState {
    name: Bytes,
    token: [Item; 3],
    peek_count: usize,
    vars: Vec<Bytes>,
    action_line: i64,
    range_depth: i64,
    stack_depth: usize,
}

impl TreeState {
    fn new(name: &[u8]) -> Self {
        TreeState {
            name: name.to_vec(),
            token: [
                Item::eof_placeholder(),
                Item::eof_placeholder(),
                Item::eof_placeholder(),
            ],
            peek_count: 0,
            vars: vec![b"$".to_vec()],
            action_line: 0,
            range_depth: 0,
            stack_depth: 0,
        }
    }
}

struct Parser<'a> {
    lex: Lexer,
    parse_name: Bytes,
    trees: HashMap<Bytes, ListNode>,
    has_function: &'a dyn Fn(&[u8]) -> bool,
    t: TreeState,
}

/// `parse.Parse(name, text, "", "", funcs...)`; `has_function` answers
/// `Tree.hasFunction`.
pub fn parse(
    name: &[u8],
    text: &[u8],
    has_function: &dyn Fn(&[u8]) -> bool,
) -> Result<Parsed, Bytes> {
    let mut p = Parser {
        lex: Lexer::new(text),
        parse_name: name.to_vec(),
        trees: HashMap::new(),
        has_function,
        t: TreeState::new(name),
    };
    let root = p.parse_top()?;
    p.add(&p.t.name.clone(), root)?;
    Ok(Parsed {
        parse_name: name.to_vec(),
        text: text.to_vec(),
        trees: p.trees,
    })
}

pub fn is_empty_tree(n: &ListNode) -> bool {
    n.nodes.iter().all(is_empty_node)
}

fn is_empty_node(n: &Node) -> bool {
    match n {
        Node::Text { text, .. } => is_blank(text),
        _ => false,
    }
}

fn split_dots(s: &[u8]) -> Vec<Bytes> {
    s.split(|&c| c == b'.').map(<[u8]>::to_vec).collect()
}

fn new_variable(pos: usize, ident: &[u8]) -> VariableNode {
    VariableNode {
        pos,
        ident: split_dots(ident),
    }
}

fn new_field(pos: usize, ident: &[u8]) -> Node {
    Node::Field {
        pos,
        ident: split_dots(&ident[1..]),
    }
}

impl Parser<'_> {
    // ---- token plumbing ---------------------------------------------

    fn next(&mut self) -> Item {
        if self.t.peek_count > 0 {
            self.t.peek_count -= 1;
        } else {
            self.t.token[0] = self.lex.next_item();
        }
        self.t.token[self.t.peek_count].clone()
    }

    fn backup(&mut self) {
        self.t.peek_count += 1;
    }

    fn backup2(&mut self, t1: Item) {
        self.t.token[1] = t1;
        self.t.peek_count = 2;
    }

    fn backup3(&mut self, t2: Item, t1: Item) {
        self.t.token[1] = t1;
        self.t.token[2] = t2;
        self.t.peek_count = 3;
    }

    fn peek(&mut self) -> Item {
        if self.t.peek_count > 0 {
            return self.t.token[self.t.peek_count - 1].clone();
        }
        self.t.peek_count = 1;
        self.t.token[0] = self.lex.next_item();
        self.t.token[0].clone()
    }

    fn next_non_space(&mut self) -> Item {
        loop {
            let token = self.next();
            if token.typ != ItemType::Space {
                return token;
            }
        }
    }

    fn peek_non_space(&mut self) -> Item {
        let token = self.next_non_space();
        self.backup();
        token
    }

    // ---- errors ------------------------------------------------------

    fn errorf(&self, format: &[u8], args: &[Value]) -> Bytes {
        let inner = sprintf(
            b"template: %s:%d: %s",
            &[
                Value::Str(self.parse_name.clone()),
                Value::Int(self.t.token[0].line),
                Value::Str(format.to_vec()),
            ],
        );
        errorf(&inner, args)
    }

    fn error_text(&self, err: &[u8]) -> Bytes {
        self.errorf(b"%s", &[Value::Str(err.to_vec())])
    }

    fn unexpected(&self, token: &Item, context: &str) -> Bytes {
        if token.typ == ItemType::Error {
            let mut extra = Bytes::new();
            if self.t.action_line != 0 && self.t.action_line != token.line {
                extra = sprintf(
                    b" in action started at %s:%d",
                    &[
                        Value::Str(self.parse_name.clone()),
                        Value::Int(self.t.action_line),
                    ],
                );
                if token.val.ends_with(b" action") {
                    extra = extra[b" in action".len()..].to_vec();
                }
            }
            return self.errorf(b"%s%s", &[Value::Str(token.string()), Value::Str(extra)]);
        }
        self.errorf(
            b"unexpected %s in %s",
            &[Value::Str(token.string()), Value::str(context)],
        )
    }

    fn expect(&mut self, expected: ItemType, context: &str) -> PResult<Item> {
        let token = self.next_non_space();
        if token.typ != expected {
            return Err(self.unexpected(&token, context));
        }
        Ok(token)
    }

    fn expect_one_of(&mut self, e1: ItemType, e2: ItemType, context: &str) -> PResult<Item> {
        let token = self.next_non_space();
        if token.typ != e1 && token.typ != e2 {
            return Err(self.unexpected(&token, context));
        }
        Ok(token)
    }

    // ---- structure ----------------------------------------------------

    fn add(&mut self, name: &[u8], root: ListNode) -> PResult<()> {
        match self.trees.get(name) {
            None => {
                self.trees.insert(name.to_vec(), root);
            }
            Some(existing) if is_empty_tree(existing) => {
                self.trees.insert(name.to_vec(), root);
            }
            Some(_) => {
                if !is_empty_tree(&root) {
                    return Err(self.errorf(
                        b"template: multiple definition of template %q",
                        &[Value::Str(name.to_vec())],
                    ));
                }
            }
        }
        Ok(())
    }

    fn parse_top(&mut self) -> PResult<ListNode> {
        let pos = self.peek().pos;
        let mut root = ListNode {
            pos,
            nodes: Vec::new(),
        };
        while self.peek().typ != ItemType::Eof {
            if self.peek().typ == ItemType::LeftDelim {
                let delim = self.next();
                if self.next_non_space().typ == ItemType::Define {
                    let saved = std::mem::replace(&mut self.t, TreeState::new(b"definition"));
                    self.parse_definition()?;
                    self.t = saved;
                    continue;
                }
                self.backup2(delim);
            }
            let n = self.text_or_action()?;
            match n {
                Node::End { .. } | Node::Else { .. } => {
                    return Err(self.errorf(b"unexpected %s", &[Value::Str(n.string())]));
                }
                _ => root.nodes.push(n),
            }
        }
        Ok(root)
    }

    fn parse_definition(&mut self) -> PResult<()> {
        const CONTEXT: &str = "define clause";
        let name = self.expect_one_of(ItemType::String, ItemType::RawString, CONTEXT)?;
        let unquoted = match strconv::unquote(&name.val) {
            Ok(s) => s,
            Err(()) => return Err(self.error_text(b"invalid syntax")),
        };
        self.t.name = unquoted;
        self.expect(ItemType::RightDelim, CONTEXT)?;
        let (root, end) = self.item_list()?;
        if !matches!(end, Node::End { .. }) {
            return Err(self.errorf(
                b"unexpected %s in %s",
                &[Value::Str(end.string()), Value::str(CONTEXT)],
            ));
        }
        let name = self.t.name.clone();
        self.add(&name, root)
    }

    fn item_list(&mut self) -> PResult<(ListNode, Node)> {
        let pos = self.peek_non_space().pos;
        let mut list = ListNode {
            pos,
            nodes: Vec::new(),
        };
        while self.peek_non_space().typ != ItemType::Eof {
            let n = self.text_or_action()?;
            if matches!(n, Node::End { .. } | Node::Else { .. }) {
                return Ok((list, n));
            }
            list.nodes.push(n);
        }
        Err(self.errorf(b"unexpected EOF", &[]))
    }

    fn text_or_action(&mut self) -> PResult<Node> {
        let token = self.next_non_space();
        match token.typ {
            ItemType::Text => Ok(Node::Text {
                pos: token.pos,
                text: token.val,
            }),
            ItemType::LeftDelim => {
                self.t.action_line = token.line;
                let r = self.action();
                self.t.action_line = 0;
                r
            }
            _ => Err(self.unexpected(&token, "input")),
        }
    }

    fn action(&mut self) -> PResult<Node> {
        let token = self.next_non_space();
        match token.typ {
            ItemType::Block => return self.block_control(),
            ItemType::Break => return self.break_control(token.pos),
            ItemType::Continue => return self.continue_control(token.pos),
            ItemType::Else => return self.else_control(),
            ItemType::End => return self.end_control(),
            ItemType::If => return self.if_control(),
            ItemType::Range => return self.range_control(),
            ItemType::Template => return self.template_control(),
            ItemType::With => return self.with_control(),
            _ => {}
        }
        self.backup();
        let token = self.peek();
        let pipe = self.pipeline("command", ItemType::RightDelim)?;
        Ok(Node::Action {
            pos: token.pos,
            pipe,
        })
    }

    fn break_control(&mut self, pos: usize) -> PResult<Node> {
        let token = self.next_non_space();
        if token.typ != ItemType::RightDelim {
            return Err(self.unexpected(&token, "{{break}}"));
        }
        if self.t.range_depth == 0 {
            return Err(self.errorf(b"{{break}} outside {{range}}", &[]));
        }
        Ok(Node::Break { pos })
    }

    fn continue_control(&mut self, pos: usize) -> PResult<Node> {
        let token = self.next_non_space();
        if token.typ != ItemType::RightDelim {
            return Err(self.unexpected(&token, "{{continue}}"));
        }
        if self.t.range_depth == 0 {
            return Err(self.errorf(b"{{continue}} outside {{range}}", &[]));
        }
        Ok(Node::Continue { pos })
    }

    fn pipeline(&mut self, context: &str, end: ItemType) -> PResult<PipeNode> {
        let token = self.peek_non_space();
        let mut pipe = PipeNode {
            pos: token.pos,
            is_assign: false,
            decl: Vec::new(),
            cmds: Vec::new(),
        };
        'decls: loop {
            let v = self.peek_non_space();
            if v.typ == ItemType::Variable {
                self.next();
                let token_after_variable = self.peek();
                let next = self.peek_non_space();
                if next.typ == ItemType::Assign || next.typ == ItemType::Declare {
                    pipe.is_assign = next.typ == ItemType::Assign;
                    self.next_non_space();
                    pipe.decl.push(new_variable(v.pos, &v.val));
                    self.t.vars.push(v.val.clone());
                } else if next.typ == ItemType::Char && next.val == b"," {
                    self.next_non_space();
                    pipe.decl.push(new_variable(v.pos, &v.val));
                    self.t.vars.push(v.val.clone());
                    if context == "range" && pipe.decl.len() < 2 {
                        match self.peek_non_space().typ {
                            ItemType::Variable | ItemType::RightDelim | ItemType::RightParen => {
                                continue 'decls;
                            }
                            _ => {
                                return Err(
                                    self.errorf(b"range can only initialize variables", &[])
                                );
                            }
                        }
                    }
                    return Err(self.errorf(b"too many declarations in %s", &[Value::str(context)]));
                } else if token_after_variable.typ == ItemType::Space {
                    self.backup3(v, token_after_variable);
                } else {
                    self.backup2(v);
                }
            }
            break;
        }
        loop {
            let token = self.next_non_space();
            if token.typ == end {
                self.check_pipeline(&pipe, context)?;
                return Ok(pipe);
            }
            match token.typ {
                ItemType::Bool
                | ItemType::CharConstant
                | ItemType::Complex
                | ItemType::Dot
                | ItemType::Field
                | ItemType::Identifier
                | ItemType::Number
                | ItemType::Nil
                | ItemType::RawString
                | ItemType::String
                | ItemType::Variable
                | ItemType::LeftParen => {
                    self.backup();
                    let c = self.command()?;
                    pipe.cmds.push(c);
                }
                _ => return Err(self.unexpected(&token, context)),
            }
        }
    }

    fn check_pipeline(&self, pipe: &PipeNode, context: &str) -> PResult<()> {
        if pipe.cmds.is_empty() {
            return Err(self.errorf(b"missing value for %s", &[Value::str(context)]));
        }
        for (i, c) in pipe.cmds[1..].iter().enumerate() {
            if matches!(
                c.args[0],
                Node::Bool { .. }
                    | Node::Dot { .. }
                    | Node::Nil { .. }
                    | Node::Number(_)
                    | Node::String { .. }
            ) {
                return Err(self.errorf(
                    b"non executable command in pipeline stage %d",
                    &[Value::Int(i as i64 + 2)],
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn parse_control(
        &mut self,
        context: &str,
    ) -> PResult<(usize, PipeNode, ListNode, Option<ListNode>)> {
        let nvars = self.t.vars.len();
        let r = self.parse_control_inner(context);
        self.t.vars.truncate(nvars);
        r
    }

    #[allow(clippy::type_complexity)]
    fn parse_control_inner(
        &mut self,
        context: &str,
    ) -> PResult<(usize, PipeNode, ListNode, Option<ListNode>)> {
        let pipe = self.pipeline(context, ItemType::RightDelim)?;
        if context == "range" {
            self.t.range_depth += 1;
        }
        let (list, next) = self.item_list()?;
        if context == "range" {
            self.t.range_depth -= 1;
        }
        let mut else_list = None;
        match next {
            Node::End { .. } => {}
            Node::Else { pos } => {
                if context == "if" && self.peek().typ == ItemType::If {
                    self.next();
                    let mut l = ListNode {
                        pos,
                        nodes: Vec::new(),
                    };
                    l.nodes.push(self.if_control()?);
                    else_list = Some(l);
                } else if context == "with" && self.peek().typ == ItemType::With {
                    self.next();
                    let mut l = ListNode {
                        pos,
                        nodes: Vec::new(),
                    };
                    l.nodes.push(self.with_control()?);
                    else_list = Some(l);
                } else {
                    let (l, next) = self.item_list()?;
                    if !matches!(next, Node::End { .. }) {
                        return Err(
                            self.errorf(b"expected end; found %s", &[Value::Str(next.string())])
                        );
                    }
                    else_list = Some(l);
                }
            }
            _ => {}
        }
        Ok((pipe.pos, pipe, list, else_list))
    }

    fn branch(&mut self, context: &str) -> PResult<Box<BranchNode>> {
        let (pos, pipe, list, else_list) = self.parse_control(context)?;
        Ok(Box::new(BranchNode {
            pos,
            pipe,
            list,
            else_list,
        }))
    }

    fn if_control(&mut self) -> PResult<Node> {
        Ok(Node::If(self.branch("if")?))
    }

    fn range_control(&mut self) -> PResult<Node> {
        Ok(Node::Range(self.branch("range")?))
    }

    fn with_control(&mut self) -> PResult<Node> {
        Ok(Node::With(self.branch("with")?))
    }

    fn end_control(&mut self) -> PResult<Node> {
        let pos = self.expect(ItemType::RightDelim, "end")?.pos;
        Ok(Node::End { pos })
    }

    fn else_control(&mut self) -> PResult<Node> {
        let peek = self.peek_non_space();
        if peek.typ == ItemType::If || peek.typ == ItemType::With {
            return Ok(Node::Else { pos: peek.pos });
        }
        let token = self.expect(ItemType::RightDelim, "else")?;
        Ok(Node::Else { pos: token.pos })
    }

    fn block_control(&mut self) -> PResult<Node> {
        const CONTEXT: &str = "block clause";
        let token = self.next_non_space();
        let name = self.parse_template_name(&token, CONTEXT)?;
        let pipe = self.pipeline(CONTEXT, ItemType::RightDelim)?;

        let saved = std::mem::replace(&mut self.t, TreeState::new(&name));
        let (root, end) = self.item_list()?;
        let block_state = std::mem::replace(&mut self.t, saved);
        if !matches!(end, Node::End { .. }) {
            return Err(self.errorf(
                b"unexpected %s in %s",
                &[Value::Str(end.string()), Value::str(CONTEXT)],
            ));
        }
        let outer = std::mem::replace(&mut self.t, block_state);
        let added = self.add(&name, root);
        self.t = outer;
        added?;

        Ok(Node::Template(Box::new(TemplateNode {
            pos: token.pos,
            name,
            pipe: Some(pipe),
        })))
    }

    fn template_control(&mut self) -> PResult<Node> {
        const CONTEXT: &str = "template clause";
        let token = self.next_non_space();
        let name = self.parse_template_name(&token, CONTEXT)?;
        let mut pipe = None;
        if self.next_non_space().typ != ItemType::RightDelim {
            self.backup();
            pipe = Some(self.pipeline(CONTEXT, ItemType::RightDelim)?);
        }
        Ok(Node::Template(Box::new(TemplateNode {
            pos: token.pos,
            name,
            pipe,
        })))
    }

    fn parse_template_name(&self, token: &Item, context: &str) -> PResult<Bytes> {
        match token.typ {
            ItemType::String | ItemType::RawString => {
                strconv::unquote(&token.val).map_err(|()| self.error_text(b"invalid syntax"))
            }
            _ => Err(self.unexpected(token, context)),
        }
    }

    fn command(&mut self) -> PResult<CommandNode> {
        let pos = self.peek_non_space().pos;
        let mut cmd = CommandNode {
            pos,
            args: Vec::new(),
        };
        loop {
            self.peek_non_space();
            if let Some(operand) = self.operand()? {
                cmd.args.push(operand);
            }
            let token = self.next();
            match token.typ {
                ItemType::Space => continue,
                ItemType::RightDelim | ItemType::RightParen => self.backup(),
                ItemType::Pipe => {}
                _ => return Err(self.unexpected(&token, "operand")),
            }
            break;
        }
        if cmd.args.is_empty() {
            return Err(self.errorf(b"empty command", &[]));
        }
        Ok(cmd)
    }

    fn operand(&mut self) -> PResult<Option<Node>> {
        let Some(mut node) = self.term()? else {
            return Ok(None);
        };
        if self.peek().typ == ItemType::Field {
            let chain_pos = self.peek().pos;
            let mut fields: Vec<Bytes> = Vec::new();
            while self.peek().typ == ItemType::Field {
                let val = self.next().val;
                fields.push(val[1..].to_vec());
            }
            let chain = Node::Chain {
                pos: chain_pos,
                node: Box::new(node.clone()),
                field: fields,
            };
            node = match &node {
                Node::Field { .. } => new_field(chain_pos, &chain.string()),
                Node::Variable(_) => Node::Variable(new_variable(chain_pos, &chain.string())),
                Node::Bool { .. }
                | Node::String { .. }
                | Node::Number(_)
                | Node::Nil { .. }
                | Node::Dot { .. } => {
                    return Err(
                        self.errorf(b"unexpected . after term %q", &[Value::Str(node.string())])
                    );
                }
                _ => chain,
            };
        }
        Ok(Some(node))
    }

    fn term(&mut self) -> PResult<Option<Node>> {
        let token = self.next_non_space();
        match token.typ {
            ItemType::Identifier => {
                if !(self.has_function)(&token.val) {
                    return Err(
                        self.errorf(b"function %q not defined", &[Value::Str(token.val.clone())])
                    );
                }
                Ok(Some(Node::Identifier {
                    pos: token.pos,
                    ident: token.val,
                }))
            }
            ItemType::Dot => Ok(Some(Node::Dot { pos: token.pos })),
            ItemType::Nil => Ok(Some(Node::Nil { pos: token.pos })),
            ItemType::Variable => {
                let v = new_variable(token.pos, &token.val);
                if self.t.vars.iter().any(|name| *name == v.ident[0]) {
                    return Ok(Some(Node::Variable(v)));
                }
                Err(self.errorf(b"undefined variable %q", &[Value::Str(v.ident[0].clone())]))
            }
            ItemType::Field => Ok(Some(new_field(token.pos, &token.val))),
            ItemType::Bool => Ok(Some(Node::Bool {
                pos: token.pos,
                value: token.val == b"true",
            })),
            ItemType::CharConstant | ItemType::Complex | ItemType::Number => {
                let kind = match token.typ {
                    ItemType::CharConstant => NumberKind::CharConstant,
                    ItemType::Complex => NumberKind::Complex,
                    _ => NumberKind::Plain,
                };
                match NumberNode::new(token.pos, &token.val, kind) {
                    Ok(n) => Ok(Some(Node::Number(Box::new(n)))),
                    Err(e) => Err(self.error_text(&e)),
                }
            }
            ItemType::LeftParen => {
                if self.t.stack_depth >= MAX_STACK_DEPTH {
                    return Err(self.errorf(b"max expression depth exceeded", &[]));
                }
                self.t.stack_depth += 1;
                let r = self.pipeline("parenthesized pipeline", ItemType::RightParen);
                self.t.stack_depth -= 1;
                Ok(Some(Node::Pipe(r?)))
            }
            ItemType::String | ItemType::RawString => match strconv::unquote(&token.val) {
                Ok(s) => Ok(Some(Node::String {
                    pos: token.pos,
                    quoted: token.val,
                    text: s,
                })),
                Err(()) => Err(self.error_text(b"invalid syntax")),
            },
            _ => {
                self.backup();
                Ok(None)
            }
        }
    }
}
