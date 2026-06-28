// SPDX-License-Identifier: Apache-2.0
//! Recursive-descent parser.

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::asm::{parse_asm_line, AsmBody, AsmLine};
use crate::ast::*;
use crate::cimport;
use crate::lexer::{self, Tok, Token};

fn resolve_stdlib_import(importer: &Path, name: &str) -> Option<String> {
    let importer_dir = importer.parent()?;
    let mut candidates: Vec<String> = vec![format!("{name}.etpy")];
    if let Some(idx) = name.find('_') {
        let (head, tail_with_us) = name.split_at(idx);
        let tail = &tail_with_us[1..];     // skip the underscore
        candidates.push(format!("{head}/{tail}.etpy"));
    }
    candidates.push(format!("opsec/{name}.etpy"));

    let mut cursor = importer_dir.to_path_buf();
    loop {
        for sub in &candidates {
            let candidate = cursor.join("stdlib").join(sub);
            if candidate.exists() {
                let rel = pathdiff_relative(&candidate, importer_dir)
                    .unwrap_or(candidate);
                return Some(rel.to_string_lossy().to_string());
            }
        }
        match cursor.parent() {
            Some(p) if p != cursor => cursor = p.to_path_buf(),
            _ => return None,
        }
    }
}

/// dst relative to base (both absolute, or both relative to the
/// same anchor). Inline replacement for the pathdiff crate.
fn pathdiff_relative(dst: &Path, base: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let d: Vec<_> = dst.components().collect();
    let b: Vec<_> = base.components().collect();
    let mut common = 0;
    while common < d.len() && common < b.len() && d[common] == b[common] {
        common += 1;
    }
    let mut out = PathBuf::new();
    for _ in &b[common..] {
        out.push("..");
    }
    for c in &d[common..] {
        match c {
            Component::Normal(s) => out.push(s),
            Component::RootDir | Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                out.push(c.as_os_str());
            }
        }
    }
    if out.as_os_str().is_empty() { None } else { Some(out) }
}

/// Sized-integer aliases. These are always valid as cast targets regardless
/// of whether the source declared anything by that name.
fn is_sized_int_name(s: &str) -> bool {
    matches!(s, "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64")
}

pub struct Parser {
    toks: Vec<Token>,
    pos:  usize,
    type_names: HashSet<String>,
    /// Absolute path of this parser's source file. use resolves
    /// relative to this directory.
    source_path: PathBuf,
    /// Canonical paths already pulled in. Shared across recursive
    /// use so cycle detection is global.
    imported: Rc<RefCell<HashSet<PathBuf>>>,
}

impl Parser {
    /// Root parser. Seeds imported with the source file's own path
    /// so a transitive use of it is a silent no-op.
    pub fn new(toks: Vec<Token>, source_path: impl AsRef<Path>) -> Self {
        let imported = Rc::new(RefCell::new(HashSet::new()));
        let p = source_path.as_ref().to_path_buf();
        if let Ok(canon) = std::fs::canonicalize(&p) {
            imported.borrow_mut().insert(canon);
        }
        Self {
            toks,
            pos: 0,
            type_names: HashSet::new(),
            source_path: p,
            imported,
        }
    }

    /// Child parser for use expansion. Shares imported with the parent.
    fn new_child(
        toks: Vec<Token>,
        source_path: PathBuf,
        imported: Rc<RefCell<HashSet<PathBuf>>>,
    ) -> Self {
        Self {
            toks,
            pos: 0,
            type_names: HashSet::new(),
            source_path,
            imported,
        }
    }

    fn peek(&self)        -> &Tok { &self.toks[self.pos].kind }
    fn peek_tok(&self)    -> &Token { &self.toks[self.pos] }
    fn advance(&mut self) -> Tok  { let k = self.toks[self.pos].kind.clone(); self.pos += 1; k }
    fn check(&self, k: &Tok) -> bool { std::mem::discriminant(self.peek()) == std::mem::discriminant(k) }
    fn matches(&mut self, k: &Tok) -> bool {
        if self.check(k) { self.advance(); true } else { false }
    }
    fn expect(&mut self, k: &Tok, what: &str) -> Result<Tok, String> {
        if self.check(k) { Ok(self.advance()) }
        else {
            let t = self.peek_tok();
            Err(format!("parse error at {}:{}: expected {what}, got {:?}", t.line, t.col, t.kind))
        }
    }
    fn eat_ident(&mut self) -> Result<String, String> {
        if let Tok::Ident(s) = self.peek().clone() { self.advance(); Ok(s) }
        else {
            let t = self.peek_tok();
            Err(format!("parse error at {}:{}: expected identifier", t.line, t.col))
        }
    }

    pub fn parse_program(&mut self) -> Result<Program, String> {
        let mut p = Program::default();
        while !self.check(&Tok::Eof) {
            // Collect attributes first; check that the next item is
            // one that accepts them (fn or struct).
            let attrs = self.parse_attrs()?;
            match self.peek() {
                Tok::Fn | Tok::Extern => {
                    let mut f = self.parse_fn()?;
                    f.attrs = attrs;
                    p.functions.push(f);
                }
                Tok::Struct  => {
                    let mut s = self.parse_struct()?;
                    s.attrs = attrs;
                    self.type_names.insert(s.name.clone());
                    p.structs.push(s);
                }
                _ if !attrs.is_empty() => {
                    let t = self.peek_tok();
                    return Err(format!(
                        "parse error at {}:{}: attributes only apply to `fn` or `struct` declarations",
                        t.line, t.col
                    ));
                }
                Tok::Static  => p.statics.push(self.parse_static()?),
                Tok::Enum    => {
                    let e = self.parse_enum()?;
                    self.type_names.insert(e.name.clone());
                    p.enums.push(e);
                }
                Tok::UseC    => self.parse_use_c_into(&mut p)?,
                Tok::Use     => self.parse_use_into(&mut p)?,
                _ => {
                    let t = self.peek_tok();
                    return Err(format!(
                        "parse error at {}:{}: expected `fn`, `extern fn`, `static`, `struct`, `enum`, `use_c`, or `use`",
                        t.line, t.col
                    ));
                }
            }
        }
        Ok(p)
    }

    fn parse_attrs(&mut self) -> Result<Vec<Attr>, String> {
        let mut out = Vec::new();
        while self.check(&Tok::LBrack) {
            self.advance();
            let kind = self.eat_ident()?;
            let arg = if self.matches(&Tok::LParen) {
                let name = match self.peek().clone() {
                    Tok::Str(s)   => { self.advance(); s }
                    Tok::Ident(s) => { self.advance(); s }
                    _ => {
                        let t = self.peek_tok();
                        return Err(format!(
                            "parse error at {}:{}: attribute argument must be \
                             an identifier or string literal",
                            t.line, t.col
                        ));
                    }
                };
                self.expect(&Tok::RParen, "`)`")?;
                Some(name)
            } else {
                None
            };
            self.expect(&Tok::RBrack, "`]`")?;
            out.push(Attr { kind, arg });
        }
        Ok(out)
    }

    fn parse_use_c_into(&mut self, prog: &mut Program) -> Result<(), String> {
        let here = self.peek_tok().clone();
        self.expect(&Tok::UseC, "`use_c`")?;
        let rel_path = match self.peek().clone() {
            Tok::Str(s) => { self.advance(); s }
            _ => return Err(format!(
                "parse error at {}:{}: expected string literal path after `use_c`",
                here.line, here.col
            )),
        };
        self.expect(&Tok::Semi, "`;`")?;

        let dir = self.source_path.parent().unwrap_or_else(|| Path::new("."));
        let candidate = dir.join(&rel_path);
        let resolved = if candidate.exists() {
            candidate
        } else {
            PathBuf::from(&rel_path)
        };
        let resolved_str = resolved.to_string_lossy().to_string();

        let imported = cimport::parse_header(&resolved_str)?;
        for s in &imported.structs {
            self.type_names.insert(s.name.clone());
        }
        prog.structs.extend(imported.structs);
        prog.statics.extend(imported.statics);
        Ok(())
    }

    fn parse_use_into(&mut self, prog: &mut Program) -> Result<(), String> {
        let here = self.peek_tok().clone();
        self.expect(&Tok::Use, "`use`")?;

        let rel_path = match self.peek().clone() {
            Tok::Str(s) => { self.advance(); s }
            Tok::Ident(name) => {
                self.advance();
                resolve_stdlib_import(&self.source_path, &name)
                    .ok_or_else(|| format!(
                        "use `{name}`: no stdlib module found. \
                         Expected to find `stdlib/{name}.etpy` walking \
                         up from {}.",
                        self.source_path.display()
                    ))?
            }
            _ => return Err(format!(
                "parse error at {}:{}: expected `\"path\"` or stdlib name after `use`",
                here.line, here.col
            )),
        };
        self.expect(&Tok::Semi, "`;`")?;

        // Resolve relative to the importing file's directory.
        let dir = self.source_path.parent().unwrap_or_else(|| Path::new("."));
        let abs = dir.join(&rel_path);
        let canon = std::fs::canonicalize(&abs)
            .map_err(|e| format!(
                "use \"{rel_path}\": {} ({})",
                e,
                abs.display(),
            ))?;

        // Dedupe + cycle break.
        if !self.imported.borrow_mut().insert(canon.clone()) {
            return Ok(());
        }

        // Parse the imported file. Use new_child so the child shares our
        // imported-paths set - any use it does dedupes globally.
        let src = std::fs::read_to_string(&canon)
            .map_err(|e| format!("use \"{rel_path}\": {e}"))?;
        let tokens = lexer::tokenize(&src)?;
        let mut child = Parser::new_child(tokens, canon.clone(), self.imported.clone());
        let sub = child.parse_program()
            .map_err(|e| format!("in `use \"{rel_path}\"`: {e}"))?;

        // Merge. Struct + enum names get registered in our own
        // type_names set so subsequent casts / declarations in
        // this file can refer to them.
        for s in &sub.structs {
            self.type_names.insert(s.name.clone());
        }
        for e in &sub.enums {
            self.type_names.insert(e.name.clone());
        }
        prog.structs.extend(sub.structs);
        prog.statics.extend(sub.statics);
        prog.functions.extend(sub.functions);
        prog.enums.extend(sub.enums);
        Ok(())
    }

    fn parse_type(&mut self) -> Result<String, String> {
        let mut ty = match self.peek().clone() {
            Tok::Int_  => { self.advance(); "int".to_string() }
            Tok::Str_  => { self.advance(); "str".to_string() }
            Tok::Wstr_ => { self.advance(); "wstr".to_string() }
            Tok::Bool_ => { self.advance(); "bool".to_string() }
            Tok::Void_ => { self.advance(); "void".to_string() }
            Tok::Char_ => { self.advance(); "u8".to_string() }
            Tok::Ident(name) => { self.advance(); name }
            _ => {
                let t = self.peek_tok();
                return Err(format!("parse error at {}:{}: expected type", t.line, t.col));
            }
        };
        while self.matches(&Tok::Star) {
            ty.push('*');
        }
        if self.matches(&Tok::LBrack) {
            let n = match self.peek().clone() {
                Tok::Int(n) if n >= 0 => { self.advance(); n }
                _ => {
                    let t = self.peek_tok();
                    return Err(format!(
                        "parse error at {}:{}: array size must be a non-negative integer literal",
                        t.line, t.col
                    ));
                }
            };
            self.expect(&Tok::RBrack, "`]`")?;
            ty = format!("{ty}[{n}]");
        }
        Ok(ty)
    }

    fn parse_static(&mut self) -> Result<StaticDecl, String> {
        self.expect(&Tok::Static, "`static`")?;
        let name = self.eat_ident()?;
        self.expect(&Tok::Colon, "`:`")?;
        let ty = self.parse_type()?;
        let init = if self.matches(&Tok::Assign) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect(&Tok::Semi, "`;`")?;
        Ok(StaticDecl { name, ty, init, attrs: vec![] })
    }

    fn parse_struct(&mut self) -> Result<StructDef, String> {
        self.expect(&Tok::Struct, "`struct`")?;
        let name = self.eat_ident()?;
        self.expect(&Tok::LBrace, "`{`")?;
        let mut fields = Vec::new();
        while !self.check(&Tok::RBrace) {
            let fname = self.eat_ident()?;
            self.expect(&Tok::Colon, "`:`")?;
            let fty = self.parse_type()?;
            fields.push((fname, fty));
            if !self.matches(&Tok::Comma) { break; }
        }
        self.expect(&Tok::RBrace, "`}`")?;
        Ok(StructDef { name, fields, is_union: false, attrs: Vec::new() })
    }

    fn parse_enum(&mut self) -> Result<crate::ast::EnumDecl, String> {
        self.expect(&Tok::Enum, "`enum`")?;
        let name = self.eat_ident()?;
        self.expect(&Tok::LBrace, "`{`")?;
        let mut variants: Vec<(String, i128)> = Vec::new();
        let mut next_value: i128 = 0;
        while !self.check(&Tok::RBrace) {
            let vname = self.eat_ident()?;
            let value = if self.matches(&Tok::Assign) {
                // Optional unary minus before the integer literal -
                // enum Errno { OK = 0, OOM = -1 } should parse.
                let negate = self.matches(&Tok::Minus);
                let n = match self.peek().clone() {
                    Tok::Int(n) => { self.advance(); n }
                    _ => {
                        let t = self.peek_tok();
                        return Err(format!(
                            "parse error at {}:{}: enum variant value must be an integer literal",
                            t.line, t.col
                        ));
                    }
                };
                if negate { -n } else { n }
            } else {
                next_value
            };
            variants.push((vname, value));
            next_value = value.wrapping_add(1);
            if !self.matches(&Tok::Comma) { break; }
        }
        self.expect(&Tok::RBrace, "`}`")?;
        // Trailing semicolon optional - mirrors the C-style };
        // habit without forcing it.
        let _ = self.matches(&Tok::Semi);
        Ok(crate::ast::EnumDecl { name, variants })
    }

    /// Used by the cast disambiguator: built-in keyword types and the
    /// sized-int aliases. Struct names are excluded from cast types so we
    /// don't need a symbol table at parse time.
    fn try_take_cast_type(&mut self) -> Option<String> {
        let saved = self.pos;
        let mut ty = match self.peek().clone() {
            Tok::Int_  => "int".to_string(),
            Tok::Str_  => "str".to_string(),
            Tok::Wstr_ => "wstr".to_string(),
            Tok::Bool_ => "bool".to_string(),
            Tok::Void_ => "void".to_string(),
            Tok::Char_ => "u8".to_string(),
            Tok::Ident(s) if is_sized_int_name(&s) || self.type_names.contains(&s) => s,
            _ => return None,
        };
        self.advance();
        // Accept trailing *s - (u32*)x, (Beacon**)p, etc.
        while self.matches(&Tok::Star) {
            ty.push('*');
        }
        if matches!(self.peek(), Tok::RParen) {
            Some(ty)
        } else {
            self.pos = saved;
            None
        }
    }

    fn parse_field_chain(&mut self, mut base: Expr) -> Result<Expr, String> {
        loop {
            if self.check(&Tok::Dot) || self.check(&Tok::Arrow) {
                self.advance();
                let field = self.eat_ident()?;
                base = Expr::Field { base: Box::new(base), field };
            } else if self.matches(&Tok::LBrack) {
                let index = self.parse_expr()?;
                self.expect(&Tok::RBrack, "`]`")?;
                base = Expr::Index { base: Box::new(base), index: Box::new(index) };
            } else {
                break;
            }
        }
        Ok(base)
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, String> {
        let mut args = Vec::new();
        if !self.check(&Tok::RParen) {
            args.push(self.parse_expr()?);
            while self.matches(&Tok::Comma) { args.push(self.parse_expr()?); }
        }
        self.expect(&Tok::RParen, "`)`")?;
        Ok(args)
    }

    fn parse_fn(&mut self) -> Result<Function, String> {
        let is_extern = self.matches(&Tok::Extern);
        self.expect(&Tok::Fn, "`fn`")?;
        let name = self.eat_ident()?;
        self.expect(&Tok::LParen, "`(`")?;
        let mut params = Vec::new();
        if !self.check(&Tok::RParen) {
            loop {
                let pn = self.eat_ident()?;
                self.expect(&Tok::Colon, "`:`")?;
                let pt = self.parse_type()?;
                params.push(Param { name: pn, ty: pt });
                if !self.matches(&Tok::Comma) { break; }
            }
        }
        self.expect(&Tok::RParen, "`)`")?;
        self.expect(&Tok::Arrow,  "`->`")?;
        let ret_ty = self.parse_type()?;
        let body = if is_extern {
            self.expect(&Tok::Semi, "`;` (extern fn declarations have no body)")?;
            Vec::new()
        } else {
            self.parse_block()?
        };
        Ok(Function { name, params, ret_ty, body, attrs: Vec::new(), is_extern })
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>, String> {
        self.expect(&Tok::LBrace, "`{`")?;
        let mut body = Vec::new();
        while !self.check(&Tok::RBrace) { body.push(self.parse_stmt()?); }
        self.expect(&Tok::RBrace, "`}`")?;
        Ok(body)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, String> {
        // Most statements end with ;; the parsing of the trailing
        // semicolon is shared via parse_simple_stmt_no_semi.
        match self.peek().clone() {
            Tok::Var      => self.parse_var(),
            Tok::If       => self.parse_if(),
            Tok::While    => self.parse_while(),
            Tok::For      => self.parse_for(),
            Tok::Break    => {
                self.advance();
                self.expect(&Tok::Semi, "`;`")?;
                Ok(Stmt::Break)
            }
            Tok::Continue => {
                self.advance();
                self.expect(&Tok::Semi, "`;`")?;
                Ok(Stmt::Continue)
            }
            Tok::Ret      => self.parse_ret(),
            Tok::Try      => self.parse_try(),
            Tok::Raise    => self.parse_raise(),
            Tok::Asm      => self.parse_asm(),
            _ => {
                let s = self.parse_simple_stmt_no_semi()?;
                self.expect(&Tok::Semi, "`;`")?;
                Ok(s)
            }
        }
    }

    fn parse_simple_stmt_no_semi(&mut self) -> Result<Stmt, String> {
        let here = self.peek_tok().clone();
        let span = Span::new(here.line, here.col);
        let lhs = self.parse_expr()?;
        // Postfix ++ / -- - desugar to lhs = lhs +/- 1.
        if self.matches(&Tok::PlusPlus) {
            return Ok(Stmt::Expr {
                value: Self::make_compound_assign(lhs, "+", Expr::Int(1))?,
                span,
            });
        }
        if self.matches(&Tok::MinusMinus) {
            return Ok(Stmt::Expr {
                value: Self::make_compound_assign(lhs, "-", Expr::Int(1))?,
                span,
            });
        }
        // x OP= rhs - desugar to x = x OP rhs.
        let op = if self.matches(&Tok::PlusEq)    { Some("+") }
            else if self.matches(&Tok::MinusEq)   { Some("-") }
            else if self.matches(&Tok::StarEq)    { Some("*") }
            else if self.matches(&Tok::SlashEq)   { Some("/") }
            else if self.matches(&Tok::PercentEq) { Some("%") }
            else if self.matches(&Tok::AmpEq)     { Some("&") }
            else if self.matches(&Tok::PipeEq)    { Some("|") }
            else if self.matches(&Tok::CaretEq)   { Some("^") }
            else if self.matches(&Tok::ShlEq)     { Some("<<") }
            else if self.matches(&Tok::ShrEq)     { Some(">>") }
            else { None };
        if let Some(op) = op {
            let rhs = self.parse_expr()?;
            return Ok(Stmt::Expr {
                value: Self::make_compound_assign(lhs, op, rhs)?,
                span,
            });
        }
        Ok(Stmt::Expr { value: lhs, span })
    }

    fn make_compound_assign(lhs: Expr, op: &str, rhs: Expr) -> Result<Expr, String> {
        match lhs {
            Expr::Var(name) => {
                let new_val = Expr::Binary {
                    op: op.into(),
                    lhs: Box::new(Expr::Var(name.clone())),
                    rhs: Box::new(rhs),
                };
                Ok(Expr::Assign { name, value: Box::new(new_val) })
            }
            Expr::Field { base, field } => {
                let read = Expr::Field { base: base.clone(), field: field.clone() };
                let new_val = Expr::Binary {
                    op: op.into(),
                    lhs: Box::new(read),
                    rhs: Box::new(rhs),
                };
                Ok(Expr::FieldAssign { base, field, value: Box::new(new_val) })
            }
            Expr::Unary { op: uop, operand } if uop == "*" => {
                let read = Expr::Unary { op: "*".into(), operand: operand.clone() };
                let new_val = Expr::Binary {
                    op: op.into(),
                    lhs: Box::new(read),
                    rhs: Box::new(rhs),
                };
                Ok(Expr::DerefAssign { ptr: operand, value: Box::new(new_val) })
            }
            Expr::Index { base, index } => {
                let read = Expr::Index { base: base.clone(), index: index.clone() };
                let new_val = Expr::Binary {
                    op: op.into(),
                    lhs: Box::new(read),
                    rhs: Box::new(rhs),
                };
                Ok(Expr::IndexAssign { base, index, value: Box::new(new_val) })
            }
            _ => Err("invalid target for `++`/`--` or compound assignment".into()),
        }
    }

    fn parse_var(&mut self) -> Result<Stmt, String> {
        let here = self.peek_tok().clone();
        let span = Span::new(here.line, here.col);
        self.advance();
        let name = self.eat_ident()?;
        let ty = if self.matches(&Tok::Colon) { self.parse_type()? } else { "int".into() };
        // = is optional. Scalars without an initialiser are zeroed; struct
        // locals are zero-filled in their entirety (the typical Win32
        // pattern is then to set the cb field and call the API).
        let value = if self.matches(&Tok::Assign) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect(&Tok::Semi, "`;`")?;
        Ok(Stmt::Var { name, ty, value, span })
    }

    fn parse_for(&mut self) -> Result<Stmt, String> {
        self.expect(&Tok::For, "`for`")?;
        // init clause - ; means empty.
        let init = if self.matches(&Tok::Semi) {
            None
        } else if self.check(&Tok::Var) {
            Some(Box::new(self.parse_var()?))   // parse_var consumes its own `;`
        } else {
            let s = self.parse_simple_stmt_no_semi()?;
            self.expect(&Tok::Semi, "`;`")?;
            Some(Box::new(s))
        };
        // cond clause - empty means infinite (no test).
        let cond = if self.check(&Tok::Semi) {
            None
        } else {
            Some(self.parse_expr()?)
        };
        self.expect(&Tok::Semi, "`;`")?;
        // step clause - empty means no per-iteration step. Stops at {.
        let step = if self.check(&Tok::LBrace) {
            None
        } else {
            Some(Box::new(self.parse_simple_stmt_no_semi()?))
        };
        let body = self.parse_block()?;
        Ok(Stmt::For { init, cond, step, body })
    }

    fn parse_if(&mut self) -> Result<Stmt, String> {
        self.advance();
        let cond = self.parse_expr()?;
        let then_body = self.parse_block()?;
        let mut else_body = Vec::new();
        if self.matches(&Tok::Else) {
            if self.check(&Tok::If) { else_body.push(self.parse_if()?); }
            else                     { else_body = self.parse_block()?; }
        }
        Ok(Stmt::If { cond, then_body, else_body })
    }

    fn parse_while(&mut self) -> Result<Stmt, String> {
        self.advance();
        let cond = self.parse_expr()?;
        let body = self.parse_block()?;
        Ok(Stmt::While { cond, body })
    }

    fn parse_ret(&mut self) -> Result<Stmt, String> {
        let here = self.peek_tok().clone();
        let span = Span::new(here.line, here.col);
        self.advance();
        let value = if self.check(&Tok::Semi) { None } else { Some(self.parse_expr()?) };
        self.expect(&Tok::Semi, "`;`")?;
        Ok(Stmt::Ret { value, span })
    }

    /// raise expr; - throw to the innermost try handler. Lowers via
    /// macros::emit_raise. The handler restores rsp/rbp/pc; if no
    /// handler is installed the program exits with rax = 0xFF.
    fn parse_raise(&mut self) -> Result<Stmt, String> {
        let here = self.peek_tok().clone();
        let span = Span::new(here.line, here.col);
        self.advance();
        let value = self.parse_expr()?;
        self.expect(&Tok::Semi, "`;`")?;
        Ok(Stmt::Raise { value, span })
    }

    fn parse_try(&mut self) -> Result<Stmt, String> {
        self.advance();
        let body = self.parse_block()?;
        self.expect(&Tok::Catch, "`catch`")?;
        let err_name = self.eat_ident()?;
        let handler = self.parse_block()?;
        Ok(Stmt::Try { body, err_name, handler })
    }

    fn parse_asm(&mut self) -> Result<Stmt, String> {
        self.advance();   // consume `asm` keyword
        self.expect(&Tok::LBrace, "`{`")?;
        let mut lines: Vec<AsmLine> = Vec::new();
        let mut cur_line: u32 = 0;
        let mut cur_col:  u32 = 0;
        let mut buf = String::new();

        while !self.check(&Tok::RBrace) {
            // Detect end-of-statement: an explicit ; OR the next
            // token sits on a different source line than the
            // accumulated buffer (newline-implicit terminator).
            let here = self.peek_tok();
            let here_line = here.line;
            let here_col  = here.col;
            let new_line = !buf.is_empty() && here_line != cur_line;
            if new_line {
                flush_asm_buf(&mut buf, &mut lines, cur_line, cur_col)?;
            }

            if self.matches(&Tok::Semi) {
                flush_asm_buf(&mut buf, &mut lines, cur_line, cur_col)?;
                continue;
            }

            if buf.is_empty() {
                cur_line = here_line;
                cur_col  = here_col;
            }

            let t = self.advance();
            asm_append_token(&mut buf, &t);
        }
        flush_asm_buf(&mut buf, &mut lines, cur_line, cur_col)?;
        self.expect(&Tok::RBrace, "`}`")?;
        Ok(Stmt::Asm(lines))
    }

    fn parse_expr(&mut self)   -> Result<Expr, String> { self.parse_assign() }

    fn parse_assign(&mut self) -> Result<Expr, String> {
        let lhs = self.parse_or()?;
        if self.matches(&Tok::Assign) {
            let value = self.parse_assign()?;
            return match lhs {
                Expr::Var(name) => {
                    Ok(Expr::Assign { name, value: Box::new(value) })
                }
                Expr::Field { base, field } => {
                    Ok(Expr::FieldAssign { base, field, value: Box::new(value) })
                }
                // *ptr = value - deref-assignment. The unary * parsed
                // earlier shows up here as Unary { op: "*", operand };
                // pull out the operand and build a DerefAssign.
                Expr::Unary { op, operand } if op == "*" => {
                    Ok(Expr::DerefAssign { ptr: operand, value: Box::new(value) })
                }
                // buf[i] = value - indexed-assignment. The postfix [i]
                // parsed earlier shows up here as Index { base, index }.
                Expr::Index { base, index } => {
                    Ok(Expr::IndexAssign { base, index, value: Box::new(value) })
                }
                _ => Err("invalid assignment target".into()),
            };
        }
        Ok(lhs)
    }
    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_and()?;
        while self.matches(&Tok::OrOr) {
            let rhs = self.parse_and()?;
            lhs = Expr::Binary { op: "||".into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_bor()?;
        while self.matches(&Tok::AndAnd) {
            let rhs = self.parse_bor()?;
            lhs = Expr::Binary { op: "&&".into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_bor(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_bxor()?;
        while self.matches(&Tok::Pipe) {
            let rhs = self.parse_bxor()?;
            lhs = Expr::Binary { op: "|".into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_bxor(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_band()?;
        while self.matches(&Tok::Caret) {
            let rhs = self.parse_band()?;
            lhs = Expr::Binary { op: "^".into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_band(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_equality()?;
        // Binary & between two expressions is bitwise AND. Unary &expr
        // (address-of) is handled in parse_unary; the position disambiguates.
        while self.matches(&Tok::Amp) {
            let rhs = self.parse_equality()?;
            lhs = Expr::Binary { op: "&".into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_equality(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_comparison()?;
        loop {
            let op = if self.matches(&Tok::EqEq) { "==" }
                else if self.matches(&Tok::NotEq) { "!=" }
                else { break };
            let rhs = self.parse_comparison()?;
            lhs = Expr::Binary { op: op.into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_comparison(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_shift()?;
        loop {
            let op = if self.matches(&Tok::Lt) { "<" }
                else if self.matches(&Tok::Gt) { ">" }
                else if self.matches(&Tok::LtEq) { "<=" }
                else if self.matches(&Tok::GtEq) { ">=" }
                else { break };
            let rhs = self.parse_shift()?;
            lhs = Expr::Binary { op: op.into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_shift(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_addsub()?;
        loop {
            let op = if self.matches(&Tok::Shl) { "<<" }
                else if self.matches(&Tok::Shr) { ">>" }
                else { break };
            let rhs = self.parse_addsub()?;
            lhs = Expr::Binary { op: op.into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_addsub(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_muldiv()?;
        loop {
            let op = if self.matches(&Tok::Plus) { "+" }
                else if self.matches(&Tok::Minus) { "-" }
                else { break };
            let rhs = self.parse_muldiv()?;
            lhs = Expr::Binary { op: op.into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_muldiv(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = if self.matches(&Tok::Star) { "*" }
                else if self.matches(&Tok::Slash) { "/" }
                else if self.matches(&Tok::Percent) { "%" }
                else { break };
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary { op: op.into(), lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
    fn parse_unary(&mut self) -> Result<Expr, String> {
        if self.matches(&Tok::Minus) {
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary { op: "-".into(), operand: Box::new(inner) });
        }
        if self.matches(&Tok::Bang) {
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary { op: "!".into(), operand: Box::new(inner) });
        }
        if self.matches(&Tok::Tilde) {
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary { op: "~".into(), operand: Box::new(inner) });
        }
        // *expr - pointer dereference. Distinguished from multiplication
        // by position: at the start of a unary (no left operand pending),
        // * is always prefix-deref.
        if self.matches(&Tok::Star) {
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary { op: "*".into(), operand: Box::new(inner) });
        }
        // &expr - address-of.
        if self.matches(&Tok::Amp) {
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary { op: "&".into(), operand: Box::new(inner) });
        }
        self.parse_primary()
    }
    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek().clone() {
            Tok::Int(n)  => { self.advance(); Ok(Expr::Int(n)) }
            Tok::Str(s)  => { self.advance(); Ok(Expr::Str(s)) }
            Tok::True    => { self.advance(); Ok(Expr::Bool(true)) }
            Tok::False   => { self.advance(); Ok(Expr::Bool(false)) }
            Tok::Sizeof  => {
                self.advance();
                self.expect(&Tok::LParen, "`(` after `sizeof`")?;
                let ty = self.parse_type()?;
                self.expect(&Tok::RParen, "`)`")?;
                Ok(Expr::SizeOf { ty })
            }
            Tok::LParen  => {
                self.advance();
                if let Some(ty) = self.try_take_cast_type() {
                    self.expect(&Tok::RParen, "`)`")?;
                    let inner = self.parse_unary()?;
                    Ok(Expr::Cast { ty, expr: Box::new(inner) })
                } else {
                    let e = self.parse_expr()?;
                    self.expect(&Tok::RParen, "`)`")?;
                    // A parenthesised expression can still be the base of a
                    // field-access chain.
                    self.parse_field_chain(e)
                }
            }
            Tok::Str_ => {
                let here = self.peek_tok().clone();
                let span = Span::new(here.line, here.col);
                self.advance();
                if self.matches(&Tok::Dot) || self.matches(&Tok::Arrow) {
                    let second = self.eat_ident()?;
                    if self.matches(&Tok::LParen) {
                        let args = self.parse_call_args()?;
                        Ok(Expr::Call { ns: "str".into(), fname: second, args, span })
                    } else {
                        Err(format!(
                            "parse error at {}:{}: `str.{}` must be a call \
                             (e.g. `str.format(...)`)",
                            here.line, here.col, second
                        ))
                    }
                } else {
                    Err(format!(
                        "parse error at {}:{}: `str` is a type keyword, \
                         not a value - did you mean `str.format(...)`?",
                        here.line, here.col
                    ))
                }
            }
            Tok::Ident(first) => {
                let here = self.peek_tok().clone();
                let span = Span::new(here.line, here.col);
                self.advance();
                if self.type_names.contains(&first) && self.check(&Tok::LBrace) {
                    self.advance();   // consume `{`
                    let mut fields: Vec<(String, Expr)> = Vec::new();
                    while !self.check(&Tok::RBrace) {
                        let fname = self.eat_ident()?;
                        self.expect(&Tok::Colon, "`:`")?;
                        let fval = self.parse_expr()?;
                        fields.push((fname, fval));
                        if !self.matches(&Tok::Comma) { break; }
                    }
                    self.expect(&Tok::RBrace, "`}`")?;
                    return Ok(Expr::StructLit { ty: first, fields, span });
                }
                if self.matches(&Tok::Dot) || self.matches(&Tok::Arrow) {
                    let second = self.eat_ident()?;
                    if self.matches(&Tok::LParen) {
                        let args = self.parse_call_args()?;
                        Ok(Expr::Call { ns: first, fname: second, args, span })
                    } else {
                        let base = Expr::Var(first);
                        let init = Expr::Field { base: Box::new(base), field: second };
                        self.parse_field_chain(init)
                    }
                } else if self.matches(&Tok::LParen) {
                    // Local-function call: foo
                    let args = self.parse_call_args()?;
                    Ok(Expr::Call { ns: String::new(), fname: first, args, span })
                } else {
                    // Bare var; may have postfix field access.
                    self.parse_field_chain(Expr::Var(first))
                }
            }
            other => {
                let t = self.peek_tok();
                Err(format!("parse error at {}:{}: unexpected {:?}", t.line, t.col, other))
            }
        }
    }
}


fn flush_asm_buf(
    buf: &mut String,
    lines: &mut Vec<AsmLine>,
    line: u32,
    col:  u32,
) -> Result<(), String> {
    let s = buf.trim();
    if !s.is_empty() {
        let body: AsmBody = parse_asm_line(s)?;
        lines.push(AsmLine { line, col, body });
    }
    buf.clear();
    Ok(())
}

fn asm_append_token(buf: &mut String, t: &Tok) {
    let binds_left = matches!(t,
        Tok::RBrack | Tok::Colon | Tok::Comma
    );
    let prev_binds_right = buf.ends_with('%') || buf.ends_with('[');

    if !buf.is_empty() && !binds_left && !prev_binds_right {
        buf.push(' ');
    }
    match t {
        Tok::Ident(s) => buf.push_str(s),
        Tok::Int(n)   => {
            // Preserve hex form for big values so the asm-line
            // parser sees 0x12345 rather than a decimal blob.
            if (0..=0xFF).contains(n) {
                buf.push_str(&format!("0x{:x}", n));
            } else {
                buf.push_str(&n.to_string());
            }
        }
        Tok::Comma   => buf.push(','),
        Tok::Plus    => buf.push('+'),
        Tok::Minus   => buf.push('-'),
        Tok::Star    => buf.push('*'),
        Tok::Percent => buf.push('%'),
        Tok::LBrack  => buf.push('['),
        Tok::RBrack  => buf.push(']'),
        Tok::Colon   => buf.push(':'),
        Tok::Dot     => buf.push('.'),
        Tok::Ret  => buf.push_str("ret"),
        Tok::Asm  => buf.push_str("asm"),    // asm-as-ident rare; safe to pass through
        Tok::Int_ => buf.push_str("int"),
        // Anything else is a host-grammar token that has no
        // meaning inside asm - surface it so a typo doesn't get
        // silently dropped.
        other => buf.push_str(&format!("<?{:?}?>", other)),
    }
}
