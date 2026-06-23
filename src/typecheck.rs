
use crate::ast::*;
use crate::codegen::BuildKind;
use std::collections::HashMap;

pub fn check(prog: &Program) -> Result<(), Vec<String>> {
    check_with_kind(prog, BuildKind::Standard)
}

pub fn check_with_kind(prog: &Program, kind: BuildKind) -> Result<(), Vec<String>> {
    let mut errs: Vec<String> = Vec::new();
    let ctx = build_context(prog);

    let entry = kind.entry_name();
    let entry_fn = prog.functions.iter().find(|f| f.name == entry);
    match (kind, entry_fn) {
        (_, None) => errs.push(format!(
            "error[T020]: missing entry point `{entry}` for --type={}",
            match kind {
                BuildKind::Standard => "standard",
                BuildKind::Bof      => "bof",
                BuildKind::Coff     => "coff",
            }
        )),
        (BuildKind::Bof | BuildKind::Coff, Some(f)) => {
            let ret_ok = matches!(f.ret_ty.as_str(), "void" | "" | "int");
            let arity_ok = f.params.len() == 2;
            let args_ok = arity_ok
                && (f.params[0].ty == "char*" || f.params[0].ty == "u8*" || f.params[0].ty == "void*")
                && (f.params[1].ty == "int"   || f.params[1].ty == "i32" || f.params[1].ty == "u32" || f.params[1].ty == "i64" || f.params[1].ty == "u64");
            if !(ret_ok && args_ok) {
                errs.push(format!(
                    "error[T021]: BOF entry `go` must have signature \
                     `fn go(args: char*, len: int) -> void` (got `fn {}({}) -> {}`)",
                    f.name,
                    f.params.iter()
                        .map(|p| format!("{}: {}", p.name, p.ty))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if f.ret_ty.is_empty() { "void" } else { &f.ret_ty },
                ));
            }
        }
        _ => {}
    }

    for f in &prog.functions {
        let mut scope = Scope::new(&ctx);
        // Seed scope with parameter types so Var infers correctly.
        for p in &f.params {
            // Parameters are "declared" at the function header. We don't
            // have a per-param span yet - Span::default (unknown) lets
            // T010 still cite "(parameter)" if the user shadows one.
            scope.locals.insert(p.name.clone(), (p.ty.clone(), Span::default()));
        }
        check_block(&f.body, &f.ret_ty, &f.name, &mut scope, &mut errs);
    }
    // Static initialisers run in main's prologue but are placed in module scope -
    // walk them with an empty local scope so undefined Var references
    // would surface as "unknown" types (silent today; future T-rule).
    let mut empty = Scope::new(&ctx);
    for s in &prog.statics {
        if let Some(init) = &s.init {
            check_expr(init, Span::default(), &mut empty, &mut errs);
            // Treat the static as a top-level "var" for T003.
            check_assignment_compat(&s.ty, init, &mut empty,
                                    &format!("static `{}`", s.name),
                                    Span::default(), &mut errs);
        }
    }

    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

// Context built once per program - function signatures, struct layouts.

struct Context<'a> {
    /// name -> (param types, return type) for every locally-defined fn.
    fns: HashMap<String, (&'a [Param], String)>,
    /// name -> declared field list for every struct (in declaration order).
    structs: HashMap<String, &'a [(String, String)]>,
    /// name -> declared type for every module-level static.
    statics: HashMap<String, String>,
}

fn build_context(prog: &Program) -> Context<'_> {
    let mut fns = HashMap::with_capacity(prog.functions.len());
    for f in &prog.functions {
        fns.insert(f.name.clone(), (f.params.as_slice(), f.ret_ty.clone()));
    }
    let mut structs = HashMap::with_capacity(prog.structs.len());
    for s in &prog.structs {
        structs.entry(s.name.clone()).or_insert(s.fields.as_slice());
    }
    let mut statics = HashMap::with_capacity(prog.statics.len());
    for s in &prog.statics {
        statics.entry(s.name.clone()).or_insert(s.ty.clone());
    }
    Context { fns, structs, statics }
}

// Walking scope for local-variable type tracking.

struct Scope<'a> {
    ctx: &'a Context<'a>,
    locals: HashMap<String, (String, Span)>,
}

impl<'a> Scope<'a> {
    fn new(ctx: &'a Context<'a>) -> Self { Self { ctx, locals: HashMap::new() } }

    /// Look up a name's declared type. Searches locals first, then module
    /// statics, then declared functions (as first-class code pointers).
    /// Returns None when the name is unbound - that's T012.
    fn lookup_type(&self, name: &str) -> Option<&str> {
        self.locals.get(name).map(|(t, _)| t.as_str())
            .or_else(|| self.ctx.statics.get(name).map(String::as_str))
            .or_else(|| if self.ctx.fns.contains_key(name) { Some("u64") } else { None })
    }
}

// Statement walker.

fn check_block(stmts: &[Stmt], ret_ty: &str, fn_name: &str,
               scope: &mut Scope, errs: &mut Vec<String>) {
    let mut unreachable_reported = false;   // one T011 per block, not per dead stmt
    let mut after_terminator     = false;
    for s in stmts {
        if after_terminator && !unreachable_reported {
            let span = stmt_span(s);
            errs.push(format!(
                "error[T011] at {span}: unreachable code - the previous \
                 statement always exits the block (via `ret`, `break`, \
                 or `continue`)"
            ));
            unreachable_reported = true;
        }
        check_stmt(s, ret_ty, fn_name, scope, errs);
        if is_terminator(s) { after_terminator = true; }
    }
}

fn is_terminator(s: &Stmt) -> bool {
    matches!(s, Stmt::Ret { .. } | Stmt::Break | Stmt::Continue | Stmt::Raise { .. })
}

/// Best-effort span for any statement. Span::default when the stmt
/// variant doesn't carry a span yet - error message degrades gracefully
/// to <unknown> rather than fabricating a position.
fn stmt_span(s: &Stmt) -> Span {
    match s {
        Stmt::Var { span, .. } | Stmt::Ret { span, .. }
        | Stmt::Raise { span, .. } => *span,
        Stmt::Expr { span, value } => {
            if !span.is_unknown() { *span }
            else if let Expr::Call { span: cspan, .. } = value { *cspan }
            else { Span::default() }
        }
        _ => Span::default(),
    }
}

fn check_stmt(s: &Stmt, ret_ty: &str, fn_name: &str,
              scope: &mut Scope, errs: &mut Vec<String>) {
    match s {
        Stmt::Var { name, ty, value, span } => {
            if let Some((_, prev)) = scope.locals.get(name) {
                let origin = if prev.is_unknown() { "(parameter)".into() }
                             else                  { format!("{prev}") };
                errs.push(format!(
                    "error[T010] at {span}: variable `{name}` is already \
                     declared in this scope at {origin}. EntropyKit doesn't \
                     have block scoping for `var` - every declaration is \
                     visible for the rest of the function."
                ));
            }
            // var x: void = ...; is meaningless - void exists only
            // as a return type (no value) and as a pointee for void*.
            if ty == "void" {
                errs.push(format!(
                    "error[T022] at {span}: cannot declare `{name}` with type `void` - \
                     `void` is a return-only type. Use `void*` for opaque pointers \
                     or pick a concrete type."
                ));
            }
            // The initialiser sees the OLD binding for name (so the
            // self-reference idiom var x: int = x + 1; reads the prior
            // x); the new binding goes in only after the RHS is checked.
            if let Some(v) = value {
                check_expr(v, *span, scope, errs);
                check_assignment_compat(ty, v, scope,
                                        &format!("var `{name}`"), *span, errs);
            }
            scope.locals.insert(name.clone(), (ty.clone(), *span));
        }
        Stmt::Expr { value: e, .. } => check_expr(e, stmt_span(s), scope, errs),
        Stmt::Ret { value, span } => {
            match (ret_ty, value.as_ref()) {
                ("void", Some(_)) => errs.push(format!(
                    "error[T023] at {span}: `fn {fn_name}() -> void` may not \
                     return a value. Use a bare `ret;` to exit early."
                )),
                (rt, None) if rt != "void" && !rt.is_empty() => {
                }
                _ => {}
            }
            if let Some(e) = value {
                check_expr(e, *span, scope, errs);
                check_assignment_compat(ret_ty, e, scope,
                                        &format!("return value of `{fn_name}`"),
                                        *span, errs);
            }
        }
        Stmt::Break | Stmt::Continue | Stmt::Asm(_) => {}
        Stmt::Raise { value, span } => {
            check_expr(value, *span, scope, errs);
        }
        Stmt::If { cond, then_body, else_body } => {
            check_expr(cond, Span::default(), scope, errs);
            check_block(then_body, ret_ty, fn_name, scope, errs);
            check_block(else_body, ret_ty, fn_name, scope, errs);
        }
        Stmt::While { cond, body } => {
            check_expr(cond, Span::default(), scope, errs);
            check_block(body, ret_ty, fn_name, scope, errs);
        }
        Stmt::For { init, cond, step, body } => {
            if let Some(i) = init { check_stmt(i, ret_ty, fn_name, scope, errs); }
            if let Some(c) = cond { check_expr(c, Span::default(), scope, errs); }
            if let Some(st) = step { check_stmt(st, ret_ty, fn_name, scope, errs); }
            check_block(body, ret_ty, fn_name, scope, errs);
        }
        Stmt::Try { body, err_name, handler } => {
            check_block(body, ret_ty, fn_name, scope, errs);
            // err is bound inside the handler as an int sentinel today.
            scope.locals.insert(err_name.clone(), ("int".into(), Span::default()));
            check_block(handler, ret_ty, fn_name, scope, errs);
        }
    }
}

// Expression walker - collects T001/T002/T005/T006.

fn check_expr(e: &Expr, stmt_span: Span, scope: &mut Scope, errs: &mut Vec<String>) {
    match e {
        Expr::Int(_) | Expr::Str(_) | Expr::Bool(_) | Expr::SizeOf { .. } => {}
        Expr::Var(name) => {
            if scope.lookup_type(name).is_none() {
                errs.push(format!(
                    "error[T012] at {stmt_span}: use of undeclared variable \
                     `{name}`. Declare it with `var {name}: <type> = ...;` \
                     before this line, or check the spelling."
                ));
            }
        }
        Expr::Assign { name, value }      => {
            // Assignment to a name has the same "must exist" requirement
            // as reading it. Walking the RHS first matches source order
            // for diagnostics.
            check_expr(value, stmt_span, scope, errs);
            if scope.lookup_type(name).is_none() {
                errs.push(format!(
                    "error[T012] at {stmt_span}: assignment to undeclared \
                     variable `{name}`. Declare it with `var {name}: \
                     <type>;` first."
                ));
            }
        }
        Expr::Unary  { operand, .. }      => check_expr(operand, stmt_span, scope, errs),
        Expr::Binary { op, lhs, rhs }     => {
            check_expr(lhs, stmt_span, scope, errs);
            check_expr(rhs, stmt_span, scope, errs);
            check_string_in_arith(op, lhs, rhs, errs);
        }
        Expr::Field  { base, .. }         => check_expr(base, stmt_span, scope, errs),
        Expr::FieldAssign { base, field, value } => {
            check_expr(base, stmt_span, scope, errs);
            check_expr(value, stmt_span, scope, errs);
            check_field_assign(base, field, value, scope, errs);
        }
        Expr::DerefAssign { ptr, value }  => {
            check_expr(ptr, stmt_span, scope, errs);
            check_expr(value, stmt_span, scope, errs);
        }
        Expr::Cast   { expr, .. }         => check_expr(expr, stmt_span, scope, errs),
        Expr::Index  { base, index }      => {
            check_expr(base, stmt_span, scope, errs);
            check_expr(index, stmt_span, scope, errs);
        }
        Expr::IndexAssign { base, index, value } => {
            check_expr(base, stmt_span, scope, errs);
            check_expr(index, stmt_span, scope, errs);
            check_expr(value, stmt_span, scope, errs);
        }
        Expr::Call { ns, fname, args, span } => {
            for a in args { check_expr(a, *span, scope, errs); }
            check_call(ns, fname, args, *span, scope, errs);
        }
        Expr::StructLit { ty, fields, span } => {
            for (_, e) in fields { check_expr(e, *span, scope, errs); }
            let Some(decl) = scope.ctx.structs.get(ty.as_str()) else {
                errs.push(format!(
                    "error[T013] at {span}: struct literal references undeclared \
                     type `{ty}`"
                ));
                return;
            };
            for (fname, value) in fields {
                let Some((_, fty)) = decl.iter().find(|(n, _)| n == fname) else {
                    errs.push(format!(
                        "error[T013] at {span}: struct `{ty}` has no field `{fname}`"
                    ));
                    continue;
                };
                check_assignment_compat(fty, value, scope,
                    &format!("field `{ty}.{fname}`"), *span, errs);
            }
        }
    }
}

// Per-rule checkers.

fn check_call(ns: &str, fname: &str, args: &[Expr], span: Span,
              scope: &mut Scope, errs: &mut Vec<String>) {
    if !ns.is_empty() { return; }
    if scope.locals.contains_key(fname) || scope.ctx.statics.contains_key(fname) {
        return;
    }
    let Some((params, _ret_ty)) = scope.ctx.fns.get(fname) else {
        errs.push(format!(
            "error[T001] at {span}: call to undefined function `{fname}` - \
             no `fn {fname}(...)` is declared in this program. \
             Did you mean to namespace it (e.g. `User32.{fname}` for Win32 \
             or `mem.{fname}` for a memory intrinsic)?"
        ));
        return;
    };
    if params.len() != args.len() {
        errs.push(format!(
            "error[T002] at {span}: `{fname}` expects {} argument{} but got {}",
            params.len(),
            if params.len() == 1 { "" } else { "s" },
            args.len(),
        ));
        return;
    }
    // T005 (general mismatch) / T009 (pointer-pointee specifically) -
    // per-argument type compatibility.
    for (i, (param, arg)) in params.iter().zip(args.iter()).enumerate() {
        let arg_ty = infer_type(arg, scope);
        match compat(&param.ty, &arg_ty, arg) {
            Compat::Ok => {}
            Compat::Mismatch => errs.push(format!(
                "error[T005] at {span}: arg {} of `{fname}` - \
                 parameter `{}` is declared `{}` but got `{}`",
                i + 1, param.name, param.ty, display_type(&arg_ty),
            )),
            Compat::PointerPointeeMismatch => errs.push(format!(
                "error[T009] at {span}: arg {} of `{fname}` - \
                 parameter `{}` is `{}` but the argument is `{}`. \
                 Add an explicit cast (`({})arg`) if the reinterpretation \
                 is intentional.",
                i + 1, param.name, param.ty, display_type(&arg_ty), param.ty,
            )),
        }
    }
}

fn check_assignment_compat(target_ty: &str, value: &Expr, scope: &Scope,
                           ctx_label: &str, span: Span, errs: &mut Vec<String>) {
    let value_ty = infer_type(value, scope);
    match compat(target_ty, &value_ty, value) {
        Compat::Ok => {}
        Compat::Mismatch => {
            // Pick T003 for var / static initialisers, T004 for return values,
            // based on the label the caller passed in. Keep the code stable
            // per-rule so suppression instructions remain meaningful.
            let code = if ctx_label.starts_with("return value") { "T004" } else { "T003" };
            errs.push(format!(
                "error[{code}] at {span}: {ctx_label} is declared `{target_ty}` \
                 but the value has type `{}`",
                display_type(&value_ty),
            ));
        }
        Compat::PointerPointeeMismatch => errs.push(format!(
            "error[T009] at {span}: {ctx_label} is `{target_ty}` but the value \
             is `{}`. Add an explicit cast (`({})value`) if the \
             reinterpretation is intentional.",
            display_type(&value_ty), target_ty,
        )),
    }
}

fn check_field_assign(base: &Expr, field: &str, value: &Expr,
                      scope: &Scope, errs: &mut Vec<String>) {
    let base_ty = infer_type(base, scope);
    let struct_name = base_ty.trim_end_matches('*');
    let Some(fields) = scope.ctx.structs.get(struct_name) else { return; };
    let Some((_, field_ty)) = fields.iter().find(|(n, _)| n == field) else { return; };
    let value_ty = infer_type(value, scope);
    match compat(field_ty, &value_ty, value) {
        Compat::Ok => {}
        Compat::Mismatch => errs.push(format!(
            "error[T008]: field `{struct_name}.{field}` is declared `{field_ty}` \
             but the assigned value has type `{}`",
            display_type(&value_ty),
        )),
        Compat::PointerPointeeMismatch => errs.push(format!(
            "error[T009]: field `{struct_name}.{field}` is `{field_ty}` \
             but the assigned value is `{}`. Add an explicit cast \
             (`({})value`) if the reinterpretation is intentional.",
            display_type(&value_ty), field_ty,
        )),
    }
}

/// T006 - 1 + "hello" and friends.
fn check_string_in_arith(op: &str, lhs: &Expr, rhs: &Expr, errs: &mut Vec<String>) {
    // Bitwise + arithmetic ops that don't make sense for strings.
    let is_arith = matches!(op,
        "+" | "-" | "*" | "/" | "%" |
        "&" | "|" | "^" | "<<" | ">>");
    if !is_arith { return; }
    if let Some(s) = string_literal(lhs).or_else(|| string_literal(rhs)) {
        errs.push(format!(
            "error[T006]: string literal {:?} used as an operand of `{op}` - \
             EntropyKit doesn't define `{op}` on strings. Use `(u64)\"...\"` \
             to take the literal's pointer if you really want pointer math.",
            truncate(s, 24),
        ));
    }
}

fn string_literal(e: &Expr) -> Option<&str> {
    match e {
        Expr::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max]) }
}

// Type inference - minimal, string-based. Returns "?" when we honestly
// don't know (avoids false positives downstream).

fn infer_type(e: &Expr, scope: &Scope) -> String {
    match e {
        Expr::Int(_)         => "int".into(),
        Expr::Str(_)         => "str".into(),
        Expr::Bool(_)        => "bool".into(),
        Expr::SizeOf { .. }  => "u64".into(),
        Expr::Cast { ty, .. } => ty.clone(),
        Expr::Var(name) => {
            scope.lookup_type(name).map(str::to_string).unwrap_or_else(|| "?".into())
        }
        Expr::Field { base, field } => {
            let base_ty = infer_type(base, scope);
            // T* field access auto-derefs; collapse to T for lookup.
            let lookup = base_ty.trim_end_matches('*');
            scope.ctx.structs.get(lookup)
                .and_then(|fields| fields.iter().find(|(n, _)| n == field).map(|(_, t)| t.clone()))
                .unwrap_or_else(|| "?".into())
        }
        Expr::Index { base, .. } => {
            let t = infer_type(base, scope);
            element_type(&t).unwrap_or_else(|| "?".into())
        }
        Expr::Unary { op, operand } => {
            match op.as_str() {
                "*" => {
                    let t = infer_type(operand, scope);
                    pointee(&t).unwrap_or_else(|| "?".into())
                }
                "&" => format!("{}*", infer_type(operand, scope)),
                "-" | "~" => "int".into(),
                "!" => "bool".into(),
                _ => "?".into(),
            }
        }
        Expr::Binary { op, .. } => {
            match op {
                op if matches!(op.as_str(),
                    "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||") => "bool".into(),
                _ => "int".into(),
            }
        }
        Expr::Call { ns, fname, .. } => infer_call_type(ns, fname, scope),
        // Assignments are statements at the source level but expressions
        // at the AST level - they evaluate to the assigned value's type.
        Expr::Assign { value, .. }            => infer_type(value, scope),
        Expr::FieldAssign { value, .. }       => infer_type(value, scope),
        Expr::DerefAssign { value, .. }       => infer_type(value, scope),
        Expr::IndexAssign { value, .. }       => infer_type(value, scope),
        Expr::StructLit { ty, .. }            => ty.clone(),
    }
}

fn infer_call_type(ns: &str, fname: &str, scope: &Scope) -> String {
    if ns.is_empty() {
        return scope.ctx.fns.get(fname).map(|(_, r)| r.clone())
            .unwrap_or_else(|| "?".into());
    }
    match (ns, fname) {
        ("mem", "alloc") => "u64".into(),
        ("mem", "set") | ("mem", "zero") | ("mem", "copy") => "u64".into(),
        ("mem", "cmp")   => "int".into(),
        ("mem", "collect") => "int".into(),
        ("shared", "get") => "u64".into(),
        ("shared", "put") => "int".into(),
        ("str", "format") => "str".into(),
        // Anything else with a non-empty namespace is a Win32 import.
        // Treat as a generic 64-bit handle/pointer - caller can cast for
        // pointee-typed use.
        _ => "u64".into(),
    }
}

fn element_type(ty: &str) -> Option<String> {
    if let Some(t) = ty.strip_suffix(']') {
        if let Some(idx) = t.rfind('[') {
            return Some(t[..idx].to_string());
        }
    }
    pointee(ty)
}

fn pointee(ty: &str) -> Option<String> {
    ty.strip_suffix('*').map(|s| s.to_string())
}


#[derive(PartialEq, Eq)]
enum Compat {
    Ok,
    /// Different type families altogether (str vs int, struct vs pointer).
    Mismatch,
    /// Both sides are pointers / arrays but the pointee types differ.
    PointerPointeeMismatch,
}

fn compat(target: &str, source: &str, source_expr: &Expr) -> Compat {
    // Unknown source  to  don't fire false positives. As the inferer learns
    // more, this fallback shrinks naturally.
    if source == "?" || target == "?" { return Compat::Ok; }
    if target == source { return Compat::Ok; }

    // Integer literal 0 is the universal null - assignable to any pointer.
    if matches!(source_expr, Expr::Int(0)) && is_pointer(target) { return Compat::Ok; }

    // An explicit (T)expr cast is the user saying "trust me, treat this
    // as a T." Stop further checking - the cast is the type-system escape
    // hatch by design. If they wrote it wrong, that's their problem.
    if matches!(source_expr, Expr::Cast { .. }) { return Compat::Ok; }

    let tf = family(target);
    let sf = family(source);

    if tf == sf {
        if tf == Family::Pointer {
            if pointee_eq(target, source) { Compat::Ok }
            else { Compat::PointerPointeeMismatch }
        } else {
            Compat::Ok
        }
    } else if matches!((tf, sf), (Family::Int, Family::Pointer) | (Family::Pointer, Family::Int)) {
        // Pointer  <->  integer interchange is still permitted at the slot
        // level (both are 8 bytes). This is the boundary that bytes
        // will tighten in a future rule.
        Compat::Ok
    } else {
        Compat::Mismatch
    }
}

/// True when two pointer/array types denote the same element type. Strips
/// one level of * or [N] from each side, then compares.
fn pointee_eq(a: &str, b: &str) -> bool {
    let ap = element_type(a).unwrap_or_default();
    let bp = element_type(b).unwrap_or_default();
    !ap.is_empty() && ap == bp
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Family { Int, Bool, Str, Pointer, Struct, Void }

fn family(ty: &str) -> Family {
    if ty == "void" { return Family::Void; }
    if is_pointer(ty) { return Family::Pointer; }
    match ty {
        "int" | "u64" | "i64" | "u32" | "i32" | "u16" | "i16" | "u8" | "i8" => Family::Int,
        "bool" => Family::Bool,
        "str" | "wstr" => Family::Str,
        _ if ty.contains('[') => Family::Pointer,   // array decays to pointer
        _ => Family::Struct,                         // assume user-defined struct
    }
}

fn is_pointer(ty: &str) -> bool { ty.ends_with('*') || ty.contains('[') }

/// Display-friendly wrapper that turns the internal "?" sentinel into a
/// less alarming "unknown" so error messages don't leak the sentinel.
fn display_type(ty: &str) -> String {
    if ty == "?" { "<unknown>".into() }
    else         { ty.to_string() }
}

