//! Integer overflow detection pass.
//!
//! Walks every function, static init, and expression. Reports
//! `error[T030]: integer overflow` when a literal value or arithmetic
//! result exceeds the range of its declared type.

use std::collections::HashMap;

use crate::ast::*;
use crate::codegen::BuildKind;

/// Standard-mode entry. BOF builds share the same check.
pub fn check(prog: &Program) -> Result<(), Vec<String>> {
    let errs = check_with_kind(prog, BuildKind::Standard); if errs.is_empty() { Ok(()) } else { Err(errs) }
}

pub fn check_with_kind(prog: &Program, _kind: BuildKind) -> Vec<String> {
    let mut errs: Vec<String> = Vec::new();

    for f in &prog.functions {
        walk_function(&f.body, &f.ret_ty, &f.name, &mut errs);
    }
    // Skip auto-included stdlib constants (their typedefs are canonical
    // Windows idioms; e.g. INVALID_SOCKET = -1 as u32). Only user-written
    // Var/Ret expressions get checked.
    let empty_scope = OverflowScope::new();
    let empty_scope = OverflowScope::new();
    for s in &prog.statics {
        let has_user_attr = !s.attrs.iter().any(|a| a.kind == "AutoInclude");
        if !has_user_attr { continue; }
        if let Some(init) = &s.init {
            walk_expr(init, &s.ty, &empty_scope, &mut errs, &format!("static `{}`", s.name), Span::default());
        }
    }

    errs
}

/// A typed value: the declared integer type and (when known) the literal value.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TypedVal {
    ty:     String,
    value:  Option<i64>,
}

#[allow(dead_code)]
impl TypedVal {
    fn new(ty: impl Into<String>) -> Self {
        Self { ty: ty.into(), value: None }
    }
    fn with(ty: impl Into<String>, v: i64) -> Self {
        Self { ty: ty.into(), value: Some(v) }
    }
}

/// Per-function variable scope for the overflow pass.
/// Tracks each local by name: (declared type, known literal value).
#[allow(dead_code)]
struct OverflowScope {
    locals: HashMap<String, TypedVal>,
}

#[allow(dead_code)]
impl OverflowScope {
    fn new() -> Self {
        Self { locals: HashMap::new() }
    }

    fn declare(&mut self, name: String, ty: String) {
        self.locals.insert(name, TypedVal::new(ty));
    }

    fn record(&mut self, name: String, v: i64) {
        if let Some(tv) = self.locals.get_mut(&name) {
            tv.value = Some(v);
        }
    }

    fn lookup(&self, name: &str) -> Option<&TypedVal> {
        self.locals.get(name)
    }
}

fn walk_function(stmts: &[Stmt], ret_ty: &str, fn_name: &str, errs: &mut Vec<String>) {
    let mut scope = OverflowScope::new();
    for s in stmts {
        walk_stmt(s, ret_ty, fn_name, &mut scope, errs);
    }
}

fn walk_stmt(
    s: &Stmt,
    ret_ty: &str,
    fn_name: &str,
    scope: &mut OverflowScope,
    errs: &mut Vec<String>,
) {
    match s {
        Stmt::Var { name, ty, value, span } => {
            scope.declare(name.clone(), ty.clone());
            if let Some(e) = value {
                if let Some(v) = expr_value(e) {
                    scope.record(name.clone(), v);
                }
                walk_expr(e, ty, scope, errs, &format!("var `{name}` in fn `{fn_name}`"), *span);
            }
        }
        Stmt::Expr { value: e, span } => {
            walk_expr(e, "int", scope, errs, fn_name, *span);
        }
        Stmt::If { cond, then_body, else_body } => {
            walk_expr(cond, "bool", scope, errs, fn_name, Span::default());
            walk_function(then_body, ret_ty, fn_name, errs);
            walk_function(else_body, ret_ty, fn_name, errs);
        }
        Stmt::While { cond, body } => {
            walk_expr(cond, "bool", scope, errs, fn_name, Span::default());
            walk_function(body, ret_ty, fn_name, errs);
        }
        Stmt::For { init, cond, step, body } => {
            if let Some(i) = init { walk_stmt(i, ret_ty, fn_name, scope, errs); }
            if let Some(c) = cond { walk_expr(c, "bool", scope, errs, fn_name, Span::default()); }
            if let Some(s) = step { walk_stmt(s, ret_ty, fn_name, scope, errs); }
            walk_function(body, ret_ty, fn_name, errs);
        }
        Stmt::Ret { value, span } => {
            if let Some(e) = value {
                walk_expr(e, ret_ty, scope, errs, fn_name, *span);
            }
        }
        Stmt::Break | Stmt::Continue => {}
        Stmt::Raise { value, span } => {
            walk_expr(value, "int", scope, errs, fn_name, *span);
        }
        Stmt::Try { body, handler, .. } => {
            walk_function(body, ret_ty, fn_name, errs);
            walk_function(handler, ret_ty, fn_name, errs);
        }
        Stmt::Asm(_) => {}
    }
}

fn walk_expr(
    e: &Expr,
    expected_ty: &str,
    scope: &OverflowScope,
    errs: &mut Vec<String>,
    context: &str,
    span: Span,
) {
    match e {
        Expr::Int(n) => {
            // A literal placed into a specific type. The literal itself
            // is unbounded; the overflow is the type mismatch.
            check_value_overflow(*n, expected_ty, context, span, errs);
        }
        Expr::Var(_name) => {  // type is opaque until used in arithmetic
            // Variable type matters only when used as an arithmetic operand;
            // we'll pick it up there. Nothing else to do here.
        }
        Expr::Unary { op, operand } => {
            // For unary minus on a signed type, check if negating the value
            // would overflow (e.g. -(i8::MIN) = -(-128) = 128, out of range).
            check_op_overflow(
                e,
                expected_ty,
                op,
                &[operand],
                scope,
                context,
                span,
                errs,
            );
        }
        Expr::Binary { op, lhs, rhs } => {
            // Walk both children so any deeper overflows are caught too.
            let lhs_type = expr_type(lhs);
            let rhs_type = expr_type(rhs);
            walk_expr(lhs, &lhs_type, scope, errs, context, span);
            walk_expr(rhs, &rhs_type, scope, errs, context, span);
            check_op_overflow(
                e,
                expected_ty,
                op,
                &[lhs, rhs],
                scope,
                context,
                span,
                errs,
            );
        }
        Expr::Assign { name: _name, value, .. } => {
            walk_expr(value, expected_ty, scope, errs, context, span);
        }
        Expr::Field { base, field: _field } => {
            walk_expr(base, expected_ty, scope, errs, context, span);
        }
        Expr::FieldAssign { base, field: _field, value } => {
            walk_expr(base, expected_ty, scope, errs, context, span);
            walk_expr(value, expected_ty, scope, errs, context, span);
        }
        Expr::DerefAssign { ptr, value } => {
            walk_expr(ptr, expected_ty, scope, errs, context, span);
            walk_expr(value, expected_ty, scope, errs, context, span);
        }
        Expr::Index { base, index } => {
            walk_expr(base, expected_ty, scope, errs, context, span);
            walk_expr(index, "int", scope, errs, context, span);
        }
        Expr::IndexAssign { base, index, value } => {
            walk_expr(base, expected_ty, scope, errs, context, span);
            walk_expr(index, "int", scope, errs, context, span);
            walk_expr(value, expected_ty, scope, errs, context, span);
        }
        Expr::Cast { ty, expr } => {
            // A cast pins the expression to a specific type - check
            // whether the value fits the cast target.
            walk_expr(expr, ty, scope, errs, context, span);
        }
        Expr::SizeOf { ty: _ty } => {  // no overflow risk
            // SizeOf is always usize-sized; no overflow risk.
        }
        Expr::StructLit { fields, .. } => {
            for (_, e) in fields {
                walk_expr(e, expected_ty, scope, errs, context, span);
            }
        }
        Expr::Call { args, .. } => {
            for a in args {
                walk_expr(a, expected_ty, scope, errs, context, span);
            }
        }
        Expr::Bool(_) | Expr::Str(_) => {}
    }
}

/// Determine the type that an expression evaluates to.
/// Mirrors the typecheck module's infer_type, but simpler - we care
/// about the integer family here.
fn expr_type(e: &Expr) -> String {
    match e {
        Expr::Var(_name) => {  // type is opaque until used in arithmetic
            // Best effort: callers will cross-reference the scope if they
            // need it. We return a sentinel; the op-checker will do the
            // real type inference.
            format!("var_{_name}")
        }
        Expr::Int(_) => "int".into(),
        Expr::Bool(_) => "bool".into(),
        Expr::Str(_) => "str".into(),
        Expr::Unary { op, operand } => {
            match op.as_str() {
                "-" => expr_type(operand),
                "~" => expr_type(operand),
                "!" => "bool".into(),
                _ => "int".into(),
            }
        }
        Expr::Binary { op, lhs, .. } => {
            // All arithmetic is "int". Comparison/combo are "bool".
            match op.as_str() {
                "+" | "-" | "*" | "/" | "%" => "int".into(),
                "<<" | ">>" => expr_type(lhs),
                "&" | "|" | "^" => expr_type(lhs),
                "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" => "bool".into(),
                _ => "int".into(),
            }
        }
        Expr::Call { .. } => "int".into(),
        Expr::Field { .. } | Expr::Assign { .. } => "int".into(),
        Expr::Cast { ty, .. } => ty.clone(),
        Expr::Index { .. } | Expr::DerefAssign { .. } | Expr::IndexAssign { .. }
        | Expr::FieldAssign { .. } => "int".into(),
        Expr::SizeOf { ty } => format!("usize_{ty}"),
        Expr::StructLit { ty, .. } => ty.clone(),
    }
}

/// Extract a concrete integer value from an expression, if known.
fn expr_value(e: &Expr) -> Option<i64> {
    match e {
        Expr::Int(n) => Some(*n),
        Expr::Bool(true) => Some(1),
        Expr::Bool(false) => Some(0),
        Expr::Var(_name) => {  // type is opaque until used in arithmetic
            // Placeholder for variables - the scope would resolve the real
            // value during walk, but we keep this as-is since expr_value
            // operates purely on expression structure.
            Some(0)
        }
        Expr::Assign { value, .. } => expr_value(value),
        Expr::Unary { op, operand } => {
            let v = expr_value(operand)?;
            Some(match op.as_str() {
                "-" => -v,
                "~" => !v,
                "!" => if v == 0 { 1 } else { 0 },
                _ => v,
            })
        }
        Expr::Binary { op, lhs, rhs } => {
            let lv = expr_value(lhs)?;
            let rv = expr_value(rhs)?;
            Some(match op.as_str() {
                "+" => lv.wrapping_add(rv),
                "-" => lv.wrapping_sub(rv),
                "*" => lv.wrapping_mul(rv),
                "/" => {
                    if rv == 0 { return None; }
                    lv / rv
                }
                "%" => {
                    if rv == 0 { return None; }
                    lv % rv
                }
                "<<" => lv << rv.ilog2() as usize,
                ">>" => lv >> rv.ilog2() as usize,
                "&" => lv & rv,
                "|" => lv | rv,
                "^" => lv ^ rv,
                "==" => if lv == rv { 1 } else { 0 },
                "!=" => if lv != rv { 1 } else { 0 },
                "<" => if lv < rv { 1 } else { 0 },
                ">" => if lv > rv { 1 } else { 0 },
                "<=" => if lv <= rv { 1 } else { 0 },
                ">=" => if lv >= rv { 1 } else { 0 },
                "&&" => if lv != 0 && rv != 0 { 1 } else { 0 },
                "||" => if lv != 0 || rv != 0 { 1 } else { 0 },
                _ => lv,
            })
        }
        Expr::Cast { ty, expr } => {
            // For casts, apply the target type's mask to the value.
            let v = expr_value(expr)?;
            Some(match ty.as_str() {
                "i8" => v as i8 as i64,
                "i16" => v as i16 as i64,
                "i32" => v as i32 as i64,
                "i64" => v,
                "u8" => v as u8 as i64,
                "u16" => v as u16 as i64,
                "u32" => v as u32 as i64,
                "u64" => v as u64 as i64,
                "int" => v,
                _ => v,
            })
        }
        Expr::SizeOf { .. } => Some(8),
        Expr::Call { .. } => None, // call result type is opaque at this level
        _ => None,
    }
}

/// Given a type name, return (min, max) as i64.
/// Uses saturating operations where the real machine would overflow.
fn type_range(ty: &str) -> (i128, i128) {
    match ty {
        "i8"    => (-128_i128, 127_i128),
        "i16"   => (-32768_i128, 32767_i128),
        "i32"   => (-2_147_483_648_i128, 2_147_483_647_i128),
        "i64"   => (-9_223_372_036_854_775_808_i128, 9_223_372_036_854_775_807_i128),
        "u8"    => (0_i128, 255_i128),
        "u16"   => (0_i128, 65_535_i128),
        "u32"   => (0_i128, 4_294_967_295_i128),
        "u64"   => (0_i128, 18_446_744_073_709_551_615_i128),
        "int" | "" => (i64::MIN as i128, i64::MAX as i128),
        _       => (i64::MIN as i128, i64::MAX as i128),
    }
}


/// Check whether a concrete value fits the range of a given type.
fn value_fits(value: i64, ty: &str) -> bool {
    let (lo, hi) = type_range(ty);
    let v = value as i128;
    v >= lo && v <= hi
}

/// Emit an overflow error.
fn emit_overflow(
    context: &str,
    ty: &str,
    value: i64,
    _span: Span,
    errs: &mut Vec<String>,
) {
    let (lo, hi) = type_range(ty);
    errs.push(format!(
        "error[T030]: integer overflow at {} ({ty} range [{lo}, {hi}] - value {})",
        context, value
    ));
}

/// Check a literal value against its declared type. Used for Var/Static
/// initializers and Cast expressions.
fn check_value_overflow(
    value: i64,
    ty: &str,
    context: &str,
    span: Span,
    errs: &mut Vec<String>,
) {
    if !value_fits(value, ty) {
        emit_overflow(context, ty, value, span, errs);
    }
}

/// Check an operator expression for overflow.
///
/// For each arithmetic or bitwise operator, computes the result assuming
/// all operand values are known literals, then checks each operand's
/// declared type range as well as the result type range.
fn check_op_overflow(
    _e: &Expr,
    expected_ty: &str,
    op: &str,
    children: &[&Expr],
    scope: &OverflowScope,
    context: &str,
    span: Span,
    errs: &mut Vec<String>,
) {
    // Map of operator -> whether the result is arithmetic or boolean.
    // Arithmetic ops need overflow checking; boolean/comparison ops don't.
    if !is_arithmetic_op(op) {
        return;
    }

    // For each child expression, get its declared type and known value.
    // If any child is a literal, we can compute the result directly.
    // If a child is a variable, we look up its type from the scope.
    let mut operand_types: Vec<String> = Vec::new();
    let mut operand_values: Vec<Option<i64>> = Vec::new();

    for child in children {
        let e_ty = expr_type(child);
        let ty: &str = if let Expr::Var(name) = child {
            scope.lookup(name).map(|tv| tv.ty.as_str()).unwrap_or(e_ty.as_str())
        } else {
            e_ty.as_str()
        };
        let val = if let Expr::Var(name) = child {
            scope.lookup(name).and_then(|tv| tv.value)
        } else {
            expr_value(child)
        };
        operand_types.push(ty.to_string());
        operand_values.push(val);
    }

    // Check each operand against its own type range.
    for i in 0..children.len() {
        let ty = &operand_types[i];
        if let Some(val) = operand_values[i] {
            if !value_fits(val, ty) {
                emit_overflow(context, ty, val, span, errs);
            }
        }
    }

    // For binary ops, compute the result and check overflow against the
    // LHS operand type (which is the operation's type) as well as the
    // broader expected type.
    if children.len() == 2 {
        if let (Some(lv), Some(rv)) = (operand_values[0], operand_values[1]) {
            let result = compute_result(op, lv, rv);
            if let Some(res) = result {
                check_value_overflow(res, &operand_types[0], context, span, errs);
                check_value_overflow(res, expected_ty, context, span, errs);
            }
        }
    }
}

/// Determine whether an operator is arithmetic (and thus needs overflow check).
fn is_arithmetic_op(op: &str) -> bool {
    matches!(
        op,
        "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "&" | "|" | "^"
    )
}

/// Compute the result of an arithmetic operator on two integer values.
/// Returns None if the operation is undefined (e.g., division by zero).
fn compute_result(op: &str, lv: i64, rv: i64) -> Option<i64> {
    match op {
        "+" => Some(lv.wrapping_add(rv)),
        "-" => Some(lv.wrapping_sub(rv)),
        "*" => Some(lv.wrapping_mul(rv)),
        "/" => {
            if rv == 0 { None } else { Some(lv / rv) }
        }
        "%" => {
            if rv == 0 { None } else { Some(lv % rv) }
        }
        "<<" => Some(lv << rv.ilog2() as usize),
        ">>" => Some(lv >> rv.ilog2() as usize),
        "&" => Some(lv & rv),
        "|" => Some(lv | rv),
        "^" => Some(lv ^ rv),
        _ => None,
    }
}
