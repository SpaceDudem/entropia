
use std::collections::HashSet;

use crate::ast::*;
use crate::codegen::BuildKind;

/// Standard-mode entry. BOF builds use eliminate_with_kind so the
/// seed is go instead of main.
#[allow(dead_code)]
pub fn eliminate(prog: &mut Program) {
    eliminate_with_kind(prog, BuildKind::Standard)
}

pub fn eliminate_with_kind(prog: &mut Program, kind: BuildKind) {
    let mut ctx = Ctx::default();

    let entry = kind.entry_name();
    if prog.functions.iter().any(|f| f.name == entry && !f.is_extern) {
        ctx.fns.insert(entry.to_string());
    } else {
        return;
    }
    for f in &prog.functions {
        for a in &f.attrs {
            if a.kind == "Override" || a.kind == "Hook" || a.kind == "Stage" {
                ctx.fns.insert(f.name.clone());
            }
        }
    }

    // Mark-and-sweep until the live set stops growing.
    loop {
        let snapshot = (ctx.fns.len(), ctx.statics.len(), ctx.structs.len());

        for f in &prog.functions {
            if ctx.fns.contains(&f.name) {
                ctx.mark_function(f);
            }
        }
        for s in &prog.statics {
            if ctx.statics.contains(&s.name) {
                ctx.mark_type(&s.ty);
                if let Some(init) = &s.init {
                    ctx.mark_expr(init);
                }
            }
        }
        for s in &prog.structs {
            if ctx.structs.contains(&s.name) {
                for (_, fty) in &s.fields {
                    ctx.mark_type(fty);
                }
            }
        }

        if (ctx.fns.len(), ctx.statics.len(), ctx.structs.len()) == snapshot {
            break;
        }
    }

    // Sweep: keep only marked items.
    prog.functions.retain(|f| ctx.fns.contains(&f.name));
    prog.statics.retain(|s| ctx.statics.contains(&s.name));
    prog.structs.retain(|s| ctx.structs.contains(&s.name));
}

#[derive(Default)]
struct Ctx {
    fns:     HashSet<String>,
    statics: HashSet<String>,
    structs: HashSet<String>,
}

impl Ctx {
    /// Strip [N] and * suffixes; mark the bare name as a live struct.
    /// Sweep ignores names that don't correspond to a real struct, so
    /// spurious marks are harmless.
    fn mark_type(&mut self, ty: &str) {
        let mut key = ty;
        if let Some(open) = key.rfind('[') {
            if key.ends_with(']') {
                key = &key[..open];
            }
        }
        let key = key.trim_end_matches('*');
        if !key.is_empty() {
            self.structs.insert(key.to_string());
        }
    }

    fn mark_function(&mut self, f: &Function) {
        for p in &f.params {
            self.mark_type(&p.ty);
        }
        self.mark_type(&f.ret_ty);
        self.mark_block(&f.body);
    }

    fn mark_block(&mut self, stmts: &[Stmt]) {
        for s in stmts {
            self.mark_stmt(s);
        }
    }

    fn mark_stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Var { ty, value, .. } => {
                self.mark_type(ty);
                if let Some(e) = value { self.mark_expr(e); }
            }
            Stmt::Expr { value: e, .. } => self.mark_expr(e),
            Stmt::If { cond, then_body, else_body } => {
                self.mark_expr(cond);
                self.mark_block(then_body);
                self.mark_block(else_body);
            }
            Stmt::While { cond, body } => {
                self.mark_expr(cond);
                self.mark_block(body);
            }
            Stmt::For { init, cond, step, body } => {
                if let Some(i) = init { self.mark_stmt(i); }
                if let Some(c) = cond { self.mark_expr(c); }
                if let Some(s) = step { self.mark_stmt(s); }
                self.mark_block(body);
            }
            Stmt::Ret { value: Some(e), .. } => self.mark_expr(e),
            Stmt::Raise { value, .. } => self.mark_expr(value),
            Stmt::Try { body, handler, .. } => {
                self.mark_block(body);
                self.mark_block(handler);
            }
            Stmt::Ret { value: None, .. } | Stmt::Break | Stmt::Continue => {}
            Stmt::Asm(lines) => {
                // Inline-asm %name operands reference functions / statics
                // outside the Expr tree. Mark conservatively across both
                // kinds; sweep filters spurious entries.
                use crate::asm::{AsmBody, AsmOperand, AsmMem, AsmMemBase};
                fn walk_operand(op: &AsmOperand, ctx: &mut Ctx) {
                    match op {
                        AsmOperand::Sym(name) => {
                            ctx.fns.insert(name.clone());
                            ctx.statics.insert(name.clone());
                        }
                        AsmOperand::Mem(AsmMem { base: Some(AsmMemBase::Sym(name)), .. }) => {
                            ctx.fns.insert(name.clone());
                            ctx.statics.insert(name.clone());
                        }
                        _ => {}
                    }
                }
                for line in lines {
                    match &line.body {
                        AsmBody::Op1 { op, .. } => walk_operand(op, self),
                        AsmBody::Op2 { dst, src, .. } => {
                            walk_operand(dst, self);
                            walk_operand(src, self);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn mark_expr(&mut self, e: &Expr) {
        match e {
            Expr::Var(name) => {
                // Mark as both - could be a static, a local, or a
                // function name used as a code pointer.
                self.statics.insert(name.clone());
                self.fns.insert(name.clone());
            }
            Expr::Call { ns, fname, args, .. } => {
                // Only empty-namespace (local) calls need marking;
                // Win32 and intrinsics resolve at codegen.
                if ns.is_empty() {
                    self.fns.insert(fname.clone());
                }
                for a in args { self.mark_expr(a); }
            }
            Expr::Assign { value, .. } => self.mark_expr(value),
            Expr::Unary { operand, .. } => self.mark_expr(operand),
            Expr::Binary { lhs, rhs, .. } => {
                self.mark_expr(lhs);
                self.mark_expr(rhs);
            }
            Expr::Field { base, .. } => self.mark_expr(base),
            Expr::FieldAssign { base, value, .. } => {
                self.mark_expr(base);
                self.mark_expr(value);
            }
            Expr::DerefAssign { ptr, value } => {
                self.mark_expr(ptr);
                self.mark_expr(value);
            }
            Expr::Index { base, index } => {
                self.mark_expr(base);
                self.mark_expr(index);
            }
            Expr::IndexAssign { base, index, value } => {
                self.mark_expr(base);
                self.mark_expr(index);
                self.mark_expr(value);
            }
            Expr::Cast { ty, expr } => {
                self.mark_type(ty);
                self.mark_expr(expr);
            }
            Expr::SizeOf { ty } => self.mark_type(ty),
            Expr::StructLit { ty, fields, .. } => {
                self.mark_type(ty);
                for (_, e) in fields { self.mark_expr(e); }
            }
            Expr::Int(_) | Expr::Bool(_) | Expr::Str(_) => {}
        }
    }
}
