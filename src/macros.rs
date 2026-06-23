// SPDX-License-Identifier: Apache-2.0
//! Lowering for high-level constructs (try/catch, mem.alloc).

use crate::encoder::{Cond, Encoder, Reg64};

pub const HANDLER_PC:  &str = "__handler_pc";
pub const HANDLER_RSP: &str = "__handler_rsp";
pub const HANDLER_RBP: &str = "__handler_rbp";

pub fn ensure_handler_slots(enc: &mut Encoder) {
    if !enc.data_has(HANDLER_PC) {
        enc.add_bss(HANDLER_PC,  8);
        enc.add_bss(HANDLER_RSP, 8);
        enc.add_bss(HANDLER_RBP, 8);
    }
}

/// Save (handler_pc, rsp, rbp) before the try body.
pub fn emit_try_prologue(enc: &mut Encoder, handler_label: &str) {
    ensure_handler_slots(enc);
    enc.lea_r64_code(Reg64::Rax, handler_label);
    enc.mov_data_r64(HANDLER_PC,  Reg64::Rax);
    enc.mov_data_r64(HANDLER_RSP, Reg64::Rsp);
    enc.mov_data_r64(HANDLER_RBP, Reg64::Rbp);
}

/// Clear handler PC after the body completes without raising.
pub fn emit_try_epilogue(enc: &mut Encoder) {
    enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
    enc.mov_data_r64(HANDLER_PC, Reg64::Rax);
}

pub fn emit_raise(enc: &mut Encoder, fail_label: &str) {
    ensure_handler_slots(enc);
    enc.mov_r64_data(Reg64::Rcx, HANDLER_PC);
    enc.test_r64_r64(Reg64::Rcx, Reg64::Rcx);
    enc.jcc_label(Cond::Z, fail_label);
    enc.mov_r64_data(Reg64::Rsp, HANDLER_RSP);
    enc.mov_r64_data(Reg64::Rbp, HANDLER_RBP);
    enc.jmp_r64(Reg64::Rcx);
    enc.place_code_label(fail_label);
    enc.mov_r64_imm64(Reg64::Rax, 0xFF);
    enc.ret();
}

// mem.alloc -> call __gc_alloc. Argument is already in rcx.
pub const GC_ALLOC_FN: &str = "__gc_alloc";

pub fn emit_gc_alloc_call(enc: &mut Encoder) {
    enc.call_label(GC_ALLOC_FN);
}
