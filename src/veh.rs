
use crate::encoder::{Cond, Encoder, Reg64};

pub const VEH_FN: &str = "__opsec_veh_handler";

/// Handle returned by AddVectoredExceptionHandler. Stored so we can
/// remove the handler at exit.
pub const VEH_HANDLE_SLOT: &str = "__opsec_veh_handle";

// EXCEPTION_POINTERS / EXCEPTION_RECORD / CONTEXT offsets (x64, stable
// since Vista). See winnt.h.
const EP_EXCEPTION_RECORD: i32 = 0x00;
const EP_CONTEXT_RECORD:   i32 = 0x08;
const ER_EXCEPTION_CODE:   i32 = 0x00;
const CTX_RAX:             i32 = 0x78;
const CTX_RSP:             i32 = 0x98;
const CTX_RBP:             i32 = 0xA0;
const CTX_RIP:             i32 = 0xF8;

pub fn ensure_veh_slot(enc: &mut Encoder) {
    if !enc.data_has(VEH_HANDLE_SLOT) {
        enc.add_bss(VEH_HANDLE_SLOT, 8);
    }
}

pub fn emit_veh_handler(enc: &mut Encoder) {
    use Reg64::*;
    use crate::macros::{HANDLER_PC, HANDLER_RSP, HANDLER_RBP};

    enc.place_code_label(VEH_FN);

    enc.mov_r64_data(Rax, HANDLER_PC);
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Z, ".LVEH_NOT_HANDLED");

    enc.mov_r64_r64disp(Rdx, Rcx, EP_CONTEXT_RECORD);
    enc.mov_r64disp_r64(Rdx, CTX_RIP, Rax);

    enc.mov_r64_data(Rax, HANDLER_RSP);
    enc.mov_r64disp_r64(Rdx, CTX_RSP, Rax);

    enc.mov_r64_data(Rax, HANDLER_RBP);
    enc.mov_r64disp_r64(Rdx, CTX_RBP, Rax);

    // ExceptionCode -> Context->Rax.
    enc.mov_r64_r64disp(Rcx, Rcx, EP_EXCEPTION_RECORD);
    enc.mov_r32_r64disp(Rcx, Rcx, ER_EXCEPTION_CODE);
    enc.mov_r64disp_r64(Rdx, CTX_RAX, Rcx);

    enc.xor_r64_r64(Rax, Rax);
    enc.mov_data_r64(HANDLER_PC, Rax);

    enc.mov_r64_imm64(Rax, 0xFFFF_FFFF_FFFF_FFFF);
    enc.ret();

    enc.place_code_label(".LVEH_NOT_HANDLED");
    enc.xor_r64_r64(Rax, Rax);
    enc.ret();
}
