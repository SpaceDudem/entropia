
use crate::encoder::{Cond, Encoder, Reg64};

/// Data-section slot holding the host services table pointer (qword).
pub const SLOT_HOST_SERVICES: &str = "__host_services";

/// Code labels for the runtime helpers.
pub const FN_GET: &str = "__shared_get";
pub const FN_PUT: &str = "__shared_put";

/// Byte offsets of each callable in the HostServices struct.
const OFF_GET: i32 = 0x00;
const OFF_PUT: i32 = 0x08;

/// Emit the slot and helper bodies. Safe to call exactly once per binary.
pub fn emit_runtime(enc: &mut Encoder) {
    if !enc.data_has(SLOT_HOST_SERVICES) {
        enc.add_bss(SLOT_HOST_SERVICES, 8);
    }
    emit_get(enc);
    emit_put(enc);
}

/// __shared_get -> ptr. rcx = name; rax = host's return (or 0).
fn emit_get(enc: &mut Encoder) {
    use Reg64::*;
    enc.place_code_label(FN_GET);
    enc.mov_r64_data(Rax, SLOT_HOST_SERVICES);
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Z, ".Lsg_nohost");
    enc.mov_r64_r64disp(Rax, Rax, OFF_GET);
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Z, ".Lsg_nohost");
    // Tail-call. rcx already holds name; caller reserved shadow space.
    enc.jmp_r64(Rax);

    enc.place_code_label(".Lsg_nohost");
    enc.xor_r64_r64(Rax, Rax);
    enc.ret();
}

/// __shared_put -> ok. rcx/rdx = name/ptr; rax = host's
/// return (0 if no host).
fn emit_put(enc: &mut Encoder) {
    use Reg64::*;
    enc.place_code_label(FN_PUT);
    enc.mov_r64_data(Rax, SLOT_HOST_SERVICES);
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Z, ".Lsp_nohost");
    enc.mov_r64_r64disp(Rax, Rax, OFF_PUT);
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Z, ".Lsp_nohost");
    enc.jmp_r64(Rax);

    enc.place_code_label(".Lsp_nohost");
    enc.xor_r64_r64(Rax, Rax);
    enc.ret();
}
