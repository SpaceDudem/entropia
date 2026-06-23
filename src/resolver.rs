
use crate::encoder::{Cond, Encoder, Reg64};

// Baseline strings the resolver always needs.
const STR_KERNEL32: &str = "__rstr_kernel32";
const STR_LOADLIBRARYA: &str = "__rstr_LoadLibraryA";
const STR_GETPROCADDRESS: &str = "__rstr_GetProcAddress";

// Cached slots; shared.rs and friends can read these too.
pub const SLOT_LOADLIBRARYA: &str = "__rslot_LoadLibraryA";
pub const SLOT_GETPROCADDRESS: &str = "__rslot_GetProcAddress";
pub const SLOT_KERNEL32_BASE: &str = "__rslot_kernel32_base";

/// One Win32 import to resolve before main runs.
#[derive(Debug, Clone)]
pub struct Import {
    /// DLL name with extension, e.g. "user32.dll". Case-insensitive match.
    pub dll: String,
    pub func: String,
    /// Data label for the call [rip+slot] qword.
    pub slot: String,
}

/// Emit __resolve_imports + helpers, baseline strings, and cached slots.
pub fn emit(enc: &mut Encoder, imports: &[Import]) {
    emit_baseline_strings_and_slots(enc);
    emit_find_export(enc);
    emit_resolve_imports(enc, imports);
}

pub fn emit_with_user_resolver(enc: &mut Encoder, imports: &[Import], user_fn: &str) {
    use Reg64::*;
    enc.place_code_label("__resolve_imports");

    enc.push_r64(Rbp);
    enc.mov_r64_r64(Rbp, Rsp);
    enc.sub_r64_imm32(Rsp, 0x28);

    for imp in imports {
        let dll_label = dll_string_label(&imp.dll);
        let fn_label  = func_string_label(&imp.func);
        if !enc.data_has(&dll_label) { enc.add_string(&dll_label, &imp.dll); }
        if !enc.data_has(&fn_label)  { enc.add_string(&fn_label, &imp.func); }

        // Call user_fn.
        enc.lea_r64_data(Rcx, &dll_label);
        enc.lea_r64_data(Rdx, &fn_label);
        enc.call_label(user_fn);
        // Whatever they returned goes straight into the import slot -
        // a function pointer for normal DLLs, or an SSN packed in the
        // low 32 bits for ntdll exports when NtCall is also overridden.
        enc.mov_data_r64(&imp.slot, Rax);
    }

    enc.add_r64_imm32(Rsp, 0x28);
    enc.pop_r64(Rbp);
    enc.ret();
}

fn emit_baseline_strings_and_slots(enc: &mut Encoder) {
    if !enc.data_has(STR_KERNEL32)        { enc.add_string(STR_KERNEL32, "kernel32.dll"); }
    if !enc.data_has(STR_LOADLIBRARYA)    { enc.add_string(STR_LOADLIBRARYA, "LoadLibraryA"); }
    if !enc.data_has(STR_GETPROCADDRESS)  { enc.add_string(STR_GETPROCADDRESS, "GetProcAddress"); }
    if !enc.data_has(SLOT_LOADLIBRARYA)   { enc.add_bss(SLOT_LOADLIBRARYA, 8); }
    if !enc.data_has(SLOT_GETPROCADDRESS) { enc.add_bss(SLOT_GETPROCADDRESS, 8); }
    if !enc.data_has(SLOT_KERNEL32_BASE)  { enc.add_bss(SLOT_KERNEL32_BASE, 8); }
}

fn emit_find_export(enc: &mut Encoder) {
    use Reg64::*;
    enc.place_code_label("__find_export");

    // Prologue: save the few callee-saves we use as work registers.
    enc.push_r64(Rbp);
    enc.mov_r64_r64(Rbp, Rsp);
    enc.push_r64(Rbx);
    enc.push_r64(Rsi);
    enc.push_r64(Rdi);

    // rbx = module base (we'll lose rcx to inner strcmps), rdi = target name.
    enc.mov_r64_r64(Rbx, Rcx);
    enc.mov_r64_r64(Rdi, Rdx);

    // eax = [rbx + 0x3C]  -- e_lfanew
    enc.mov_r32_r64disp(Rax, Rbx, 0x3C);
    // Export directory RVA = [rbx + e_lfanew + 0x88].
    //   r8 = rbx + e_lfanew  (PE header)
    enc.lea_r64_base_idx(R8, Rbx, Rax);
    // r9 = [r8 + 0x88] (Export RVA)
    enc.mov_r32_r64disp(R9, R8, 0x88);
    enc.test_r64_r64(R9, R9);
    enc.jcc_label(Cond::Z, ".Lfe_notfound");

    // r8 = ExportDirectory absolute  = rbx + ExportRVA
    enc.lea_r64_base_idx(R8, Rbx, R9);

    // r9 = NumberOfNames           = [r8 + 0x18]
    enc.mov_r32_r64disp(R9, R8, 0x18);
    enc.test_r64_r64(R9, R9);
    enc.jcc_label(Cond::Z, ".Lfe_notfound");

    // r10 = AddressOfNames RVA     = [r8 + 0x20]; then r10 = rbx + r10
    enc.mov_r32_r64disp(R10, R8, 0x20);
    enc.lea_r64_base_idx(R10, Rbx, R10);

    // r11 = current index = 0
    enc.xor_r64_r64(R11, R11);

    // -- search loop -----------------------------------------------------
    enc.place_code_label(".Lfe_loop");
    enc.cmp_r64_r64(R11, R9);
    enc.jcc_label(Cond::Ge, ".Lfe_notfound");

    // rcx = name string ptr = rbx + [r10 + r11*4]
    enc.mov_r32_base_idx_scale4(Rcx, R10, R11);
    enc.lea_r64_base_idx(Rcx, Rbx, Rcx);

    enc.mov_r64_r64(Rsi, Rcx);
    enc.mov_r64_r64(Rax, Rdi);

    enc.place_code_label(".Lfe_cmpchar");
    enc.movzx_r64_byte_r64(Rcx, Rsi);
    enc.movzx_r64_byte_r64(Rdx, Rax);
    enc.cmp_r64_r64(Rcx, Rdx);
    enc.jcc_label(Cond::Ne, ".Lfe_nextidx");
    enc.test_r64_r64(Rcx, Rcx);
    enc.jcc_label(Cond::Z, ".Lfe_match");
    enc.inc_r64(Rsi);
    enc.inc_r64(Rax);
    enc.jmp_label(".Lfe_cmpchar");

    enc.place_code_label(".Lfe_nextidx");
    enc.inc_r64(R11);
    enc.jmp_label(".Lfe_loop");

    // Match: r11 holds the matching index. Use ordinal table to get fn index,
    // then function-RVA table to get the RVA, then add base.
    enc.place_code_label(".Lfe_match");
    // rcx = AddressOfNameOrdinals RVA = [r8 + 0x24];  to  rcx = rbx + rcx
    enc.mov_r32_r64disp(Rcx, R8, 0x24);
    enc.lea_r64_base_idx(Rcx, Rbx, Rcx);
    // rdx (function index) = movzx word [rcx + r11*2]
    enc.movzx_r64_word_base_idx_scale2(Rdx, Rcx, R11);

    // rcx = AddressOfFunctions RVA = [r8 + 0x1C];  to  rcx = rbx + rcx
    enc.mov_r32_r64disp(Rcx, R8, 0x1C);
    enc.lea_r64_base_idx(Rcx, Rbx, Rcx);
    // rax = dword [rcx + rdx*4]
    enc.mov_r32_base_idx_scale4(Rax, Rcx, Rdx);
    // rax = rbx + rax
    enc.lea_r64_base_idx(Rax, Rbx, Rax);
    enc.jmp_label(".Lfe_done");

    enc.place_code_label(".Lfe_notfound");
    enc.xor_r64_r64(Rax, Rax);

    enc.place_code_label(".Lfe_done");
    enc.pop_r64(Rdi);
    enc.pop_r64(Rsi);
    enc.pop_r64(Rbx);
    enc.pop_r64(Rbp);
    enc.ret();
}

fn emit_resolve_imports(enc: &mut Encoder, imports: &[Import]) {
    use Reg64::*;
    enc.place_code_label("__resolve_imports");

    // Frame: 1 + 7 pushes is odd-aligned; sub 0x28 (32 shadow + 8 pad)
    // restores 16-alignment for the LoadLibraryA call (otherwise ntdll's
    // movaps in RtlDosApplyFileIsolationRedirection AVs).
    enc.push_r64(Rbp);
    enc.mov_r64_r64(Rbp, Rsp);
    enc.push_r64(Rbx);
    enc.push_r64(Rsi);
    enc.push_r64(Rdi);
    enc.push_r64(R12);
    enc.push_r64(R13);
    enc.push_r64(R14);
    enc.push_r64(R15);
    enc.sub_r64_imm32(Rsp, 0x28);

    // PEB walk for kernel32.dll.
    enc.mov_rax_gs_qword(0x60);                  // rax = PEB
    enc.mov_r64_r64disp(Rax, Rax, 0x18);         // rax = PEB.Ldr
    enc.lea_r64_r64disp(R12, Rax, 0x20);         // r12 = &InMemoryOrderModuleList
    enc.mov_r64_r64disp(Rbx, R12, 0);            // rbx = head.Flink

    enc.place_code_label(".Lri_walk");
    enc.cmp_r64_r64(Rbx, R12);
    enc.jcc_label(Cond::Eq, ".Lri_fail");        // wrapped without a hit

    // UTF-16 BaseDllName vs ASCII "kernel32.dll", case-insensitive.
    enc.mov_r64_r64disp(R13, Rbx, 0x50);         // r13 = Buffer
    enc.movzx_r64_word_r64disp(R14, Rbx, 0x48);  // r14 = Length (bytes)
    enc.lea_r64_data(Rdi, STR_KERNEL32);

    emit_inline_unicode_ascii_ci_cmp(enc, Rdi, R13, R14);
    // rax = 1 if matched, 0 otherwise.
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Nz, ".Lri_found_k32");

    // next = current->Flink
    enc.mov_r64_r64disp(Rbx, Rbx, 0);
    enc.jmp_label(".Lri_walk");

    enc.place_code_label(".Lri_found_k32");
    enc.mov_r64_r64disp(R15, Rbx, 0x20);         // r15 = kernel32 DllBase
    enc.mov_data_r64(SLOT_KERNEL32_BASE, R15);

    enc.mov_r64_r64(Rcx, R15);
    enc.lea_r64_data(Rdx, STR_LOADLIBRARYA);
    enc.call_label("__find_export");
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Z, ".Lri_fail");
    enc.mov_data_r64(SLOT_LOADLIBRARYA, Rax);
    enc.mov_r64_r64(R13, Rax); // r13 = LoadLibraryA

    enc.mov_r64_r64(Rcx, R15);
    enc.lea_r64_data(Rdx, STR_GETPROCADDRESS);
    enc.call_label("__find_export");
    enc.test_r64_r64(Rax, Rax);
    enc.jcc_label(Cond::Z, ".Lri_fail");
    enc.mov_data_r64(SLOT_GETPROCADDRESS, Rax);
    enc.mov_r64_r64(R14, Rax); // r14 = GetProcAddress

    // Per-import resolution. r13 = LoadLibraryA, r14 = GetProcAddress.
    for (i, imp) in imports.iter().enumerate() {
        let dll_label = dll_string_label(&imp.dll);
        let fn_label = func_string_label(&imp.func);
        let skip_label = format!(".Lri_skip_{i}");

        if !enc.data_has(&dll_label)  { enc.add_string(&dll_label, &imp.dll); }
        if !enc.data_has(&fn_label)   { enc.add_string(&fn_label, &imp.func); }

        // rcx = dll name; call LoadLibraryA
        enc.lea_r64_data(Reg64::Rcx, &dll_label);
        enc.call_r64(R13);
        enc.test_r64_r64(Rax, Rax);
        enc.jcc_label(Cond::Z, &skip_label);

        // rcx = handle, rdx = fn name; call GetProcAddress
        enc.mov_r64_r64(Rcx, Rax);
        enc.lea_r64_data(Reg64::Rdx, &fn_label);
        enc.call_r64(R14);
        enc.mov_data_r64(&imp.slot, Rax);

        enc.place_code_label(&skip_label);
    }
    enc.jmp_label(".Lri_done");

    // Failure path: unresolved slots stay at 0; an indirect call to
    // them AVs cleanly. Skip the imports loop entirely.
    enc.place_code_label(".Lri_fail");

    enc.place_code_label(".Lri_done");
    enc.add_r64_imm32(Rsp, 0x28);
    enc.pop_r64(R15);
    enc.pop_r64(R14);
    enc.pop_r64(R13);
    enc.pop_r64(R12);
    enc.pop_r64(Rdi);
    enc.pop_r64(Rsi);
    enc.pop_r64(Rbx);
    enc.pop_r64(Rbp);
    enc.ret();
}

fn emit_inline_unicode_ascii_ci_cmp(
    enc: &mut Encoder,
    ascii_ptr: Reg64,
    wide_ptr: Reg64,
    wide_len_bytes: Reg64,
) {
    use Reg64::*;
    // Move into a stable scratch set: rax=ascii ptr walker, rdx=wide ptr walker,
    // rcx=remaining wide chars.
    enc.mov_r64_r64(Rax, ascii_ptr);
    enc.mov_r64_r64(Rdx, wide_ptr);
    // rcx = wide_len_bytes / 2  -- shift right by 1
    enc.mov_r64_r64(Rcx, wide_len_bytes);
    // sar/shr rcx, 1 - use raw bytes (REX.W D1 /5 = shr reg,1)
    enc.emit_raw(0x48); enc.emit_raw(0xD1); enc.emit_raw(0xE9);

    let unique = next_label_id();
    let l_loop = format!(".Lci_loop_{unique}");
    let l_done_count = format!(".Lci_done_count_{unique}");
    let l_mismatch = format!(".Lci_mismatch_{unique}");
    let l_match = format!(".Lci_match_{unique}");
    let l_end = format!(".Lci_end_{unique}");

    enc.place_code_label(&l_loop);
    enc.test_r64_r64(Rcx, Rcx);
    enc.jcc_label(Cond::Z, &l_done_count);

    // ASCII char (zero-extended)
    enc.movzx_r64_byte_r64(R8, Rax);
    enc.test_r64_r64(R8, R8);
    enc.jcc_label(Cond::Z, &l_mismatch); // ASCII ended early -> length mismatch

    // Wide char low byte (we don't bother checking the high byte; for DLL
    // names it's always 0). Same offset trick - read 16 bits via movzx word.
    enc.movzx_r64_word_r64disp(R9, Rdx, 0);

    // Lowercase both: if in 'A'..'Z' add 32.
    emit_to_lower(enc, R8);
    emit_to_lower(enc, R9);

    enc.cmp_r64_r64(R8, R9);
    enc.jcc_label(Cond::Ne, &l_mismatch);

    enc.inc_r64(Rax);
    enc.add_r64_imm8(Rdx, 2);
    enc.sub_r64_imm8(Rcx, 1);
    enc.jmp_label(&l_loop);

    // Wide is exhausted; ASCII must also be at its NUL terminator.
    enc.place_code_label(&l_done_count);
    enc.movzx_r64_byte_r64(R8, Rax);
    enc.test_r64_r64(R8, R8);
    enc.jcc_label(Cond::Z, &l_match);

    enc.place_code_label(&l_mismatch);
    enc.xor_r64_r64(Rax, Rax);
    enc.jmp_label(&l_end);

    enc.place_code_label(&l_match);
    enc.mov_r64_imm64(Rax, 1);

    enc.place_code_label(&l_end);
}

/// Emit: if reg in 'A'..'Z' { reg += 32 }
fn emit_to_lower(enc: &mut Encoder, reg: Reg64) {
    use Reg64::*;
    let unique = next_label_id();
    let l_skip = format!(".Ltl_skip_{unique}");

    enc.cmp_r64_imm32(reg, b'A' as i32);
    enc.jcc_label(Cond::Lt, &l_skip);
    enc.cmp_r64_imm32(reg, b'Z' as i32);
    enc.jcc_label(Cond::Gt, &l_skip);
    enc.add_r64_imm8(reg, 32);
    enc.place_code_label(&l_skip);
    let _ = Rax; // silence unused-import warning in this nested scope
}

fn next_label_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Stable label for the data section holding a DLL name string. We dedupe
/// per DLL so repeated imports from the same library share one string.
pub fn dll_string_label(dll: &str) -> String {
    format!("__rstr_dll_{}", sanitize(dll))
}

/// Stable label for a function-name string. Function names are not unique
/// across DLLs in principle (think CreateProcessW in both kernel32 and
/// kernelbase), so the slot label is per (dll, func) - see [slot_label].
pub fn func_string_label(func: &str) -> String {
    format!("__rstr_fn_{}", sanitize(func))
}

/// Data-section label for the qword slot a call site dereferences. Encodes
/// both DLL and function name so different DLLs exporting the same name
/// don't collide.
pub fn slot_label(dll: &str, func: &str) -> String {
    format!("FN_{}_{}", sanitize(dll), sanitize(func))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}
