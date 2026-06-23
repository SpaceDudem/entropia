
use crate::encoder::{Cond, Encoder, Reg64};
use crate::macros::GC_ALLOC_FN;

pub const HEAP_BASE:  &str = "__gc_heap";
pub const HEAP_NEXT:  &str = "__gc_next";
pub const HEAP_END:   &str = "__gc_end";
pub const FREELIST:   &str = "__gc_freelist";
pub const STACK_TOP:  &str = "__gc_stack_top";

/// Heap size in bytes. Embedded in the binary regardless of use.
pub const DEFAULT_HEAP_BYTES: usize = 4 * 1024;

// Header flag bits (low 3 bits of the size word).
const FLAG_MARK: i8 = 0b001;
const FLAG_FREE: i8 = 0b010;

// and r, -2 clears bit 0. free is never cleared in isolation - sweep
// rewrites the header wholesale.
const CLEAR_MARK_MASK: i8 = !FLAG_MARK;

pub fn emit_runtime(enc: &mut Encoder) {
    enc.add_bss(HEAP_NEXT,  8);                 // bump cursor
    enc.add_bss(HEAP_END,   8);                 // bump limit (heap + SIZE)
    enc.add_bss(FREELIST,   8);                 // head of free list (or 0)
    enc.add_bss(STACK_TOP,  8);                 // captured rsp from main
    enc.add_bss(HEAP_BASE,  DEFAULT_HEAP_BYTES);

    emit_init(enc);
    emit_alloc(enc);
    emit_try_alloc(enc);
    emit_collect(enc);
    emit_mark_range(enc);
}

// __gc_init: called once from main's prologue. Sets heap bounds and
// clears the freelist. __gc_stack_top is captured separately in main.
fn emit_init(enc: &mut Encoder) {
    enc.place_code_label("__gc_init");
    enc.lea_r64_data(Reg64::Rax, HEAP_BASE);
    enc.mov_data_r64(HEAP_NEXT, Reg64::Rax);
    enc.add_r64_imm32(Reg64::Rax, DEFAULT_HEAP_BYTES as i32);
    enc.mov_data_r64(HEAP_END, Reg64::Rax);
    enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
    enc.mov_data_r64(FREELIST, Reg64::Rax);
    enc.ret();
}

// __gc_alloc: public entry. Round + header, try, collect-and-retry on
// miss, 0 on OOM.
fn emit_alloc(enc: &mut Encoder) {
    enc.place_code_label(GC_ALLOC_FN);

    // rcx += 15 (round + header). add r, imm8 (4 bytes).
    enc.add_r64_imm32(Reg64::Rcx, 15);
    // rcx &= -8.
    enc.and_r64_imm8(Reg64::Rcx, -8);

    enc.call_label("__gc_try_alloc");
    enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
    enc.jcc_label(Cond::Nz, "__gc_alloc_done");

    // Collect-and-retry. Stack rcx because every scratch register is
    // clobbered by the collector. Push/pop runs only on the failure
    // path; success returns earlier with balanced stack.
    enc.push_r64(Reg64::Rcx);
    enc.call_label("__gc_collect");
    enc.pop_r64(Reg64::Rcx);
    enc.call_label("__gc_try_alloc");

    enc.place_code_label("__gc_alloc_done");
    enc.ret();
}

// __gc_try_alloc: first-fit over the freelist, fall through to bump,
// fall through to OOM. Caller passes rounded total (header included)
// in rcx. Returns user pointer (header+8) in rax, or 0.
fn emit_try_alloc(enc: &mut Encoder) {
    enc.place_code_label("__gc_try_alloc");

    // rax = freelist head; rdx = NULL (prev).
    enc.mov_r64_data(Reg64::Rax, FREELIST);
    enc.xor_r64_r64(Reg64::Rdx, Reg64::Rdx);

    enc.place_code_label("__gc_fl_loop");
    enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
    enc.jcc_label(Cond::Z, "__gc_try_bump");

    // r8 = header at [rax], r8 = size (flags masked off).
    enc.mov_r64_r64disp(Reg64::R8, Reg64::Rax, 0);
    enc.and_r64_imm8(Reg64::R8, -8);
    // Need at least rcx bytes? Unsigned compare.
    enc.cmp_r64_r64(Reg64::R8, Reg64::Rcx);
    enc.jcc_label(Cond::B, "__gc_fl_next");

    // Big enough. Unlink from free list. r9 = next-free pointer.
    enc.mov_r64_r64disp(Reg64::R9, Reg64::Rax, 8);
    enc.test_r64_r64(Reg64::Rdx, Reg64::Rdx);
    enc.jcc_label(Cond::Z, "__gc_fl_head");
    enc.mov_r64disp_r64(Reg64::Rdx, 8, Reg64::R9);
    enc.jmp_label("__gc_fl_use");
    enc.place_code_label("__gc_fl_head");
    enc.mov_data_r64(FREELIST, Reg64::R9);

    enc.place_code_label("__gc_fl_use");
    // Header = original block size, flag bits cleared. No split on
    // partial fit; accepts internal fragmentation for a smaller hot path.
    enc.mov_r64disp_r64(Reg64::Rax, 0, Reg64::R8);
    enc.add_r64_imm32(Reg64::Rax, 8);
    enc.ret();

    enc.place_code_label("__gc_fl_next");
    enc.mov_r64_r64(Reg64::Rdx, Reg64::Rax);
    enc.mov_r64_r64disp(Reg64::Rax, Reg64::Rax, 8);
    enc.jmp_label("__gc_fl_loop");

    enc.place_code_label("__gc_try_bump");
    enc.mov_r64_data(Reg64::Rax, HEAP_NEXT);
    enc.mov_r64_r64(Reg64::R9, Reg64::Rax);
    enc.add_r64_r64(Reg64::R9, Reg64::Rcx);
    enc.mov_r64_data(Reg64::R8, HEAP_END);
    enc.cmp_r64_r64(Reg64::R9, Reg64::R8);
    // ja: unsigned strictly above (heap_next + size > end  to  OOM).
    enc.jcc_label(Cond::A, "__gc_oom");
    enc.mov_data_r64(HEAP_NEXT, Reg64::R9);
    enc.mov_r64disp_r64(Reg64::Rax, 0, Reg64::Rcx);
    enc.add_r64_imm32(Reg64::Rax, 8);
    enc.ret();

    enc.place_code_label("__gc_oom");
    enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
    enc.ret();
}

fn emit_collect(enc: &mut Encoder) {
    enc.place_code_label("__gc_collect");

    // Save callee-saved registers (Win64 NV set).
    enc.push_r64(Reg64::Rbx);
    enc.push_r64(Reg64::Rbp);
    enc.push_r64(Reg64::Rdi);
    enc.push_r64(Reg64::Rsi);
    enc.push_r64(Reg64::R12);
    enc.push_r64(Reg64::R13);
    enc.push_r64(Reg64::R14);
    enc.push_r64(Reg64::R15);

    //   rax = current block, r8 = heap_next (one-past-last-block)
    enc.lea_r64_data(Reg64::Rax, HEAP_BASE);
    enc.mov_r64_data(Reg64::R8, HEAP_NEXT);

    enc.place_code_label("__gc_clear");
    enc.cmp_r64_r64(Reg64::Rax, Reg64::R8);
    enc.jcc_label(Cond::Ae, "__gc_mark_init");
    enc.mov_r64_r64disp(Reg64::Rcx, Reg64::Rax, 0);
    enc.mov_r64_r64(Reg64::Rdx, Reg64::Rcx);
    enc.and_r64_imm8(Reg64::Rdx, -8);                       // rdx = size
    enc.and_r64_imm8(Reg64::Rcx, CLEAR_MARK_MASK);          // clear mark
    enc.mov_r64disp_r64(Reg64::Rax, 0, Reg64::Rcx);
    enc.add_r64_r64(Reg64::Rax, Reg64::Rdx);
    enc.jmp_label("__gc_clear");

    enc.place_code_label("__gc_mark_init");
    enc.mov_r64_r64(Reg64::Rsi, Reg64::Rsp);
    enc.mov_r64_data(Reg64::Rdi, STACK_TOP);
    enc.call_label("__gc_mark_range");

    enc.place_code_label("__gc_transitive");
    enc.xor_r64_r64(Reg64::Rbx, Reg64::Rbx);                // change-count
    enc.lea_r64_data(Reg64::Rax, HEAP_BASE);

    enc.place_code_label("__gc_t_loop");
    enc.mov_r64_data(Reg64::R8, HEAP_NEXT);
    enc.cmp_r64_r64(Reg64::Rax, Reg64::R8);
    enc.jcc_label(Cond::Ae, "__gc_t_done");
    enc.mov_r64_r64disp(Reg64::Rcx, Reg64::Rax, 0);         // header
    enc.mov_r64_r64(Reg64::Rdx, Reg64::Rcx);
    enc.and_r64_imm8(Reg64::Rdx, -8);                       // rdx = size
    // Marked?
    enc.mov_r64_r64(Reg64::R9, Reg64::Rcx);
    enc.and_r64_imm8(Reg64::R9, FLAG_MARK);
    enc.test_r64_r64(Reg64::R9, Reg64::R9);
    enc.jcc_label(Cond::Z, "__gc_t_next");
    // Marked: scan payload [rax+8 .. rax+size).
    enc.push_r64(Reg64::Rax);
    enc.push_r64(Reg64::Rdx);
    enc.push_r64(Reg64::Rbx);
    enc.mov_r64_r64(Reg64::Rsi, Reg64::Rax);
    enc.add_r64_imm32(Reg64::Rsi, 8);
    enc.mov_r64_r64(Reg64::Rdi, Reg64::Rax);
    enc.add_r64_r64(Reg64::Rdi, Reg64::Rdx);
    enc.call_label("__gc_mark_range");                      // returns rax = #newly-marked
    enc.pop_r64(Reg64::Rbx);
    enc.add_r64_r64(Reg64::Rbx, Reg64::Rax);
    enc.pop_r64(Reg64::Rdx);
    enc.pop_r64(Reg64::Rax);

    enc.place_code_label("__gc_t_next");
    enc.add_r64_r64(Reg64::Rax, Reg64::Rdx);
    enc.jmp_label("__gc_t_loop");

    enc.place_code_label("__gc_t_done");
    enc.test_r64_r64(Reg64::Rbx, Reg64::Rbx);
    enc.jcc_label(Cond::Nz, "__gc_transitive");

    enc.lea_r64_data(Reg64::Rax, HEAP_BASE);
    enc.xor_r64_r64(Reg64::R11, Reg64::R11);                // new freelist head

    enc.place_code_label("__gc_sweep_loop");
    enc.mov_r64_data(Reg64::R8, HEAP_NEXT);
    enc.cmp_r64_r64(Reg64::Rax, Reg64::R8);
    enc.jcc_label(Cond::Ae, "__gc_sweep_done");
    enc.mov_r64_r64disp(Reg64::Rcx, Reg64::Rax, 0);
    enc.mov_r64_r64(Reg64::Rdx, Reg64::Rcx);
    enc.and_r64_imm8(Reg64::Rdx, -8);
    enc.mov_r64_r64(Reg64::R9, Reg64::Rcx);
    enc.and_r64_imm8(Reg64::R9, FLAG_MARK);
    enc.test_r64_r64(Reg64::R9, Reg64::R9);
    enc.jcc_label(Cond::Z, "__gc_sweep_free");
    // Marked: clear mark bit; keep allocated.
    enc.and_r64_imm8(Reg64::Rcx, CLEAR_MARK_MASK);
    enc.mov_r64disp_r64(Reg64::Rax, 0, Reg64::Rcx);
    enc.jmp_label("__gc_sweep_next");

    enc.place_code_label("__gc_sweep_free");
    // Unmarked: write size | FREE to header, link onto fresh freelist.
    enc.or_r64_imm8(Reg64::Rcx, FLAG_FREE);
    enc.mov_r64disp_r64(Reg64::Rax, 0, Reg64::Rcx);
    enc.mov_r64disp_r64(Reg64::Rax, 8, Reg64::R11);
    enc.mov_r64_r64(Reg64::R11, Reg64::Rax);

    enc.place_code_label("__gc_sweep_next");
    enc.add_r64_r64(Reg64::Rax, Reg64::Rdx);
    enc.jmp_label("__gc_sweep_loop");

    enc.place_code_label("__gc_sweep_done");
    enc.mov_data_r64(FREELIST, Reg64::R11);

    // Restore saved regs in reverse push order.
    enc.pop_r64(Reg64::R15);
    enc.pop_r64(Reg64::R14);
    enc.pop_r64(Reg64::R13);
    enc.pop_r64(Reg64::R12);
    enc.pop_r64(Reg64::Rsi);
    enc.pop_r64(Reg64::Rdi);
    enc.pop_r64(Reg64::Rbp);
    enc.pop_r64(Reg64::Rbx);
    enc.ret();
}

fn emit_mark_range(enc: &mut Encoder) {
    enc.place_code_label("__gc_mark_range");

    enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);                // counter
    // r10 = first valid user pointer (heap_base + 8)
    enc.lea_r64_data(Reg64::R10, HEAP_BASE);
    enc.add_r64_imm32(Reg64::R10, 8);
    // r11 = upper bound (heap_next)
    enc.mov_r64_data(Reg64::R11, HEAP_NEXT);

    enc.place_code_label("__gc_mr_loop");
    enc.cmp_r64_r64(Reg64::Rsi, Reg64::Rdi);
    enc.jcc_label(Cond::Ae, "__gc_mr_done");
    enc.mov_r64_r64disp(Reg64::Rcx, Reg64::Rsi, 0);         // potential ptr

    // In range?
    enc.cmp_r64_r64(Reg64::Rcx, Reg64::R10);
    enc.jcc_label(Cond::B, "__gc_mr_next");
    enc.cmp_r64_r64(Reg64::Rcx, Reg64::R11);
    enc.jcc_label(Cond::Ae, "__gc_mr_next");
    // Aligned?
    enc.mov_r64_r64(Reg64::R8, Reg64::Rcx);
    enc.and_r64_imm8(Reg64::R8, 7);
    enc.test_r64_r64(Reg64::R8, Reg64::R8);
    enc.jcc_label(Cond::Nz, "__gc_mr_next");
    // Treat (rcx - 8) as the block's header location.
    enc.add_r64_imm32(Reg64::Rcx, -8);
    enc.mov_r64_r64disp(Reg64::R8, Reg64::Rcx, 0);          // header
    // Already marked?
    enc.mov_r64_r64(Reg64::R9, Reg64::R8);
    enc.and_r64_imm8(Reg64::R9, FLAG_MARK);
    enc.test_r64_r64(Reg64::R9, Reg64::R9);
    enc.jcc_label(Cond::Nz, "__gc_mr_next");
    // Set mark bit and bump counter.
    enc.or_r64_imm8(Reg64::R8, FLAG_MARK);
    enc.mov_r64disp_r64(Reg64::Rcx, 0, Reg64::R8);
    enc.add_r64_imm32(Reg64::Rax, 1);

    enc.place_code_label("__gc_mr_next");
    enc.add_r64_imm32(Reg64::Rsi, 8);
    enc.jmp_label("__gc_mr_loop");

    enc.place_code_label("__gc_mr_done");
    enc.ret();
}
