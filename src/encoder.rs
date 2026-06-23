
use std::collections::HashMap;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg64 {
    Rax = 0, Rcx = 1, Rdx = 2, Rbx = 3,
    Rsp = 4, Rbp = 5, Rsi = 6, Rdi = 7,
    R8  = 8, R9  = 9, R10 =10, R11 =11,
    R12 =12, R13 =13, R14 =14, R15 =15,
}

impl Reg64 {
    pub fn lo3(self) -> u8 { (self as u8) & 0b111 }
    pub fn ext(self) -> bool { (self as u8) & 0b1000 != 0 }

    pub fn from_name(s: &str) -> Option<Self> {
        use Reg64::*;
        Some(match s {
            "rax" => Rax, "rcx" => Rcx, "rdx" => Rdx, "rbx" => Rbx,
            "rsp" => Rsp, "rbp" => Rbp, "rsi" => Rsi, "rdi" => Rdi,
            "r8"  => R8,  "r9"  => R9,  "r10" => R10, "r11" => R11,
            "r12" => R12, "r13" => R13, "r14" => R14, "r15" => R15,
            _ => return None,
        })
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Cond {
    Eq, Ne, Lt, Gt, Le, Ge, Z, Nz,
    /// Unsigned below (CF=1) - for cmp ptr, lower_bound; jb out_of_range.
    B,
    /// Unsigned below-or-equal (CF=1 ∨ ZF=1).
    Be,
    /// Unsigned above (CF=0 ∧ ZF=0) - for cmp new_next, end; ja oom.
    A,
    /// Unsigned above-or-equal (CF=0) - for sweep loop termination.
    Ae,
    /// Sign flag set (SF=1).
    S,
    /// Sign flag clear (SF=0).
    Ns,
}

impl Cond {
    /// Returns the low nibble that follows 0x0F 8_ for jcc rel32,
    /// 0x0F 9_ for setcc, and 0x0F 4_ for cmovcc. The encoding scheme
    /// is the same low-nibble across all three opcode families.
    pub fn nibble(self) -> u8 {
        match self {
            Cond::Z  | Cond::Eq => 0x4,
            Cond::Nz | Cond::Ne => 0x5,
            Cond::B  => 0x2,
            Cond::Ae => 0x3,
            Cond::Be => 0x6,
            Cond::A  => 0x7,
            Cond::S  => 0x8,
            Cond::Ns => 0x9,
            Cond::Lt => 0xC,
            Cond::Ge => 0xD,
            Cond::Le => 0xE,
            Cond::Gt => 0xF,
        }
    }
}

/// Segment-override prefix (0x64 = FS, 0x65 = GS). Only FS/GS matter
/// in user mode on x86-64; CS/DS/ES/SS are flat. GS points at the TEB.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    Fs,
    Gs,
}

impl Segment {
    fn prefix(self) -> u8 {
        match self { Segment::Fs => 0x64, Segment::Gs => 0x65 }
    }
}

/// Where a rel32 should point.
#[derive(Debug, Clone)]
pub enum RelocTarget {
    Code(String),  // a code-section label
    Data(String),
    External(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSection { Rdata, Data, Bss }

#[derive(Debug, Clone)]
pub struct Reloc {
    pub patch_at: usize,
    pub target:   RelocTarget,
}

#[derive(Debug, Clone)]
pub struct DbgMark {
    pub code_off: usize,
    pub line:     u32,
    pub col:      u32,
    pub kind:     &'static str,
}

#[derive(Debug, Clone)]
pub struct DbgVar {
    pub name:       String,
    pub ty:         String,
    pub loc:        String,
    pub line_start: u32,
    pub line_end:   u32,
}

pub struct Encoder {
    pub code: Vec<u8>,
    /// Read-only initialised data - string literals, format templates,
    /// DLL names. Lands in .rdata for BOF mode; flattened into the
    /// standard [code | rdata | data | bss] blob for shellcode mode.
    pub rdata: Vec<u8>,
    pub data: Vec<u8>,
    /// Uninitialised (zero-filled) data - import slots, format
    /// buffers, static slots. Carries a size only; the bytes are
    /// materialised at load time.
    pub bss_size: usize,
    code_labels:   HashMap<String, usize>,
    rdata_labels:  HashMap<String, usize>,
    data_labels:   HashMap<String, usize>,
    bss_labels:    HashMap<String, usize>,
    relocs:      Vec<Reloc>,
    pub dbg_marks: Vec<DbgMark>,
    pub dbg_vars:  Vec<DbgVar>,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            rdata: Vec::new(),
            data: Vec::new(),
            bss_size: 0,
            code_labels:  HashMap::new(),
            rdata_labels: HashMap::new(),
            data_labels:  HashMap::new(),
            bss_labels:   HashMap::new(),
            relocs: Vec::new(),
            dbg_marks: Vec::new(),
            dbg_vars:  Vec::new(),
        }
    }

    pub fn dbg_mark(&mut self, line: u32, col: u32, kind: &'static str) {
        if line == 0 { return; }
        self.dbg_marks.push(DbgMark { code_off: self.code.len(), line, col, kind });
    }

    pub fn dbg_var(&mut self, name: &str, ty: &str, frame_off: i32, line_start: u32, line_end: u32) {
        if line_start == 0 || name.is_empty() { return; }
        let loc = if frame_off < 0 {
            format!("rbp-0x{:x}", -frame_off)
        } else {
            format!("rbp+0x{:x}", frame_off)
        };
        self.dbg_vars.push(DbgVar {
            name: name.to_string(),
            ty:   ty.to_string(),
            loc,
            line_start,
            line_end,
        });
    }

    pub fn code_reloc_ranges(&self) -> Vec<std::ops::Range<usize>> {
        self.relocs.iter().map(|r| r.patch_at..(r.patch_at + 4)).collect()
    }

    pub fn code_label_positions(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.code_labels.values().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn splice(&mut self, at: usize, old_len: usize, new_bytes: &[u8]) {
        let delta = new_bytes.len() as isize - old_len as isize;
        // Replace the bytes in place.
        self.code.splice(at..at + old_len, new_bytes.iter().copied());
        if delta == 0 { return; }
        for pos in self.code_labels.values_mut() {
            if *pos > at {
                *pos = ((*pos as isize) + delta) as usize;
            }
        }
        for r in self.relocs.iter_mut() {
            if r.patch_at >= at + old_len {
                r.patch_at = ((r.patch_at as isize) + delta) as usize;
            }
        }
    }

    fn emit(&mut self, b: u8)   { self.code.push(b); }
    fn emit32(&mut self, v: u32){ self.code.extend_from_slice(&v.to_le_bytes()); }
    fn emit64(&mut self, v: u64){ self.code.extend_from_slice(&v.to_le_bytes()); }

    fn rex(&mut self, w: bool, r: bool, x: bool, b: bool) {
        if w || r || x || b {
            let mut byte = 0x40u8;
            if w { byte |= 0x08; }
            if r { byte |= 0x04; }
            if x { byte |= 0x02; }
            if b { byte |= 0x01; }
            self.emit(byte);
        }
    }

    fn modrm(&mut self, mod_: u8, reg: u8, rm: u8) {
        self.emit(((mod_ & 0b11) << 6) | ((reg & 0b111) << 3) | (rm & 0b111));
    }

    pub fn place_code_label(&mut self, name: &str) {
        self.code_labels.insert(name.to_string(), self.code.len());
    }

    pub fn add_rdata(&mut self, name: &str, bytes: &[u8]) {
        let offset = self.rdata.len();
        self.rdata.extend_from_slice(bytes);
        self.rdata_labels.insert(name.to_string(), offset);
    }

    pub fn add_rdata_raw_named(&mut self, name: &str, bytes: &[u8]) {
        let offset = self.rdata.len();
        self.rdata.extend_from_slice(bytes);
        self.rdata_labels.insert(name.to_string(), offset);
    }

    pub fn mark_rdata_position(&mut self, name: &str) {
        self.rdata_labels.insert(name.to_string(), self.rdata.len());
    }

    /// Append bytes to the mutable .data section. Reserved for
    /// initialised mutable data - currently only used when a future
    /// const-baked static landing path needs it.
    pub fn add_data(&mut self, name: &str, bytes: &[u8]) {
        let offset = self.data.len();
        self.data.extend_from_slice(bytes);
        self.data_labels.insert(name.to_string(), offset);
    }

    pub fn data_has(&self, name: &str) -> bool {
        self.rdata_labels.contains_key(name)
            || self.data_labels.contains_key(name)
            || self.bss_labels.contains_key(name)
    }

    pub fn code_has(&self, name: &str) -> bool {
        self.code_labels.contains_key(name)
    }

    /// Add a NUL-terminated string to .rdata. Strings are
    /// universally read-only - the compiler doesn't expose any
    /// in-place string mutation today.
    pub fn add_string(&mut self, name: &str, s: &str) {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0);
        self.add_rdata(name, &bytes);
    }

    pub fn add_bss(&mut self, name: &str, size: usize) {
        let offset = self.bss_size;
        self.bss_size += size;
        self.bss_labels.insert(name.to_string(), offset);
    }

    fn rel32_to(&mut self, target: RelocTarget) {
        let patch_at = self.code.len();
        self.emit32(0);
        self.relocs.push(Reloc { patch_at, target });
    }


    /// mov reg64, imm64    (REX.W + B8+rd io)
    pub fn mov_r64_imm64(&mut self, dst: Reg64, imm: u64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xB8 + dst.lo3());
        self.emit64(imm);
    }

    /// mov dst, src (both reg64)    (REX.W + 89 /r)
    pub fn mov_r64_r64(&mut self, dst: Reg64, src: Reg64) {
        self.rex(true, src.ext(), false, dst.ext());
        self.emit(0x89);
        self.modrm(0b11, src.lo3(), dst.lo3());
    }

    /// mov reg64, [rip + rel32]    (REX.W + 8B /r, mod=00 rm=101)
    pub fn mov_r64_data(&mut self, dst: Reg64, label: &str) {
        self.rex(true, dst.ext(), false, false);
        self.emit(0x8B);
        self.modrm(0b00, dst.lo3(), 0b101);
        self.rel32_to(RelocTarget::Data(label.to_string()));
    }

    /// mov [rip + rel32], reg64    (REX.W + 89 /r, mod=00 rm=101)
    pub fn mov_data_r64(&mut self, label: &str, src: Reg64) {
        self.rex(true, src.ext(), false, false);
        self.emit(0x89);
        self.modrm(0b00, src.lo3(), 0b101);
        self.rel32_to(RelocTarget::Data(label.to_string()));
    }

    /// mov reg64, [rbp + disp32]    (REX.W + 8B /r, mod=10 rm=101)
    pub fn mov_r64_rbp_disp(&mut self, dst: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, false);
        self.emit(0x8B);
        self.modrm(0b10, dst.lo3(), Reg64::Rbp.lo3());
        self.emit32(disp as u32);
    }

    /// mov [rbp + disp32], reg64    (REX.W + 89 /r)
    pub fn mov_rbp_disp_r64(&mut self, disp: i32, src: Reg64) {
        self.rex(true, src.ext(), false, false);
        self.emit(0x89);
        self.modrm(0b10, src.lo3(), Reg64::Rbp.lo3());
        self.emit32(disp as u32);
    }

    /// lea reg64, [rip + rel32]    (REX.W + 8D /r, mod=00 rm=101)
    pub fn lea_r64_data(&mut self, dst: Reg64, label: &str) {
        self.rex(true, dst.ext(), false, false);
        self.emit(0x8D);
        self.modrm(0b00, dst.lo3(), 0b101);
        self.rel32_to(RelocTarget::Data(label.to_string()));
    }

    /// lea reg64, [rip + rel32]   - used for taking a code address
    /// (e.g. saving a handler PC into a longjmp buffer).
    pub fn lea_r64_code(&mut self, dst: Reg64, label: &str) {
        self.rex(true, dst.ext(), false, false);
        self.emit(0x8D);
        self.modrm(0b00, dst.lo3(), 0b101);
        self.rel32_to(RelocTarget::Code(label.to_string()));
    }

    /// push reg64    (50+rd, REX.B for R8..R15)
    pub fn push_r64(&mut self, r: Reg64) {
        self.rex(false, false, false, r.ext());
        self.emit(0x50 + r.lo3());
    }

    /// pop reg64    (58+rd)
    pub fn pop_r64(&mut self, r: Reg64) {
        self.rex(false, false, false, r.ext());
        self.emit(0x58 + r.lo3());
    }

    /// ret    (C3)
    pub fn ret(&mut self) { self.emit(0xC3); }

    /// nop    (90)
    pub fn nop(&mut self) { self.emit(0x90); }

    pub fn sub_r64_imm32(&mut self, dst: Reg64, imm: i32) {
        self.rex(true, false, false, dst.ext());
        if let Ok(imm8) = i8::try_from(imm) {
            self.emit(0x83);
            self.modrm(0b11, 5, dst.lo3());
            self.emit(imm8 as u8);
        } else {
            self.emit(0x81);
            self.modrm(0b11, 5, dst.lo3());
            self.emit32(imm as u32);
        }
    }

    /// add reg64, imm    Size-aware companion to [sub_r64_imm32]. Same
    /// 7 to 4 byte win for small immediates (add rsp, 8, frame fix-ups,
    /// small struct field offsets, etc.).
    pub fn add_r64_imm32(&mut self, dst: Reg64, imm: i32) {
        self.rex(true, false, false, dst.ext());
        if let Ok(imm8) = i8::try_from(imm) {
            self.emit(0x83);
            self.modrm(0b11, 0, dst.lo3());
            self.emit(imm8 as u8);
        } else {
            self.emit(0x81);
            self.modrm(0b11, 0, dst.lo3());
            self.emit32(imm as u32);
        }
    }

    /// add reg64, reg64    (REX.W + 01 /r)
    pub fn add_r64_r64(&mut self, dst: Reg64, src: Reg64) {
        self.rex(true, src.ext(), false, dst.ext());
        self.emit(0x01);
        self.modrm(0b11, src.lo3(), dst.lo3());
    }

    /// sub dst, src    (REX.W + 29 /r)
    pub fn sub_r64_r64(&mut self, dst: Reg64, src: Reg64) {
        self.rex(true, src.ext(), false, dst.ext());
        self.emit(0x29);
        self.modrm(0b11, src.lo3(), dst.lo3());
    }

    pub fn xor_r64_r64(&mut self, dst: Reg64, src: Reg64) {
        if dst as u8 == src as u8 && !dst.ext() {
            // 2-byte xor er32, er32 - REX omitted entirely.
            self.emit(0x31);
            self.modrm(0b11, src.lo3(), dst.lo3());
            return;
        }
        self.rex(true, src.ext(), false, dst.ext());
        self.emit(0x31);
        self.modrm(0b11, src.lo3(), dst.lo3());
    }

    /// and dst, src    (REX.W + 21 /r)
    pub fn and_r64_r64(&mut self, dst: Reg64, src: Reg64) {
        self.rex(true, src.ext(), false, dst.ext());
        self.emit(0x21);
        self.modrm(0b11, src.lo3(), dst.lo3());
    }

    /// and r64, imm8 (sign-extended)    (REX.W + 83 /4 ib) - 4 bytes.
    /// Used by the GC for masking off the low-3-bit header flags
    /// (and rcx, -8 keeps just the size).
    pub fn and_r64_imm8(&mut self, dst: Reg64, imm: i8) {
        self.rex(true, false, false, dst.ext());
        self.emit(0x83);
        self.modrm(0b11, 4, dst.lo3());
        self.emit(imm as u8);
    }

    /// or r64, imm8 (sign-extended)    (REX.W + 83 /1 ib) - 4 bytes.
    /// Used by the GC for setting flag bits without disturbing size
    /// (or rcx, 1 sets the mark bit).
    pub fn or_r64_imm8(&mut self, dst: Reg64, imm: i8) {
        self.rex(true, false, false, dst.ext());
        self.emit(0x83);
        self.modrm(0b11, 1, dst.lo3());
        self.emit(imm as u8);
    }

    /// or dst, src    (REX.W + 09 /r)
    pub fn or_r64_r64(&mut self, dst: Reg64, src: Reg64) {
        self.rex(true, src.ext(), false, dst.ext());
        self.emit(0x09);
        self.modrm(0b11, src.lo3(), dst.lo3());
    }

    /// not r64    (REX.W + F7 /2) - bitwise complement
    pub fn not_r64(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xF7);
        self.modrm(0b11, 2, dst.lo3());
    }

    /// shl r64, cl    (REX.W + D3 /4) - logical shift left, count in CL
    pub fn shl_r64_cl(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xD3);
        self.modrm(0b11, 4, dst.lo3());
    }

    /// shl r64, imm8    (REX.W + C1 /4 ib) - logical shift left by constant.
    pub fn shl_r64_imm8(&mut self, dst: Reg64, imm: u8) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xC1);
        self.modrm(0b11, 4, dst.lo3());
        self.emit(imm);
    }

    /// imul r64, r/m64, imm8 (sign-extended) - REX.W + 6B /r ib.
    /// Three-operand multiply with a small immediate. Used by the
    /// hashed-import resolver's djb2-style hash.
    pub fn imul_r64_r64_imm8(&mut self, dst: Reg64, src: Reg64, imm: i8) {
        self.rex(true, dst.ext(), false, src.ext());
        self.emit(0x6B);
        self.modrm(0b11, dst.lo3(), src.lo3());
        self.emit(imm as u8);
    }

    pub fn cmp_r32_imm32(&mut self, dst: Reg64, imm: u32) {
        if dst.ext() { self.emit(0x41); }
        self.emit(0x81);
        self.modrm(0b11, 7, dst.lo3());
        self.emit32(imm);
    }

    #[allow(dead_code)]
    pub fn shr_r64_cl(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xD3);
        self.modrm(0b11, 5, dst.lo3());
    }

    /// sar r64, cl    (REX.W + D3 /7) - arithmetic shift right, count in CL
    pub fn sar_r64_cl(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xD3);
        self.modrm(0b11, 7, dst.lo3());
    }

    /// cld    (FC) - clear direction flag. String ops then auto-increment
    /// rdi/rsi. Win64 callers may have set DF; intrinsic memory primitives
    /// emit this defensively before any rep so direction is deterministic.
    pub fn cld(&mut self) { self.emit(0xFC); }

    /// rep stosb    (F3 AA) - fill rcx bytes at [rdi] with al. Modifies
    /// rdi (post-increment by rcx) and rcx (zero).
    pub fn rep_stosb(&mut self) { self.emit(0xF3); self.emit(0xAA); }

    /// rep movsb    (F3 A4) - copy rcx bytes from [rsi] to [rdi].
    /// Modifies rsi, rdi, rcx.
    pub fn rep_movsb(&mut self) { self.emit(0xF3); self.emit(0xA4); }

    /// repe cmpsb    (F3 A6) - compare rcx bytes; stop on first mismatch
    /// OR when rcx hits zero. ZF=1 means full match.
    pub fn repe_cmpsb(&mut self) { self.emit(0xF3); self.emit(0xA6); }

    /// cmp reg64, reg64    (REX.W + 39 /r)
    pub fn cmp_r64_r64(&mut self, a: Reg64, b: Reg64) {
        self.rex(true, b.ext(), false, a.ext());
        self.emit(0x39);
        self.modrm(0b11, b.lo3(), a.lo3());
    }

    /// test reg64, reg64    (REX.W + 85 /r)
    pub fn test_r64_r64(&mut self, a: Reg64, b: Reg64) {
        self.rex(true, b.ext(), false, a.ext());
        self.emit(0x85);
        self.modrm(0b11, b.lo3(), a.lo3());
    }

    pub fn call_extern(&mut self, sym: &str) {
        self.emit(0xFF);
        self.modrm(0b00, 0b010, 0b101);
        self.rel32_to(RelocTarget::External(sym.to_string()));
    }

    pub fn call_label(&mut self, label: &str) {
        self.emit(0xE8);
        self.rel32_to(RelocTarget::Code(label.to_string()));
    }

    /// call [rip + rel32]    (FF /2, mod=00 rm=101) - indirect through slot
    pub fn call_indirect_data(&mut self, label: &str) {
        self.emit(0xFF);
        self.modrm(0b00, 2, 0b101);
        self.rel32_to(RelocTarget::Data(label.to_string()));
    }

    /// call reg64    (FF /2)
    pub fn call_r64(&mut self, r: Reg64) {
        self.rex(false, false, false, r.ext());
        self.emit(0xFF);
        self.modrm(0b11, 2, r.lo3());
    }

    /// jmp rel32    (E9 cd)
    pub fn jmp_label(&mut self, label: &str) {
        self.emit(0xE9);
        self.rel32_to(RelocTarget::Code(label.to_string()));
    }

    /// jmp reg64    (FF /4) - used for indirect jumps (longjmp restore)
    pub fn jmp_r64(&mut self, r: Reg64) {
        self.rex(false, false, false, r.ext());
        self.emit(0xFF);
        self.modrm(0b11, 4, r.lo3());
    }

    /// jcc rel32    (0F 8x cd)
    pub fn jcc_label(&mut self, cond: Cond, label: &str) {
        self.emit(0x0F);
        self.emit(0x80 + cond.nibble());
        self.rel32_to(RelocTarget::Code(label.to_string()));
    }

    /// raw byte emit (for inline asm { 0x.. } blocks)
    pub fn emit_raw(&mut self, b: u8) { self.emit(b); }


    /// mov dst, [base + disp32]    (REX.W + 8B /r)
    pub fn mov_r64_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x8B);
        let rm = base.lo3();
        if rm == 0b100 {
            // rsp/r12 require a SIB byte even with no index.
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24); // SIB: scale=00 index=100(none) base=100
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// mov [base + disp32], src    (REX.W + 89 /r)
    pub fn mov_r64disp_r64(&mut self, base: Reg64, disp: i32, src: Reg64) {
        self.rex(true, src.ext(), false, base.ext());
        self.emit(0x89);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, src.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, src.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// lea dst, [base + disp32]    (REX.W + 8D /r)
    pub fn lea_r64_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x8D);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// lea dst, [base + idx*1]    (REX.W + 8D /r, SIB scale=00) - RVA  to  absolute
    pub fn lea_r64_base_idx(&mut self, dst: Reg64, base: Reg64, idx: Reg64) {
        self.rex(true, dst.ext(), idx.ext(), base.ext());
        self.emit(0x8D);
        // mod=00 reg=dst rm=100 (SIB); SIB: scale=00 index=idx base=base
        // base==rbp/r13 + mod=00 means [disp32] - disallow that combination.
        // For us base is rcx/rax/rbx so it's fine; assert just in case.
        debug_assert!(base.lo3() != 0b101, "lea with rbp/r13 as base needs disp");
        self.modrm(0b00, dst.lo3(), 0b100);
        let sib = (0b00 << 6) | (idx.lo3() << 3) | base.lo3();
        self.emit(sib);
    }

    /// mov dst32, [base + idx*4]    (66/REX optional; default-32 mov) - RVA-table read
    pub fn mov_r32_base_idx_scale4(&mut self, dst: Reg64, base: Reg64, idx: Reg64) {
        // 32-bit mov writes zero-extend into the 64-bit register, which is
        // exactly what we want for RVAs.
        // REX only if any extended reg is used.
        if dst.ext() || base.ext() || idx.ext() {
            self.rex(false, dst.ext(), idx.ext(), base.ext());
        }
        self.emit(0x8B);
        debug_assert!(base.lo3() != 0b101, "scale-load with rbp/r13 base needs disp");
        self.modrm(0b00, dst.lo3(), 0b100);
        let sib = (0b10 << 6) | (idx.lo3() << 3) | base.lo3(); // scale=4
        self.emit(sib);
    }

    /// mov dst32, [base + disp32]    (zero-extend into r64; RVA at fixed offset)
    pub fn mov_r32_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        if dst.ext() || base.ext() {
            self.rex(false, dst.ext(), false, base.ext());
        }
        self.emit(0x8B);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// movzx dst, word ptr [base + idx*2]    (REX.W + 0F B7 /r, SIB scale=01) - ordinal table
    pub fn movzx_r64_word_base_idx_scale2(&mut self, dst: Reg64, base: Reg64, idx: Reg64) {
        self.rex(true, dst.ext(), idx.ext(), base.ext());
        self.emit(0x0F); self.emit(0xB7);
        debug_assert!(base.lo3() != 0b101);
        self.modrm(0b00, dst.lo3(), 0b100);
        let sib = (0b01 << 6) | (idx.lo3() << 3) | base.lo3();
        self.emit(sib);
    }

    /// movzx dst, byte ptr [base]    (REX.W + 0F B6 /r, mod=00)
    pub fn movzx_r64_byte_r64(&mut self, dst: Reg64, base: Reg64) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x0F); self.emit(0xB6);
        let rm = base.lo3();
        if rm == 0b101 {
            // rbp/r13: need mod=01 disp8=0
            self.modrm(0b01, dst.lo3(), rm);
            self.emit(0);
        } else if rm == 0b100 {
            self.modrm(0b00, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b00, dst.lo3(), rm);
        }
    }

    /// movzx dst, word ptr [base + disp32]    (REX.W + 0F B7 /r) - UNICODE_STRING.Length
    pub fn movzx_r64_word_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x0F); self.emit(0xB7);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// mov rax, gs:[disp32]    (65 48 8B 04 25 disp32) - PEB load on x64
    pub fn mov_rax_gs_qword(&mut self, disp: i32) {
        self.emit(0x65); // GS segment override
        self.emit(0x48); // REX.W
        self.emit(0x8B);
        self.emit(0x04); // ModR/M: mod=00 reg=000(rax) rm=100(SIB)
        self.emit(0x25); // SIB: scale=00 index=100(none) base=101(disp32 only)
        self.emit32(disp as u32);
    }

    /// mov r64, [disp32]    (REX.W + 8B /r, SIB disp-only form).
    /// Pair with emit_seg_prefix for gs:/fs: absolute loads.
    pub fn mov_r64_disp32(&mut self, dst: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, false);
        self.emit(0x8B);
        self.modrm(0b00, dst.lo3(), 0b100);
        self.emit(0x25);
        self.emit32(disp as u32);
    }

    /// mov [disp32], r64    (REX.W + 89 /r). Mirror of mov_r64_disp32.
    pub fn mov_disp32_r64(&mut self, disp: i32, src: Reg64) {
        self.rex(true, src.ext(), false, false);
        self.emit(0x89);
        self.modrm(0b00, src.lo3(), 0b100);
        self.emit(0x25);
        self.emit32(disp as u32);
    }

    /// add reg, imm8    (REX.W + 83 /0 ib) - shorter than imm32 form
    pub fn add_r64_imm8(&mut self, dst: Reg64, imm: i8) {
        self.rex(true, false, false, dst.ext());
        self.emit(0x83);
        self.modrm(0b11, 0, dst.lo3());
        self.emit(imm as u8);
    }

    /// sub reg, imm8    (REX.W + 83 /5 ib)
    pub fn sub_r64_imm8(&mut self, dst: Reg64, imm: i8) {
        self.rex(true, false, false, dst.ext());
        self.emit(0x83);
        self.modrm(0b11, 5, dst.lo3());
        self.emit(imm as u8);
    }

    /// cmp reg, imm32    (REX.W + 81 /7 id)
    pub fn cmp_r64_imm32(&mut self, dst: Reg64, imm: i32) {
        self.rex(true, false, false, dst.ext());
        self.emit(0x81);
        self.modrm(0b11, 7, dst.lo3());
        self.emit32(imm as u32);
    }

    /// inc reg    (REX.W + FF /0)
    pub fn inc_r64(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xFF);
        self.modrm(0b11, 0, dst.lo3());
    }

    /// dec reg    (REX.W + FF /1) - the inline-asm counterpart to inc.
    /// Used by dec rcx etc. inside asm { ... } blocks.
    pub fn dec_r64(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xFF);
        self.modrm(0b11, 1, dst.lo3());
    }

    /// neg reg    (REX.W + F7 /3) - two's-complement negation.
    pub fn neg_r64(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xF7);
        self.modrm(0b11, 3, dst.lo3());
    }

    /// xor reg, imm32   Size-aware. imm-8-fits uses REX.W + 83 /6 ib
    /// (4 bytes), otherwise REX.W + 81 /6 id (7 bytes). Same pattern
    /// as add_r64_imm32 / sub_r64_imm32.
    pub fn xor_r64_imm32(&mut self, dst: Reg64, imm: i32) {
        self.rex(true, false, false, dst.ext());
        if let Ok(imm8) = i8::try_from(imm) {
            self.emit(0x83);
            self.modrm(0b11, 6, dst.lo3());
            self.emit(imm8 as u8);
        } else {
            self.emit(0x81);
            self.modrm(0b11, 6, dst.lo3());
            self.emit32(imm as u32);
        }
    }

    /// and reg, imm32   Size-aware companion to and_r64_imm8.
    pub fn and_r64_imm32(&mut self, dst: Reg64, imm: i32) {
        self.rex(true, false, false, dst.ext());
        if let Ok(imm8) = i8::try_from(imm) {
            self.emit(0x83);
            self.modrm(0b11, 4, dst.lo3());
            self.emit(imm8 as u8);
        } else {
            self.emit(0x81);
            self.modrm(0b11, 4, dst.lo3());
            self.emit32(imm as u32);
        }
    }

    /// or reg, imm32    Size-aware companion to or_r64_imm8.
    pub fn or_r64_imm32(&mut self, dst: Reg64, imm: i32) {
        self.rex(true, false, false, dst.ext());
        if let Ok(imm8) = i8::try_from(imm) {
            self.emit(0x83);
            self.modrm(0b11, 1, dst.lo3());
            self.emit(imm8 as u8);
        } else {
            self.emit(0x81);
            self.modrm(0b11, 1, dst.lo3());
            self.emit32(imm as u32);
        }
    }

    /// push imm32    (68 id) - push a sign-extended 32-bit immediate.
    /// Useful inside asm blocks for push 0x1234-style scratch values.
    pub fn push_imm32(&mut self, imm: i32) {
        self.emit(0x68);
        self.emit32(imm as u32);
    }

    /// int 3    (CC) - debugger trap. Surfaces in entc-debug as a
    /// breakpoint stop, lets users plant explicit traps inline.
    pub fn int3(&mut self) { self.emit(0xCC); }

    pub fn syscall_(&mut self) { self.emit(0x0F); self.emit(0x05); }


    /// mov byte ptr [base + disp32], r8    (88 /r)
    /// Writes the LOW BYTE of src. For source rax this is al.
    pub fn mov_byte_r64disp_r8(&mut self, base: Reg64, disp: i32, src: Reg64) {
        let need_rex = src.ext() || base.ext() ||
                       matches!(src, Reg64::Rsp | Reg64::Rbp | Reg64::Rsi | Reg64::Rdi);
        if need_rex {
            self.rex(false, src.ext(), false, base.ext());
        }
        self.emit(0x88);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, src.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, src.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// mov word ptr [base + disp32], r16    (66 + 89 /r) - low 16 bits of src
    pub fn mov_word_r64disp_r16(&mut self, base: Reg64, disp: i32, src: Reg64) {
        self.emit(0x66); // operand-size override  to  16-bit operand
        if src.ext() || base.ext() {
            self.rex(false, src.ext(), false, base.ext());
        }
        self.emit(0x89);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, src.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, src.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// mov dword ptr [base + disp32], r32    (89 /r without REX.W) - low 32
    pub fn mov_dword_r64disp_r32(&mut self, base: Reg64, disp: i32, src: Reg64) {
        if src.ext() || base.ext() {
            self.rex(false, src.ext(), false, base.ext());
        }
        self.emit(0x89);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, src.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, src.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    fn scale_bits(scale: u32) -> u8 {
        match scale {
            1 => 0b00,
            2 => 0b01,
            4 => 0b10,
            8 => 0b11,
            _ => panic!("indexed addressing supports scales 1/2/4/8 only (got {scale})"),
        }
    }

    fn modrm_sib_base_idx(&mut self, reg_field: u8, base: Reg64, idx: Reg64, scale: u32) {
        let s = Self::scale_bits(scale);
        let base_lo = base.lo3();
        let sib = (s << 6) | (idx.lo3() << 3) | base_lo;
        if base_lo == 0b101 {
            // rbp/r13 base requires explicit disp (mod=01, disp8=0).
            self.modrm(0b01, reg_field, 0b100);
            self.emit(sib);
            self.emit(0);
        } else {
            self.modrm(0b00, reg_field, 0b100);
            self.emit(sib);
        }
    }

    /// movzx dst, byte ptr [base + idx*1]    (REX + 0F B6 /r, SIB scale=00)
    pub fn movzx_r64_byte_base_idx(&mut self, dst: Reg64, base: Reg64, idx: Reg64) {
        self.rex(true, dst.ext(), idx.ext(), base.ext());
        self.emit(0x0F); self.emit(0xB6);
        self.modrm_sib_base_idx(dst.lo3(), base, idx, 1);
    }

    /// movzx dst, word ptr [base + idx*2]    (REX + 0F B7 /r, SIB scale=01)
    pub fn movzx_r64_word_base_idx(&mut self, dst: Reg64, base: Reg64, idx: Reg64) {
        self.rex(true, dst.ext(), idx.ext(), base.ext());
        self.emit(0x0F); self.emit(0xB7);
        self.modrm_sib_base_idx(dst.lo3(), base, idx, 2);
    }

    /// mov dst32, [base + idx*4]    (8B /r, SIB scale=10) - zero-extends into r64
    pub fn mov_r32_base_idx(&mut self, dst: Reg64, base: Reg64, idx: Reg64) {
        if dst.ext() || base.ext() || idx.ext() {
            self.rex(false, dst.ext(), idx.ext(), base.ext());
        }
        self.emit(0x8B);
        self.modrm_sib_base_idx(dst.lo3(), base, idx, 4);
    }

    /// mov dst, qword ptr [base + idx*8]    (REX.W + 8B /r, SIB scale=11)
    pub fn mov_r64_base_idx(&mut self, dst: Reg64, base: Reg64, idx: Reg64) {
        self.rex(true, dst.ext(), idx.ext(), base.ext());
        self.emit(0x8B);
        self.modrm_sib_base_idx(dst.lo3(), base, idx, 8);
    }

    /// mov byte ptr [base + idx*1], src    (88 /r, SIB scale=00) - low byte of src
    pub fn mov_byte_base_idx_r8(&mut self, base: Reg64, idx: Reg64, src: Reg64) {
        // 8-bit destination. REX needed if any extended reg, or src is
        // rsp/rbp/rsi/rdi (whose 8-bit form is spl/bpl/sil/dil and requires REX).
        let need_rex = src.ext() || base.ext() || idx.ext() ||
                       matches!(src, Reg64::Rsp | Reg64::Rbp | Reg64::Rsi | Reg64::Rdi);
        if need_rex {
            self.rex(false, src.ext(), idx.ext(), base.ext());
        }
        self.emit(0x88);
        self.modrm_sib_base_idx(src.lo3(), base, idx, 1);
    }

    /// mov word ptr [base + idx*2], src    (66 89 /r, SIB scale=01) - low 16 of src
    pub fn mov_word_base_idx_r16(&mut self, base: Reg64, idx: Reg64, src: Reg64) {
        self.emit(0x66);
        if src.ext() || base.ext() || idx.ext() {
            self.rex(false, src.ext(), idx.ext(), base.ext());
        }
        self.emit(0x89);
        self.modrm_sib_base_idx(src.lo3(), base, idx, 2);
    }

    /// mov dword ptr [base + idx*4], src    (89 /r, SIB scale=10) - low 32 of src
    pub fn mov_dword_base_idx_r32(&mut self, base: Reg64, idx: Reg64, src: Reg64) {
        if src.ext() || base.ext() || idx.ext() {
            self.rex(false, src.ext(), idx.ext(), base.ext());
        }
        self.emit(0x89);
        self.modrm_sib_base_idx(src.lo3(), base, idx, 4);
    }

    /// mov qword ptr [base + idx*8], src    (REX.W + 89 /r, SIB scale=11)
    pub fn mov_qword_base_idx_r64(&mut self, base: Reg64, idx: Reg64, src: Reg64) {
        self.rex(true, src.ext(), idx.ext(), base.ext());
        self.emit(0x89);
        self.modrm_sib_base_idx(src.lo3(), base, idx, 8);
    }

    /// lea dst, [base + idx*scale]    (REX.W + 8D /r) - generalised form
    /// used to take the address of arr[i] for &-of or pointer arithmetic.
    pub fn lea_r64_base_idx_scale(&mut self, dst: Reg64, base: Reg64, idx: Reg64, scale: u32) {
        self.rex(true, dst.ext(), idx.ext(), base.ext());
        self.emit(0x8D);
        self.modrm_sib_base_idx(dst.lo3(), base, idx, scale);
    }

    /// movzx r64, byte ptr [base + disp32]    (REX.W + 0F B6 /r)
    pub fn movzx_r64_byte_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x0F); self.emit(0xB6);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    // Inline-asm-only instructions. Not used by the high-level codegen.

    /// Emit a segment-override prefix (0x64 = FS, 0x65 = GS).
    /// Must precede the REX byte of the targeted instruction.
    pub fn emit_seg_prefix(&mut self, seg: Segment) {
        self.emit(seg.prefix());
    }

    /// cmovcc dst, src    (REX.W + 0F 4_ /r) - branchless conditional move.
    pub fn cmovcc_r64_r64(&mut self, cond: Cond, dst: Reg64, src: Reg64) {
        self.rex(true, dst.ext(), false, src.ext());
        self.emit(0x0F);
        self.emit(0x40 | cond.nibble());
        self.modrm(0b11, dst.lo3(), src.lo3());
    }

    /// rol r64, imm8    (REX.W + C1 /0 ib)
    pub fn rol_r64_imm8(&mut self, dst: Reg64, imm: u8) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xC1);
        self.modrm(0b11, 0, dst.lo3());
        self.emit(imm);
    }

    /// rol r64, cl    (REX.W + D3 /0)
    pub fn rol_r64_cl(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xD3);
        self.modrm(0b11, 0, dst.lo3());
    }

    /// ror r64, imm8    (REX.W + C1 /1 ib) - used by ror13 hashed imports.
    pub fn ror_r64_imm8(&mut self, dst: Reg64, imm: u8) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xC1);
        self.modrm(0b11, 1, dst.lo3());
        self.emit(imm);
    }

    /// ror r64, cl    (REX.W + D3 /1)
    pub fn ror_r64_cl(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0xD3);
        self.modrm(0b11, 1, dst.lo3());
    }

    /// movsx r64, byte ptr [base + disp32]    (REX.W + 0F BE /r)
    pub fn movsx_r64_byte_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x0F); self.emit(0xBE);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// movsx r64, word ptr [base + disp32]    (REX.W + 0F BF /r)
    pub fn movsx_r64_word_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x0F); self.emit(0xBF);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// movsxd r64, dword ptr [base + disp32]    (REX.W + 63 /r)
    pub fn movsxd_r64_r64disp(&mut self, dst: Reg64, base: Reg64, disp: i32) {
        self.rex(true, dst.ext(), false, base.ext());
        self.emit(0x63);
        let rm = base.lo3();
        if rm == 0b100 {
            self.modrm(0b10, dst.lo3(), 0b100);
            self.emit(0x24);
        } else {
            self.modrm(0b10, dst.lo3(), rm);
        }
        self.emit32(disp as u32);
    }

    /// movsxd r64, r32    (REX.W + 63 /r, mod=11)
    pub fn movsxd_r64_r64(&mut self, dst: Reg64, src: Reg64) {
        self.rex(true, dst.ext(), false, src.ext());
        self.emit(0x63);
        self.modrm(0b11, dst.lo3(), src.lo3());
    }

    /// xchg r64, r64    (REX.W + 87 /r) - atomic register swap.
    pub fn xchg_r64_r64(&mut self, a: Reg64, b: Reg64) {
        self.rex(true, a.ext(), false, b.ext());
        self.emit(0x87);
        self.modrm(0b11, a.lo3(), b.lo3());
    }

    /// bswap r64    (REX.W + 0F C8+rd) - byte-swap.
    pub fn bswap_r64(&mut self, dst: Reg64) {
        self.rex(true, false, false, dst.ext());
        self.emit(0x0F);
        self.emit(0xC8 + dst.lo3());
    }


    pub fn finalize(mut self) -> Result<Vec<u8>, String> {
        while self.code.len() & 7 != 0 {
            self.code.push(0x90);
        }
        let code_len  = self.code.len();
        let rdata_off = code_len;
        let data_off  = rdata_off + self.rdata.len();
        let bss_off   = data_off  + self.data.len();

        // Shift each label by its section's base offset so they become
        // absolute offsets inside the combined blob.
        for (_n, off) in self.rdata_labels.iter_mut() { *off += rdata_off; }
        for (_n, off) in self.data_labels.iter_mut()  { *off += data_off;  }
        for (_n, off) in self.bss_labels.iter_mut()   { *off += bss_off;   }

        self.code.extend_from_slice(&self.rdata);
        self.code.extend_from_slice(&self.data);
        // .bss flattens to its zero-fill in standard mode so the
        // single-buffer launcher model keeps working.
        self.code.resize(self.code.len() + self.bss_size, 0);

        for r in &self.relocs {
            let target_off = match &r.target {
                RelocTarget::Code(n) => *self.code_labels.get(n)
                    .ok_or_else(|| format!("unresolved code label: {n}"))?,
                RelocTarget::Data(n) => self.rdata_labels.get(n)
                    .or_else(|| self.data_labels.get(n))
                    .or_else(|| self.bss_labels.get(n))
                    .copied()
                    .ok_or_else(|| format!("unresolved data label: {n}"))?,
                RelocTarget::External(n) => {
                    return Err(format!(
                        "external symbol `{n}` referenced in --type=standard build. \
                         External symbols are only valid in `--type=bof|coff`."
                    ));
                }
            };
            // rel32 is computed from the byte AFTER the displacement field.
            let next_ip = (r.patch_at + 4) as i64;
            let rel = target_off as i64 - next_ip;
            if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                return Err("rel32 out of range".into());
            }
            let bytes = (rel as i32 as u32).to_le_bytes();
            self.code[r.patch_at..r.patch_at + 4].copy_from_slice(&bytes);
        }
        Ok(self.code)
    }

    pub fn finalize_for_coff(mut self) -> Result<CoffArtifact, String> {
        let code_len = self.code.len();
        let mut externals:   Vec<ExternalReloc> = Vec::new();
        let mut data_relocs: Vec<DataReloc> = Vec::new();

        for r in &self.relocs {
            match &r.target {
                RelocTarget::Code(n) => {
                    let target_off = *self.code_labels.get(n)
                        .ok_or_else(|| format!("unresolved code label: {n}"))?;
                    let next_ip = (r.patch_at + 4) as i64;
                    let rel = target_off as i64 - next_ip;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err("rel32 out of range".into());
                    }
                    let bytes = (rel as i32 as u32).to_le_bytes();
                    self.code[r.patch_at..r.patch_at + 4].copy_from_slice(&bytes);
                }
                RelocTarget::Data(n) => {
                    // Look the label up across each data-like section.
                    // Whichever holds it dictates the section symbol the
                    // emitter uses for the relocation.
                    let (offset, section) =
                        if let Some(&off) = self.rdata_labels.get(n) {
                            (off as u32, DataSection::Rdata)
                        } else if let Some(&off) = self.data_labels.get(n) {
                            (off as u32, DataSection::Data)
                        } else if let Some(&off) = self.bss_labels.get(n) {
                            (off as u32, DataSection::Bss)
                        } else {
                            return Err(format!("unresolved data label: {n}"));
                        };
                    // Write the in-section offset to the patch site as
                    // the relocation addend.
                    let bytes = offset.to_le_bytes();
                    self.code[r.patch_at..r.patch_at + 4].copy_from_slice(&bytes);
                    data_relocs.push(DataReloc {
                        at: r.patch_at as u32,
                        section,
                    });
                }
                RelocTarget::External(n) => {
                    externals.push(ExternalReloc {
                        at:  r.patch_at as u32,
                        sym: n.clone(),
                    });
                }
            }
        }

        Ok(CoffArtifact {
            text:        self.code,
            rdata:       self.rdata,
            data:        self.data,
            bss_size:    self.bss_size,
            text_size:   code_len,
            externals,
            data_relocs,
            code_labels: self.code_labels,
        })
    }
}

/// One external relocation collected during finalize_for_coff. The
/// COFF emitter (src/coff.rs) turns these into REL32 entries against
/// the artifact's symbol table.
#[derive(Debug, Clone)]
pub struct ExternalReloc {
    pub at:  u32,
    pub sym: String,
}

#[derive(Debug, Clone)]
pub struct DataReloc {
    pub at:      u32,
    pub section: DataSection,
}

/// Output of finalize_for_coff. Carries the still-separate sections
/// plus the metadata the COFF emitter needs to build a valid .obj.
#[derive(Debug)]
pub struct CoffArtifact {
    /// Patched .text bytes (internal labels resolved; external rel32
    /// fields zeroed for the loader to fill in).
    pub text:      Vec<u8>,
    /// Read-only initialised data - string literals, format templates,
    /// DLL names. Lands in .rdata.
    pub rdata:     Vec<u8>,
    /// Mutable initialised data - .data. Empty in current use; the
    /// codegen still routes static initialisers through .bss + an
    /// init-replay sequence.
    pub data:      Vec<u8>,
    /// Size of the .bss section (zero-filled by the loader). Import
    /// slots, format buffers, static slots all are placed here.
    pub bss_size:  usize,
    pub text_size: usize,
    pub externals: Vec<ExternalReloc>,
    /// Cross-section relocations from .text into one of the
    /// data-like sections. Each carries the target section so the
    /// emitter writes against the right section symbol.
    pub data_relocs: Vec<DataReloc>,
    /// Code-section labels - function start offsets within .text.
    /// codegen uses this map to find go's offset for the symbol
    /// table entry.
    pub code_labels: HashMap<String, usize>,
}
