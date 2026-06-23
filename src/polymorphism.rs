
use crate::encoder::{Encoder, Reg64, Cond};

// Configuration

/// Active OPSEC techniques. Default = none.
#[derive(Debug, Clone, Default)]
pub struct OpsecConfig {
    pub poly:              bool,
    pub poly_deep:         bool,
    pub junk_level:        u8,
    pub reorder_functions: bool,
    /// XOR-encrypt rdata/data + decryptor at entry. Standard mode only;
    /// BOF rdata is RO.
    pub strings_xor:       bool,
    pub nop_sled:          bool,
    /// Auto-include stdlib/opsec/direct_syscall.etpy's
    /// [Override] syscall stub.
    pub direct_syscalls:   bool,
    /// Auto-include stdlib/opsec/indirect_syscall.etpy. Mutually
    /// exclusive with direct_syscalls (same slot).
    pub indirect_syscalls: bool,
    pub hashed_imports:    bool,
    /// Auto-included sleep-mask template ([Hook]).
    /// Variants differ in wait primitive and cipher.
    pub sleep_mask:        SleepMaskVariant,
    /// Rebuild short string literals on the stack via mov [rsp+N],
    /// imm64 runs instead of .rdata pointers. Composes with
    /// strings_xor (stack-built strings excluded from the XOR pool).
    pub stack_strings:     bool,
    /// None = system-time nanos at build time; Some = deterministic.
    pub seed:              Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SleepMaskVariant {
    #[default]
    None,
    Simple,
    Ekko,
    Foliage,
}

impl SleepMaskVariant {
    /// Stdlib sub-path the driver auto-uses. None means
    /// "splice nothing - the operator wrote their own".
    pub fn stdlib_subpath(self) -> Option<&'static str> {
        match self {
            Self::None    => None,
            Self::Simple  => Some("opsec/sleep_simple.etpy"),
            Self::Ekko    => Some("opsec/sleep_ekko.etpy"),
            Self::Foliage => Some("opsec/sleep_foliage.etpy"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::None    => "none",
            Self::Simple  => "simple",
            Self::Ekko    => "ekko",
            Self::Foliage => "foliage",
        }
    }
}

impl OpsecConfig {
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut cfg = Self::default();
        let trimmed = s.trim();
        if trimmed.is_empty() { return Ok(cfg); }
        for token in trimmed.split(',') {
            let raw = token.trim();
            match raw {
                "none" | "" => {}
                "all" => {
                    cfg.poly            = true;
                    cfg.poly_deep       = true;
                    cfg.strings_xor     = true;
                    cfg.nop_sled        = true;
                    cfg.direct_syscalls = true;
                    cfg.hashed_imports  = true;
                    cfg.stack_strings   = true;
                }
                "poly"             => cfg.poly            = true,
                "poly=deep"
                | "polydeep"
                | "poly_deep"     => { cfg.poly = true; cfg.poly_deep = true; }
                "reorder"
                | "reorder_fns"
                | "reorder_functions" => cfg.reorder_functions = true,
                _ if raw.starts_with("junk=") => {
                    let v = raw.split_once('=').map(|(_, v)| v).unwrap_or("");
                    let n: u8 = v.trim().parse().map_err(|_| format!(
                        "junk={}: expected an integer level in 1..=5", v
                    ))?;
                    if !(1..=5).contains(&n) {
                        return Err(format!(
                            "junk={}: level must be in 1..=5 (0 = off)", n
                        ));
                    }
                    // Junk insertion needs poly_deep's instruction-
                    // boundary detection. Auto-enable both so a
                    // bare junk=N flag does what the operator means.
                    cfg.poly = true;
                    cfg.poly_deep = true;
                    cfg.junk_level = n;
                }
                "strings_xor"
                | "strings"        => cfg.strings_xor     = true,
                "stack_strings"
                | "stackstr"       => cfg.stack_strings   = true,
                "nop_sled"
                | "nops"           => cfg.nop_sled        = true,
                "direct_syscalls"
                | "syscall"
                | "syscalls"       => cfg.direct_syscalls = true,
                "indirect_syscalls"
                | "indirect"
                | "isyscalls"      => cfg.indirect_syscalls = true,
                "hashed_imports"
                | "hashed"
                | "import_hash"
                | "ihash"          => cfg.hashed_imports = true,
                _ if raw.starts_with("sleep_mask=") || raw.starts_with("sleepmask=") => {
                    let v = raw.split_once('=').map(|(_, v)| v).unwrap_or("");
                    cfg.sleep_mask = match v.trim() {
                        "none" | ""            => SleepMaskVariant::None,
                        "simple" | "xor"       => SleepMaskVariant::Simple,
                        "ekko"                 => SleepMaskVariant::Ekko,
                        "foliage"              => SleepMaskVariant::Foliage,
                        other => return Err(format!(
                            "unknown sleep_mask variant `{other}` - valid: \
                             simple, ekko, foliage, none"
                        )),
                    };
                }
                other => return Err(format!(
                    "unknown opsec mode `{other}` - valid: poly, strings_xor, \
                     stack_strings, nop_sled, direct_syscalls, \
                     indirect_syscalls, hashed_imports, \
                     sleep_mask=<simple|ekko|foliage>, all, none"
                )),
            }
        }
        // Indirect wins over direct when both are asked (e.g. via
        // --opsec=all,indirect_syscalls). Both occupy the
        // [Override] slot, so we have to pick one.
        if cfg.indirect_syscalls {
            cfg.direct_syscalls = false;
        }
        Ok(cfg)
    }

    /// Resolve --seed=... into a concrete u64.
    /// "random"  to  system-time nanos; hex / decimal  to  that value.
    pub fn parse_seed(s: &str) -> Result<u64, String> {
        let s = s.trim();
        if s.is_empty() || s == "random" {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xDEADBEEF_DEADBEEF);
            return Ok(nanos);
        }
        if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(h, 16)
                .map_err(|e| format!("--seed `{s}`: {e}"));
        }
        s.parse::<u64>().map_err(|e| format!("--seed `{s}`: {e}"))
    }

    /// True iff any technique is enabled - codegen / driver use
    /// this to short-circuit when OPSEC is fully off.
    pub fn any(&self) -> bool {
        self.poly || self.strings_xor || self.nop_sled
            || self.direct_syscalls || self.indirect_syscalls
            || self.hashed_imports || self.stack_strings
            || self.sleep_mask != SleepMaskVariant::None
            || self.reorder_functions
            || self.junk_level > 0
    }
}


pub struct Rng { state: u64 }

impl Rng {
    pub fn new(seed: u64) -> Self {
        // xorshift requires non-zero state.
        Self { state: if seed == 0 { 0xDEAD_BEEF_CAFE_F00D } else { seed } }
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    pub fn next_u8(&mut self) -> u8 { self.next_u64() as u8 }
    /// Uniform integer in 0..n. n == 0 returns 0.
    pub fn range(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
    /// One-in-n probability, returns true with rate 1/n.
    pub fn one_in(&mut self, n: u64) -> bool {
        self.range(n) == 0
    }
}


const NOP_VARIANTS: &[&[u8]] = &[
    &[0x90],                                                       // 1
    &[0x66, 0x90],                                                 // 2
    &[0x0F, 0x1F, 0x00],                                           // 3
    &[0x0F, 0x1F, 0x40, 0x00],                                     // 4
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],                               // 5
    &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],                         // 6
    &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],                   // 7
    &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],             // 8
    &[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],       // 9
];

/// Emit a single multi-byte NOP of exactly n bytes (1..=9). Used
/// by codegen-level NOP-sled insertion. Larger sleds chain these.
pub fn emit_nop_block(enc: &mut Encoder, n: usize) {
    let n = n.clamp(1, NOP_VARIANTS.len());
    for &b in NOP_VARIANTS[n - 1] {
        enc.emit_raw(b);
    }
}

/// Emit total bytes worth of NOPs by chaining 1-9 byte variants.
/// The block sizes themselves are randomised via rng so two
/// builds with the same total produce different byte sequences.
pub fn emit_nop_sled(enc: &mut Encoder, rng: &mut Rng, total: usize) {
    let mut remaining = total;
    while remaining > 0 {
        let max = remaining.min(NOP_VARIANTS.len());
        let block = 1 + (rng.range(max as u64) as usize);
        emit_nop_block(enc, block);
        remaining -= block;
    }
}

// Post-codegen pass entry point.

pub fn transform(enc: &mut Encoder, cfg: &OpsecConfig, rng: &mut Rng) {
    if !cfg.any() { return; }
    if cfg.poly {
        let reloc_ranges = enc.code_reloc_ranges();
        substitute_equivalents(enc, rng, &reloc_ranges);
        redecompose_nop_runs(enc, rng, &reloc_ranges);
    }
    if cfg.poly_deep {
        expand_equivalents(enc, rng, cfg.junk_level);
    }
    if cfg.strings_xor {
        encrypt_rdata_data(enc, rng);
    }
}


/// True if i..i+len overlaps any reloc patch site.
fn overlaps_reloc(i: usize, len: usize, reloc_ranges: &[std::ops::Range<usize>]) -> bool {
    let end = i + len;
    reloc_ranges.iter().any(|r| i < r.end && r.start < end)
}

/// Top-level: walk the code buffer, attempt each known
/// transformation family at every position. First match wins
/// (transforms don't compose at a single site).
fn substitute_equivalents(
    enc: &mut Encoder,
    rng: &mut Rng,
    reloc_ranges: &[std::ops::Range<usize>],
) {
    let mut i = 0;
    while i < enc.code.len() {
        let consumed =
            try_xor_sub_swap(&mut enc.code, rng, i, reloc_ranges)
                .or_else(|| try_mov_reg_reg_swap(&mut enc.code, rng, i, reloc_ranges))
                .or_else(|| try_test_or_and_swap(&mut enc.code, rng, i, reloc_ranges))
                .unwrap_or(1);
        i += consumed;
    }
}


fn is_rex_w(b: u8) -> bool {
    (b & 0xF0) == 0x40 && (b & 0x08) != 0
}

fn try_xor_sub_swap(
    code: &mut [u8],
    rng: &mut Rng,
    i: usize,
    reloc_ranges: &[std::ops::Range<usize>],
) -> Option<usize> {
    // 2-byte form: 31 /r, modrm.mod=11, reg == rm.
    if i + 2 <= code.len()
        && code[i] == 0x31
        && (code[i + 1] & 0xC0) == 0xC0
        && ((code[i + 1] >> 3) & 7) == (code[i + 1] & 7)
        && !overlaps_reloc(i, 2, reloc_ranges)
    {
        if rng.one_in(2) {
            code[i] = 0x29;
        }
        return Some(2);
    }
    // Also accept the already-substituted form so the pass is
    // idempotent across multiple builds with the same seed.
    if i + 2 <= code.len()
        && code[i] == 0x29
        && (code[i + 1] & 0xC0) == 0xC0
        && ((code[i + 1] >> 3) & 7) == (code[i + 1] & 7)
        && !overlaps_reloc(i, 2, reloc_ranges)
    {
        if rng.one_in(2) {
            code[i] = 0x31;
        }
        return Some(2);
    }

    // 3-byte REX form: REX.W (any combo of R/X/B), 31|29 /r,
    // modrm.mod=11, modrm.reg == modrm.rm.
    if i + 3 <= code.len()
        && is_rex_w(code[i])
        && (code[i] & 0x02) == 0           // X must be 0
        && (code[i + 1] == 0x31 || code[i + 1] == 0x29)
        && (code[i + 2] & 0xC0) == 0xC0
        && ((code[i + 2] >> 3) & 7) == (code[i + 2] & 7)
        && ((code[i] & 0x04) >> 2) == (code[i] & 0x01) // REX.R == REX.B
        && !overlaps_reloc(i, 3, reloc_ranges)
    {
        if rng.one_in(2) {
            code[i + 1] ^= 0x31 ^ 0x29; // flip between the two opcodes
        }
        return Some(3);
    }

    None
}


fn try_mov_reg_reg_swap(
    code: &mut [u8],
    rng: &mut Rng,
    i: usize,
    reloc_ranges: &[std::ops::Range<usize>],
) -> Option<usize> {
    if i + 3 > code.len() { return None; }
    let rex = code[i];
    let opcode = code[i + 1];
    let modrm = code[i + 2];
    if !is_rex_w(rex) { return None; }
    if (rex & 0x02) != 0 { return None; } // X must be 0

    let in_mr = opcode == 0x89 && (modrm & 0xC0) == 0xC0;
    let in_rm = opcode == 0x8B && (modrm & 0xC0) == 0xC0;
    let in_lea = opcode == 0x8D && (modrm & 0xC0) == 0x00 // mod = 00
                 && (modrm & 7) != 4    // not SIB
                 && (modrm & 7) != 5;   // not RIP-relative

    if !(in_mr || in_rm || in_lea) { return None; }
    if overlaps_reloc(i, 3, reloc_ranges) { return None; }

    // Decode into canonical (dst_low3, src_low3, dst_ext, src_ext).
    let reg_field = (modrm >> 3) & 7;
    let rm_field = modrm & 7;
    let rex_r = (rex >> 2) & 1;
    let rex_b = rex & 1;

    let (dst_low3, src_low3, dst_ext, src_ext) = if in_mr {
        // MR: reg = src, rm = dst
        (rm_field, reg_field, rex_b == 1, rex_r == 1)
    } else {
        // RM and LEA: reg = dst, rm = src
        (reg_field, rm_field, rex_r == 1, rex_b == 1)
    };

    let lea_ok = src_low3 != 4 && src_low3 != 5;
    let n = if lea_ok { 3 } else { 2 };
    let pick = rng.range(n as u64) as u8;
    let target = match pick { 0 => 0x89, 1 => 0x8B, _ => 0x8D };

    let (new_reg_field, new_rm_field, new_rex_r, new_rex_b, new_mod) = match target {
        0x89 => {
            // MR: reg = src, rm = dst, mod = 11
            (src_low3, dst_low3, src_ext, dst_ext, 0xC0u8)
        }
        0x8B => {
            // RM: reg = dst, rm = src, mod = 11
            (dst_low3, src_low3, dst_ext, src_ext, 0xC0u8)
        }
        _ /* 0x8D */ => {
            // LEA [reg]: reg = dst, rm = src, mod = 00
            (dst_low3, src_low3, dst_ext, src_ext, 0x00u8)
        }
    };

    let new_rex = 0x48
        | (rex & 0x08) // W (already 1)
        | ((new_rex_r as u8) << 2)
        | (new_rex_b as u8);
    let new_modrm = new_mod | ((new_reg_field & 7) << 3) | (new_rm_field & 7);

    code[i] = new_rex;
    code[i + 1] = target;
    code[i + 2] = new_modrm;
    Some(3)
}


fn try_test_or_and_swap(
    code: &mut [u8],
    rng: &mut Rng,
    i: usize,
    reloc_ranges: &[std::ops::Range<usize>],
) -> Option<usize> {
    if i + 3 > code.len() { return None; }
    let rex = code[i];
    let opcode = code[i + 1];
    let modrm = code[i + 2];
    if !is_rex_w(rex) { return None; }
    if (rex & 0x02) != 0 { return None; } // X = 0

    // We only act on the same-register form; otherwise or/and
    // would actually mutate the destination.
    if (modrm & 0xC0) != 0xC0 { return None; }
    if ((modrm >> 3) & 7) != (modrm & 7) { return None; }
    if ((rex & 0x04) >> 2) != (rex & 0x01) { return None; } // R == B

    let is_test = opcode == 0x85;
    let is_or = opcode == 0x09;
    let is_and = opcode == 0x21;
    if !(is_test || is_or || is_and) { return None; }
    if overlaps_reloc(i, 3, reloc_ranges) { return None; }

    // Pick one of the three opcodes uniformly - staying on the
    // original is a valid outcome.
    let pick = rng.range(3);
    code[i + 1] = match pick { 0 => 0x85, 1 => 0x09, _ => 0x21 };
    Some(3)
}


fn nop_prefix_len(code: &[u8]) -> usize {
    // Try longest first; NOP_VARIANTS is ordered 1..=9.
    for n in (1..=NOP_VARIANTS.len()).rev() {
        let v = NOP_VARIANTS[n - 1];
        if code.len() >= v.len() && &code[..v.len()] == v {
            return v.len();
        }
    }
    0
}

fn redecompose_nop_runs(
    enc: &mut Encoder,
    rng: &mut Rng,
    reloc_ranges: &[std::ops::Range<usize>],
) {
    let mut i = 0;
    while i < enc.code.len() {
        // Find the start of a NOP run.
        let n0 = nop_prefix_len(&enc.code[i..]);
        if n0 == 0 { i += 1; continue; }

        // Walk forward to find the total run length.
        let start = i;
        let mut j = i + n0;
        while j < enc.code.len() {
            let n = nop_prefix_len(&enc.code[j..]);
            if n == 0 { break; }
            j += n;
        }
        let run_len = j - start;

        if !overlaps_reloc(start, run_len, reloc_ranges) && run_len >= 2 {
            let mut staging: Vec<u8> = Vec::with_capacity(run_len);
            let mut remaining = run_len;
            while remaining > 0 {
                let max = remaining.min(NOP_VARIANTS.len());
                let block = 1 + (rng.range(max as u64) as usize);
                staging.extend_from_slice(NOP_VARIANTS[block - 1]);
                remaining -= block;
            }
            enc.code[start..start + run_len].copy_from_slice(&staging);
        }
        i = j;
    }
}


/// True if any label position falls strictly inside at..at+len.
/// A label exactly at at is allowed (it points to the start of
/// the replacement sequence, which is the same byte offset).
fn label_inside(at: usize, len: usize, label_positions: &[usize]) -> bool {
    label_positions.iter().any(|&p| p > at && p < at + len)
}

/// Walk the code buffer, splicing same-semantic length-changing
/// rewrites at each candidate site. Re-fetches reloc and label
/// positions inside the loop because both shift with every splice.
fn expand_equivalents(enc: &mut Encoder, rng: &mut Rng, junk_level: u8) {
    let mut i = 0;
    while i < enc.code.len() {
        let reloc_ranges = enc.code_reloc_ranges();
        let label_positions = enc.code_label_positions();
        let consumed = try_expand_xor_reg_reg(
            enc, rng, i, &reloc_ranges, &label_positions,
        )
        .or_else(|| try_expand_mov_reg_reg(
            enc, rng, i, &reloc_ranges, &label_positions,
        ))
        .or_else(|| try_expand_test_reg_reg(
            enc, rng, i, &reloc_ranges, &label_positions,
        ))
        .or_else(|| try_expand_mov_reg_imm64(
            enc, rng, i, &reloc_ranges, &label_positions,
        ))
        .unwrap_or(0);
        if consumed > 0 {
            let after = i + consumed;
            let junk_inserted = maybe_insert_junk(
                enc, rng, after, junk_level, &reloc_ranges,
                &label_positions,
            );
            i = after + junk_inserted;
        } else {
            i += 1;
        }
    }
}

fn try_expand_xor_reg_reg(
    enc: &mut Encoder,
    rng: &mut Rng,
    i: usize,
    reloc_ranges: &[std::ops::Range<usize>],
    label_positions: &[usize],
) -> Option<usize> {
    if i + 2 <= enc.code.len()
        && enc.code[i] == 0x31
        && (enc.code[i + 1] & 0xC0) == 0xC0
        && ((enc.code[i + 1] >> 3) & 7) == (enc.code[i + 1] & 7)
        && !overlaps_reloc(i, 2, reloc_ranges)
    {
        let modrm = enc.code[i + 1];
        let dst_lo3 = modrm & 7;
        return Some(expand_xor_2byte(enc, rng, i, dst_lo3, label_positions));
    }

    if i + 3 > enc.code.len() { return None; }
    let rex   = enc.code[i];
    let op    = enc.code[i + 1];
    let modrm = enc.code[i + 2];

    if !is_rex_w(rex)               { return None; }
    if (rex & 0x02) != 0            { return None; } // X must be 0
    if op != 0x31                   { return None; } // xor /r
    if (modrm & 0xC0) != 0xC0       { return None; } // mod = 11
    if ((modrm >> 3) & 7) != (modrm & 7) { return None; } // reg == rm
    if ((rex & 0x04) >> 2) != (rex & 0x01) { return None; }
    if overlaps_reloc(i, 3, reloc_ranges) { return None; }

    Some(expand_xor_3byte(enc, rng, i, rex, modrm, label_positions))
}

fn expand_xor_2byte(
    enc: &mut Encoder,
    rng: &mut Rng,
    i: usize,
    dst_lo3: u8,
    label_positions: &[usize],
) -> usize {
    let dice = rng.range(20);

    // Variant A (~30%): keep original.
    if dice < 6 { return 2; }

    // Variant B (~25%): and reg, 0.
    if dice < 11 {
        let new_modrm = 0xC0 | (4 << 3) | dst_lo3;
        let new_bytes = [0x83, new_modrm, 0x00];
        if label_inside(i, 2, label_positions) { return 2; }
        enc.splice(i, 2, &new_bytes);
        return new_bytes.len();
    }

    // Variant C (~25%): mov reg, 0 via B8+rd imm32.
    if dice < 16 {
        let new_bytes = [0xB8 | dst_lo3, 0x00, 0x00, 0x00, 0x00];
        if label_inside(i, 2, label_positions) { return 2; }
        enc.splice(i, 2, &new_bytes);
        return new_bytes.len();
    }

    // Variant D (~20%): nop + original.
    let new_bytes = [0x90, 0x31, enc.code[i + 1]];
    if label_inside(i, 2, label_positions) { return 2; }
    enc.splice(i, 2, &new_bytes);
    new_bytes.len()
}

fn expand_xor_3byte(
    enc: &mut Encoder,
    rng: &mut Rng,
    i: usize,
    rex: u8,
    modrm: u8,
    label_positions: &[usize],
) -> usize {
    let dice = rng.range(20);

    if dice < 6 { return 3; }

    if dice < 11 {
        let dst_rm = modrm & 7;
        let new_modrm = 0xC0 | (4 << 3) | dst_rm;
        let new_rex = (rex & !0x04) | ((rex & 0x01) << 2);
        let new_bytes = [new_rex, 0x83, new_modrm, 0x00];
        if label_inside(i, 3, label_positions) { return 3; }
        enc.splice(i, 3, &new_bytes);
        return new_bytes.len();
    }

    if dice < 16 {
        let dst_rm = modrm & 7;
        let new_modrm = 0xC0 | dst_rm;
        let new_rex = rex & !0x04;
        let new_bytes = [new_rex, 0xC7, new_modrm, 0x00, 0x00, 0x00, 0x00];
        if label_inside(i, 3, label_positions) { return 3; }
        enc.splice(i, 3, &new_bytes);
        return new_bytes.len();
    }

    let new_bytes = [0x48, 0x90, rex, 0x31, modrm];
    if label_inside(i, 3, label_positions) { return 3; }
    enc.splice(i, 3, &new_bytes);
    new_bytes.len()
}


fn try_expand_mov_reg_reg(
    enc: &mut Encoder,
    rng: &mut Rng,
    i: usize,
    reloc_ranges: &[std::ops::Range<usize>],
    label_positions: &[usize],
) -> Option<usize> {
    if i + 3 > enc.code.len() { return None; }
    let rex   = enc.code[i];
    let op    = enc.code[i + 1];
    let modrm = enc.code[i + 2];

    if !is_rex_w(rex)               { return None; }
    if (rex & 0x02) != 0            { return None; }
    if op != 0x89                   { return None; } // mov MR
    if (modrm & 0xC0) != 0xC0       { return None; } // mod = 11
    if overlaps_reloc(i, 3, reloc_ranges) { return None; }

    // src_low3 is modrm.reg; dst_low3 is modrm.rm.
    let src_lo3 = (modrm >> 3) & 7;
    let dst_lo3 = modrm & 7;
    // REX.R extends src; REX.B extends dst.
    let src_ext = (rex & 0x04) != 0;
    let dst_ext = (rex & 0x01) != 0;

    let dice = rng.range(20);

    // Variant A: keep original.
    if dice < 6 {
        return Some(3);
    }

    if dice < 13 {
        if label_inside(i, 3, label_positions) { return Some(3); }
        let mut new_bytes: Vec<u8> = Vec::with_capacity(4);
        // push src
        if src_ext { new_bytes.push(0x41); }
        new_bytes.push(0x50 | src_lo3);
        // pop dst
        if dst_ext { new_bytes.push(0x41); }
        new_bytes.push(0x58 | dst_lo3);
        enc.splice(i, 3, &new_bytes);
        return Some(new_bytes.len());
    }

    // Variant C: keep + prepend REX.W nop (48 90).
    if dice < 17 {
        if label_inside(i, 3, label_positions) { return Some(3); }
        let new_bytes = [0x48, 0x90, rex, op, modrm];
        enc.splice(i, 3, &new_bytes);
        return Some(new_bytes.len());
    }

    // Variant D: convert MR (89) to RM (8B) with swapped modrm.
    // Same length, different bytes - a deep-style mirror of the
    // shallow-pass MR/RM swap with deterministic firing.
    if label_inside(i, 3, label_positions) { return Some(3); }
    // For 8B (RM): modrm.reg = dst_low3, modrm.rm = src_low3.
    // REX.R extends dst, REX.B extends src.
    let new_rex = (rex & !0x05)
        | (if dst_ext { 0x04 } else { 0 })
        | (if src_ext { 0x01 } else { 0 });
    let new_modrm = 0xC0 | (dst_lo3 << 3) | src_lo3;
    let new_bytes = [new_rex, 0x8B, new_modrm];
    enc.splice(i, 3, &new_bytes);
    Some(new_bytes.len())
}


fn try_expand_test_reg_reg(
    enc: &mut Encoder,
    rng: &mut Rng,
    i: usize,
    reloc_ranges: &[std::ops::Range<usize>],
    label_positions: &[usize],
) -> Option<usize> {
    if i + 3 > enc.code.len() { return None; }
    let rex   = enc.code[i];
    let op    = enc.code[i + 1];
    let modrm = enc.code[i + 2];

    if !is_rex_w(rex)               { return None; }
    if (rex & 0x02) != 0            { return None; }
    if op != 0x85                   { return None; } // test /r
    if (modrm & 0xC0) != 0xC0       { return None; }
    if ((modrm >> 3) & 7) != (modrm & 7) { return None; } // self-test
    if ((rex & 0x04) >> 2) != (rex & 0x01) { return None; }
    if overlaps_reloc(i, 3, reloc_ranges) { return None; }

    let dice = rng.range(20);

    // Variant A: keep.
    if dice < 8 { return Some(3); }

    // Variant B: cmp reg, 0 via 83 /7 imm8.
    //   Encoding: REX.W 83 modrm imm8
    if dice < 14 {
        if label_inside(i, 3, label_positions) { return Some(3); }
        let dst_rm = modrm & 7;
        let new_modrm = 0xC0 | (7 << 3) | dst_rm;
        // REX.R must be clear for /7 sub-opcode (reg field is opcode extension).
        let new_rex = rex & !0x04;
        let new_bytes = [new_rex, 0x83, new_modrm, 0x00];
        enc.splice(i, 3, &new_bytes);
        return Some(new_bytes.len());
    }

    // Variant C: or reg, reg via 09 /r (deep-style deterministic
    // pick of one of the shallow same-length swap options).
    //   Encoding: REX.W 09 modrm
    if dice < 18 {
        if label_inside(i, 3, label_positions) { return Some(3); }
        let new_bytes = [rex, 0x09, modrm];
        enc.splice(i, 3, &new_bytes);
        return Some(new_bytes.len());
    }

    // Variant D: keep + REX.W nop prefix.
    if label_inside(i, 3, label_positions) { return Some(3); }
    let new_bytes = [0x48, 0x90, rex, op, modrm];
    enc.splice(i, 3, &new_bytes);
    Some(new_bytes.len())
}


fn try_expand_mov_reg_imm64(
    enc: &mut Encoder,
    rng: &mut Rng,
    i: usize,
    reloc_ranges: &[std::ops::Range<usize>],
    label_positions: &[usize],
) -> Option<usize> {
    if i + 10 > enc.code.len() { return None; }
    let rex = enc.code[i];
    let op  = enc.code[i + 1];

    if !is_rex_w(rex)                       { return None; }
    if (rex & 0x06) != 0                    { return None; } // R, X must be 0
    if (op & 0xF8) != 0xB8                  { return None; } // B8+rd
    if overlaps_reloc(i, 10, reloc_ranges)  { return None; }

    // Read the imm64.
    let mut imm: u64 = 0;
    for k in 0..8 {
        imm |= (enc.code[i + 2 + k] as u64) << (8 * k);
    }

    let dice = rng.range(20);

    // Keep most of the time - this is a high-cost rewrite (no
    // savings, just more instructions) so high firing rates bloat
    // the binary without proportional value.
    if dice < 14 { return Some(10); }

    // Pick a non-trivial 32-bit XOR key K (high bit clear so
    // sign-extension keeps imm64's high bits intact).
    let mut k = rng.next_u64() as u32;
    k &= 0x7FFF_FFFF;
    if k == 0 { k = 0x1234_5678; }

    let masked_imm: u64 = imm ^ (k as u64);

    let _ = (masked_imm, label_positions);
    Some(10)
}


fn maybe_insert_junk(
    enc: &mut Encoder,
    rng: &mut Rng,
    at: usize,
    level: u8,
    reloc_ranges: &[std::ops::Range<usize>],
    label_positions: &[usize],
) -> usize {
    if level == 0 { return 0; }
    if at > enc.code.len() { return 0; }

    let threshold: u64 = match level {
        1 => 1,
        2 => 3,
        3 => 6,
        4 => 10,
        _ => 15,
    };
    if rng.range(20) >= threshold { return 0; }

    // Max junk bytes at this site, also scaled by level:
    //   level 1 -> 2, level 2 -> 3, level 3 -> 5, level 4 -> 7, level 5 -> 9
    let max_bytes: usize = match level {
        1 => 2,
        2 => 3,
        3 => 5,
        4 => 7,
        _ => 9,
    };

    // The site at at is an instruction boundary by construction
    // (we just consumed an expansion). Splicing in junk is safe as
    // long as we don't overlap a reloc or land mid-label.
    if overlaps_reloc(at, 0, reloc_ranges) { return 0; }
    if label_positions.iter().any(|&p| p == at) {
        // A label at at is fine - the splice shifts it forward
        // alongside everything else, so the labelled instruction
        // moves with the junk. No special case needed.
    }

    // Build a junk staging buffer of random length 1..=max_bytes,
    // composed of NOP_VARIANTS blocks of varying sizes.
    let mut staging: Vec<u8> = Vec::with_capacity(max_bytes);
    let want = 1 + (rng.range(max_bytes as u64) as usize);
    while staging.len() < want {
        let remaining = want - staging.len();
        let pick = remaining.min(NOP_VARIANTS.len());
        let block = 1 + (rng.range(pick as u64) as usize);
        staging.extend_from_slice(NOP_VARIANTS[block - 1]);
    }
    // Splice the junk in. splice with old_len=0 inserts.
    enc.splice(at, 0, &staging);
    staging.len()
}


fn encrypt_rdata_data(enc: &mut Encoder, rng: &mut Rng) {
    // Pick the key.
    let mut key = [0u8; 8];
    for slot in key.iter_mut() { *slot = rng.next_u8(); }
    // Avoid a key byte of 0x00 - XOR with zero is the identity,
    // which would leak that byte verbatim. Replace with a random
    // non-zero value.
    for slot in key.iter_mut() {
        if *slot == 0 { *slot = 1 + rng.next_u8().saturating_sub(1).max(1); }
    }

    // Encrypt rdata.
    for (i, b) in enc.rdata.iter_mut().enumerate() {
        *b ^= key[i & 7];
    }
    // Encrypt data (currently unused by codegen but reserved).
    for (i, b) in enc.data.iter_mut().enumerate() {
        *b ^= key[i & 7];
    }

    publish_xor_key(enc, &key);
}

fn publish_xor_key(enc: &mut Encoder, key: &[u8; 8]) {
    // __rdata_end marks the last byte to decrypt. Place it BEFORE
    // appending the key.
    enc.mark_rdata_position("__rdata_end");
    enc.add_rdata_raw_named("__opsec_xor_key", key);
}


/// Internal name the entry function uses to call the decryptor.
pub const DECRYPT_FN_LABEL: &str = "__opsec_decrypt_strings";

pub fn emit_decryptor(enc: &mut Encoder) {
    let loop_label = "__opsec_dec_loop";
    let done_label = "__opsec_dec_done";

    enc.place_code_label(DECRYPT_FN_LABEL);

    enc.push_r64(Reg64::Rax);
    enc.push_r64(Reg64::Rbx);
    enc.push_r64(Reg64::Rcx);
    enc.push_r64(Reg64::Rdx);
    enc.push_r64(Reg64::R8);
    enc.push_r64(Reg64::R9);

    // rax = current rdata ptr, rcx = end ptr, rbx = key ptr.
    enc.lea_r64_data(Reg64::Rax, "__rdata_start");
    enc.lea_r64_data(Reg64::Rcx, "__rdata_end");
    enc.lea_r64_data(Reg64::Rbx, "__opsec_xor_key");
    // rdx = 0 (key cursor).
    enc.xor_r64_r64(Reg64::Rdx, Reg64::Rdx);

    enc.place_code_label(loop_label);
    enc.cmp_r64_r64(Reg64::Rax, Reg64::Rcx);
    enc.jcc_label(Cond::Ae, done_label);   // rax >= rcx  to  done

    // r8b = key[rdx]
    enc.movzx_r64_byte_base_idx(Reg64::R8, Reg64::Rbx, Reg64::Rdx);
    // r9b = *rax
    enc.movzx_r64_byte_r64disp(Reg64::R9, Reg64::Rax, 0);
    // r9 ^= r8
    enc.xor_r64_r64(Reg64::R9, Reg64::R8);
    // *rax = r9.low8
    enc.mov_byte_r64disp_r8(Reg64::Rax, 0, Reg64::R9);

    // Advance pointer + key index, wrap key at 8.
    enc.add_r64_imm8(Reg64::Rax, 1);
    enc.add_r64_imm8(Reg64::Rdx, 1);
    enc.and_r64_imm8(Reg64::Rdx, 7);

    enc.jmp_label(loop_label);

    enc.place_code_label(done_label);
    enc.pop_r64(Reg64::R9);
    enc.pop_r64(Reg64::R8);
    enc.pop_r64(Reg64::Rdx);
    enc.pop_r64(Reg64::Rcx);
    enc.pop_r64(Reg64::Rbx);
    enc.pop_r64(Reg64::Rax);
    enc.ret();
}
