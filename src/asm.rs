
use crate::encoder::{Reg64, Segment};

// AST
#[derive(Debug, Clone)]
pub enum AsmOperand {
    Reg(Reg64),
    Imm(i64),
    /// %name - resolved at codegen against the enclosing scope.
    Sym(String),
    Mem(AsmMem),
}

/// [base ± index*scale ± disp]. Components are optional.
#[derive(Debug, Clone)]
pub struct AsmMem {
    /// Register or %name (mutually exclusive in V1).
    pub base:  Option<AsmMemBase>,
    /// (register, scale). Scale ∈ {1,2,4,8}.
    pub index: Option<(Reg64, u32)>,
    pub disp:  i32,
    /// gs: / fs: override (None = flat segment).
    pub seg:   Option<Segment>,
}

#[derive(Debug, Clone)]
pub enum AsmMemBase {
    Reg(Reg64),
    Sym(String),
}

/// Mnemonic is a string so the AST doesn't enumerate every variant;
/// codegen dispatches per-mnemonic.
#[derive(Debug, Clone)]
pub enum AsmBody {
    Op0   { mnem: String },
    Op1   { mnem: String, op:  AsmOperand },
    Op2   { mnem: String, dst: AsmOperand, src: AsmOperand },
    Label (String),
    Db    (Vec<u8>),
}

/// Parsed asm line with source position for debug breadcrumbs.
/// line == 0 is "unknown" (synthetic / pre-parsed).
#[derive(Debug, Clone)]
pub struct AsmLine {
    pub line: u32,
    pub col:  u32,
    pub body: AsmBody,
}

impl AsmLine {
    #[allow(dead_code)]
    pub fn from_body(body: AsmBody) -> Self {
        Self { line: 0, col: 0, body }
    }
}


// PARSER

/// Parse one asm line. Forms: name:, db 0x..[, 0x..]*, or
/// mnem [operand[, operand]]. Empty lines are rejected.
pub fn parse_asm_line(line: &str) -> Result<AsmBody, String> {
    let trimmed = strip_trailing_comment(line).trim();
    if trimmed.is_empty() { return Err("empty asm line".into()); }

    // Label declaration: name: or name :
    if let Some(name) = parse_label_decl(trimmed) {
        return Ok(AsmBody::Label(name));
    }

    // db 0x.., 0x..
    if let Some(rest) = trimmed.strip_prefix("db ").or_else(|| trimmed.strip_prefix("db\t")) {
        return parse_db(rest);
    }

    // Generic mnemonic + comma-separated operands.
    let (mnem, rest) = split_mnemonic(trimmed);
    let operands = if rest.is_empty() {
        Vec::new()
    } else {
        split_top_level_commas(rest)?
            .iter()
            .map(|s| parse_operand(s.trim()))
            .collect::<Result<Vec<_>, _>>()?
    };

    let mnem = mnem.to_ascii_lowercase();
    match operands.len() {
        0 => Ok(AsmBody::Op0 { mnem }),
        1 => Ok(AsmBody::Op1 { mnem, op:  operands.into_iter().next().unwrap() }),
        2 => {
            let mut it = operands.into_iter();
            let dst = it.next().unwrap();
            let src = it.next().unwrap();
            Ok(AsmBody::Op2 { mnem, dst, src })
        }
        n => Err(format!("`{mnem}` takes 0/1/2 operands, got {n}")),
    }
}

/// Strip // ... from EOL. The host parser already removes //
/// from source-level tokens; this catches comments appended to
/// individual asm lines.
fn strip_trailing_comment(line: &str) -> &str {
    if let Some(idx) = line.find("//") { return &line[..idx]; }
    line
}

/// name: -> bare label name. Anything else -> None.
fn parse_label_decl(s: &str) -> Option<String> {
    let body = s.strip_suffix(':')?;
    let name = body.trim();
    if name.is_empty() { return None; }
    validate_ident(name).ok()?;
    Some(name.to_string())
}

/// (mnemonic, rest). Mnemonic ends at the first whitespace.
fn split_mnemonic(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && !(bytes[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    let mnem = &s[..i];
    let rest = s[i..].trim_start();
    (mnem, rest)
}

/// Comma-split, but respect [ ... ] so [rbp + 4*rax] doesn't tear.
fn split_top_level_commas(s: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' | b'(' => depth += 1,
            b']' | b')' => {
                if depth == 0 { return Err("unmatched `]` / `)` in asm operand".into()); }
                depth -= 1;
            }
            b',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 { return Err("unmatched `[` / `(` in asm operand".into()); }
    out.push(&s[start..]);
    Ok(out)
}

fn parse_db(rest: &str) -> Result<AsmBody, String> {
    let mut bytes = Vec::new();
    for piece in rest.split(',') {
        let p = piece.trim();
        let val: i64 = parse_int_literal(p)?;
        if !(0..=0xFF).contains(&val) {
            return Err(format!("db value out of range: {p}"));
        }
        bytes.push(val as u8);
    }
    Ok(AsmBody::Db(bytes))
}

/// Decimal / hex / negative integer literal. Hex needs 0x prefix.
fn parse_int_literal(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if let Some(neg) = s.strip_prefix('-') {
        let v = parse_int_literal(neg)?;
        return Ok(v.wrapping_neg());
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16)
            .map(|v| v as i64)
            .map_err(|e| format!("bad hex literal `{s}`: {e}"));
    }
    s.parse::<i64>().map_err(|e| format!("bad integer `{s}`: {e}"))
}

/// Routes by leading char: [ mem, % sym, digit/- imm, else reg.
fn parse_operand(s: &str) -> Result<AsmOperand, String> {
    let s = s.trim();
    if s.is_empty() { return Err("empty operand".into()); }
    if s.starts_with('[') {
        return parse_mem_operand(s, None);
    }
    // gs:[...] / fs:[...]
    if let Some(rest) = strip_seg_prefix(s) {
        let (seg, body) = rest;
        if !body.starts_with('[') {
            return Err(format!(
                "asm: segment override `{}:` must be followed by `[ ... ]`",
                match seg { Segment::Fs => "fs", Segment::Gs => "gs" }
            ));
        }
        return parse_mem_operand(body, Some(seg));
    }
    if let Some(name) = s.strip_prefix('%') {
        let name = name.trim();
        if name.is_empty() {
            return Err("`%` operand: missing name".into());
        }
        validate_ident(name)?;
        return Ok(AsmOperand::Sym(name.to_string()));
    }
    if s.starts_with('-') || s.as_bytes()[0].is_ascii_digit() {
        return Ok(AsmOperand::Imm(parse_int_literal(s)?));
    }
    // Register name - strictly lowercase to match Reg64::from_name.
    let lower = s.to_ascii_lowercase();
    if let Some(r) = Reg64::from_name(&lower) {
        return Ok(AsmOperand::Reg(r));
    }
    // Bare identifier - equivalent to %name. The % prefix is
    // available for names that could collide with a register.
    if validate_ident(s).is_ok() {
        return Ok(AsmOperand::Sym(s.to_string()));
    }
    Err(format!("unknown operand `{s}` - expected register, immediate, %name, [mem], or label"))
}

/// Strip a fs: / gs: prefix (case-insensitive). Returns
/// (seg, rest) or None.
fn strip_seg_prefix(s: &str) -> Option<(Segment, &str)> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes[2] != b':' { return None; }
    let head = &s[..2];
    let seg = match head {
        "fs" | "Fs" | "fS" | "FS" => Segment::Fs,
        "gs" | "Gs" | "gS" | "GS" => Segment::Gs,
        _ => return None,
    };
    Some((seg, s[3..].trim_start()))
}

/// [reg], [reg ± imm], [reg + reg[*N]], [reg + reg*N ± imm],
/// [%name], [%name ± imm]. Scale ∈ {1,2,4,8}.
fn parse_mem_operand(s: &str, seg: Option<Segment>) -> Result<AsmOperand, String> {
    let body = s.strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .ok_or_else(|| format!("memory operand must be `[ ... ]` (got `{s}`)"))?
        .trim();
    if body.is_empty() {
        return Err("empty `[]` memory operand".into());
    }

    let mut mem = AsmMem { base: None, index: None, disp: 0, seg };
    // Walk +/- separated terms. First term is implicitly positive.
    let mut cursor = 0usize;
    let bytes = body.as_bytes();
    let mut sign: i64 = 1;
    let mut first = true;
    while cursor < bytes.len() {
        while cursor < bytes.len() && (bytes[cursor] as char).is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() { break; }
        if !first {
            match bytes[cursor] {
                b'+' => { sign = 1; cursor += 1; }
                b'-' => { sign = -1; cursor += 1; }
                _ => return Err(format!(
                    "mem operand: expected `+` or `-` between terms in `[{body}]`"
                )),
            }
            while cursor < bytes.len() && (bytes[cursor] as char).is_ascii_whitespace() {
                cursor += 1;
            }
        }
        first = false;

        // Term ends at the next +/- at the top level.
        let term_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b'+' && bytes[cursor] != b'-' {
            cursor += 1;
        }
        let term = body[term_start..cursor].trim();
        if term.is_empty() {
            return Err(format!("mem operand: empty term in `[{body}]`"));
        }
        apply_mem_term(&mut mem, term, sign, body)?;
    }

    Ok(AsmOperand::Mem(mem))
}

/// Fold one term: reg -> base, reg*N -> index, imm -> disp,
/// %name -> sym base.
fn apply_mem_term(mem: &mut AsmMem, term: &str, sign: i64, full: &str) -> Result<(), String> {
    // Scaled index: reg * N
    if let Some(star) = term.find('*') {
        let left  = term[..star].trim();
        let right = term[star + 1..].trim();
        let reg = Reg64::from_name(&left.to_ascii_lowercase())
            .ok_or_else(|| format!("mem operand: `{left}*…` left side must be a register"))?;
        let scale = parse_int_literal(right)? as u32;
        if !matches!(scale, 1 | 2 | 4 | 8) {
            return Err(format!(
                "mem operand: scale must be 1/2/4/8 (got {scale}) in `[{full}]`"
            ));
        }
        if mem.index.is_some() {
            return Err(format!("mem operand: multiple index terms in `[{full}]`"));
        }
        mem.index = Some((reg, scale));
        return Ok(());
    }
    // %name
    if let Some(name) = term.strip_prefix('%') {
        let name = name.trim();
        validate_ident(name)?;
        if mem.base.is_some() {
            return Err(format!("mem operand: two bases in `[{full}]`"));
        }
        mem.base = Some(AsmMemBase::Sym(name.to_string()));
        return Ok(());
    }
    // Register
    let lower = term.to_ascii_lowercase();
    if let Some(reg) = Reg64::from_name(&lower) {
        if mem.base.is_some() {
            // Second register becomes the index (scale 1).
            if mem.index.is_some() {
                return Err(format!(
                    "mem operand: too many register terms in `[{full}]`"
                ));
            }
            mem.index = Some((reg, 1));
        } else {
            mem.base = Some(AsmMemBase::Reg(reg));
        }
        return Ok(());
    }
    // Otherwise: integer literal contributing to disp.
    let v = parse_int_literal(term)?;
    let signed = (sign as i64).wrapping_mul(v);
    let new_disp = (mem.disp as i64).wrapping_add(signed);
    if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
        return Err(format!("mem operand: disp out of range in `[{full}]`"));
    }
    mem.disp = new_disp as i32;
    Ok(())
}

/// [A-Za-z_][A-Za-z0-9_]*.
fn validate_ident(s: &str) -> Result<(), String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err("empty identifier".into());
    }
    let first = bytes[0] as char;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!("identifier `{s}` must start with letter or `_`"));
    }
    for &b in &bytes[1..] {
        let c = b as char;
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("identifier `{s}` has invalid char `{c}`"));
        }
    }
    Ok(())
}

