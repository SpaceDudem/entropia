// SPDX-License-Identifier: Apache-2.0
//! Source text -> token stream.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    // literals
    Ident(String),
    Int(i64),
    Str(String),

    // keywords
    Fn, Var, If, Else, While, Ret,
    For, Break, Continue,
    Int_, Str_, Wstr_, Bool_, Void_, Char_, True, False,
    Try, Catch, Raise, Asm, Macro,
    Static, Struct, Enum, UseC, Use, Sizeof,
    Extern,

    // operators
    Plus, Minus, Star, Slash, Percent,
    EqEq, NotEq, Lt, Gt, LtEq, GtEq,
    AndAnd, OrOr, Bang, Assign,
    Amp,                                              // & address-of OR bitwise AND (single; `&&` is AndAnd)
    Pipe, Caret, Tilde,                               // bitwise | ^ ~
    Shl, Shr,                                         // << >>
    PlusPlus, MinusMinus,                             // ++ / --   (postfix, statement-only)
    PlusEq, MinusEq, StarEq, SlashEq, PercentEq,      // += -= *= /= %=  compound assigns
    AmpEq, PipeEq, CaretEq, ShlEq, ShrEq,             // &= |= ^= <<= >>=  bitwise compounds

    // punctuation
    LParen, RParen, LBrace, RBrace, LBrack, RBrack,
    Comma, Semi, Colon, Dot, Arrow,

    Eof,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: Tok,
    pub line: u32,
    pub col:  u32,
}

pub fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0usize;
    let mut line = 1u32;
    let mut col  = 1u32;

    let bump = |i: &mut usize, line: &mut u32, col: &mut u32, n: usize, bytes: &[u8]| {
        for _ in 0..n {
            if *i >= bytes.len() { break; }
            if bytes[*i] == b'\n' { *line += 1; *col = 1; } else { *col += 1; }
            *i += 1;
        }
    };

    while i < bytes.len() {
        let c = bytes[i];

        // whitespace
        if (c as char).is_ascii_whitespace() {
            bump(&mut i, &mut line, &mut col, 1, bytes);
            continue;
        }
        // line comment
        if c == b'/' && i + 1 < bytes.len() && bytes[i+1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' { i += 1; }
            continue;
        }
        // block comment
        if c == b'/' && i + 1 < bytes.len() && bytes[i+1] == b'*' {
            bump(&mut i, &mut line, &mut col, 2, bytes);
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i+1] == b'/') {
                bump(&mut i, &mut line, &mut col, 1, bytes);
            }
            if i + 1 < bytes.len() { bump(&mut i, &mut line, &mut col, 2, bytes); }
            continue;
        }

        let sl = line; let sc = col;

        // identifier / keyword
        if (c as char).is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'_') {
                bump(&mut i, &mut line, &mut col, 1, bytes);
            }
            let id = std::str::from_utf8(&bytes[start..i]).unwrap().to_string();
            let kind = match id.as_str() {
                "fn" => Tok::Fn, "var" => Tok::Var, "if" => Tok::If, "else" => Tok::Else,
                "while" => Tok::While, "ret" => Tok::Ret,
                "for" => Tok::For, "break" => Tok::Break, "continue" => Tok::Continue,
                "int" => Tok::Int_, "str" => Tok::Str_, "wstr" => Tok::Wstr_,
                "bool" => Tok::Bool_,
                "void" => Tok::Void_, "char" => Tok::Char_,
                "true" => Tok::True, "false" => Tok::False,
                "try" => Tok::Try, "catch" => Tok::Catch, "raise" => Tok::Raise,
                "asm" => Tok::Asm, "macro" => Tok::Macro,
                "static" => Tok::Static, "struct" => Tok::Struct,
                "enum" => Tok::Enum,
                "use_c" => Tok::UseC,
                "use" => Tok::Use,
                "extern" => Tok::Extern,
                "sizeof" => Tok::Sizeof,
                _ => Tok::Ident(id),
            };
            out.push(Token { kind, line: sl, col: sc });
            continue;
        }

        // integer
        if (c as char).is_ascii_digit() {
            let start = i;
            // hex literal 0x..
            if c == b'0' && i + 1 < bytes.len() && (bytes[i+1] == b'x' || bytes[i+1] == b'X') {
                bump(&mut i, &mut line, &mut col, 2, bytes);
                let hex_start = i;
                while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                    bump(&mut i, &mut line, &mut col, 1, bytes);
                }
                if hex_start == i {
                    return Err(format!("empty hex literal at {sl}:{sc}"));
                }
                let raw = std::str::from_utf8(&bytes[hex_start..i]).unwrap();
                // Use u64 parse then cast - allows full 64-bit range.
                let v = u64::from_str_radix(raw, 16).map_err(|e| e.to_string())? as i64;
                out.push(Token { kind: Tok::Int(v), line: sl, col: sc });
                continue;
            }
            while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                bump(&mut i, &mut line, &mut col, 1, bytes);
            }
            let raw = std::str::from_utf8(&bytes[start..i]).unwrap();
            let v: i64 = raw.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            out.push(Token { kind: Tok::Int(v), line: sl, col: sc });
            continue;
        }

        // string
        if c == b'"' {
            bump(&mut i, &mut line, &mut col, 1, bytes);
            let mut s = String::new();
            while i < bytes.len() && bytes[i] != b'"' {
                let ch = bytes[i];
                if ch == b'\\' && i + 1 < bytes.len() {
                    bump(&mut i, &mut line, &mut col, 1, bytes);
                    let esc = bytes[i];
                    let mapped = match esc {
                        b'n' => '\n', b't' => '\t', b'r' => '\r',
                        b'0' => '\0', b'\\' => '\\', b'"' => '"',
                        _ => esc as char,
                    };
                    s.push(mapped);
                    bump(&mut i, &mut line, &mut col, 1, bytes);
                } else {
                    s.push(ch as char);
                    bump(&mut i, &mut line, &mut col, 1, bytes);
                }
            }
            if i >= bytes.len() { return Err(format!("unterminated string at {sl}:{sc}")); }
            bump(&mut i, &mut line, &mut col, 1, bytes);
            out.push(Token { kind: Tok::Str(s), line: sl, col: sc });
            continue;
        }

        // symbols
        let two = |a: u8, b: u8| -> bool {
            i + 1 < bytes.len() && bytes[i] == a && bytes[i+1] == b
        };
        let three = |a: u8, b: u8, c2: u8| -> bool {
            i + 2 < bytes.len() && bytes[i] == a && bytes[i+1] == b && bytes[i+2] == c2
        };
        // Match longer sequences first: <<= before << before <= before <.
        let (kind, len) = if three(b'<', b'<', b'=') { (Tok::ShlEq, 3) }
            else if three(b'>', b'>', b'=')  { (Tok::ShrEq, 3) }
            else if two(b'=', b'=')          { (Tok::EqEq, 2) }
            else if two(b'!', b'=')          { (Tok::NotEq, 2) }
            else if two(b'<', b'<')          { (Tok::Shl, 2) }
            else if two(b'>', b'>')          { (Tok::Shr, 2) }
            else if two(b'<', b'=')          { (Tok::LtEq, 2) }
            else if two(b'>', b'=')          { (Tok::GtEq, 2) }
            else if two(b'&', b'&')          { (Tok::AndAnd, 2) }
            else if two(b'|', b'|')          { (Tok::OrOr, 2) }
            else if two(b'-', b'>')          { (Tok::Arrow, 2) }
            // Postfix increment / decrement and compound assigns. ++
            // and += both share a + prefix; match longer first.
            else if two(b'+', b'+')          { (Tok::PlusPlus, 2) }
            else if two(b'-', b'-')          { (Tok::MinusMinus, 2) }
            else if two(b'+', b'=')          { (Tok::PlusEq, 2) }
            else if two(b'-', b'=')          { (Tok::MinusEq, 2) }
            else if two(b'*', b'=')          { (Tok::StarEq, 2) }
            else if two(b'/', b'=')          { (Tok::SlashEq, 2) }
            else if two(b'%', b'=')          { (Tok::PercentEq, 2) }
            else if two(b'&', b'=')          { (Tok::AmpEq, 2) }
            else if two(b'|', b'=')          { (Tok::PipeEq, 2) }
            else if two(b'^', b'=')          { (Tok::CaretEq, 2) }
            else {
                let k = match c {
                    b'+' => Tok::Plus,  b'-' => Tok::Minus,  b'*' => Tok::Star,
                    b'/' => Tok::Slash, b'%' => Tok::Percent,
                    b'<' => Tok::Lt,    b'>' => Tok::Gt,
                    b'!' => Tok::Bang,  b'=' => Tok::Assign,
                    b'&' => Tok::Amp,
                    b'|' => Tok::Pipe,  b'^' => Tok::Caret, b'~' => Tok::Tilde,
                    b'(' => Tok::LParen, b')' => Tok::RParen,
                    b'{' => Tok::LBrace, b'}' => Tok::RBrace,
                    b'[' => Tok::LBrack, b']' => Tok::RBrack,
                    b',' => Tok::Comma, b';' => Tok::Semi,
                    b':' => Tok::Colon, b'.' => Tok::Dot,
                    _ => return Err(format!("unexpected char '{}' at {sl}:{sc}", c as char)),
                };
                (k, 1)
            };
        bump(&mut i, &mut line, &mut col, len, bytes);
        out.push(Token { kind, line: sl, col: sc });
    }
    out.push(Token { kind: Tok::Eof, line, col });
    Ok(out)
}
