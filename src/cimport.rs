
use std::fs;

use crate::ast::{Expr, StaticDecl, StructDef};

/// Output of parsing one C header.
#[derive(Debug, Default)]
pub struct CImport {
    pub statics: Vec<StaticDecl>,
    pub structs: Vec<StructDef>,
}

/// Parse a header at path and produce Entropia AST nodes.
pub fn parse_header(path: &str) -> Result<CImport, String> {
    let src = fs::read_to_string(path)
        .map_err(|e| format!("use_c `{path}`: {e}"))?;
    let mut p = CParser::new(&src, path);
    p.parse_all()?;
    Ok(p.out)
}

// TOKENIZER
#[derive(Debug, Clone, PartialEq)]
enum CTok {
    Ident(String),
    Int(i64),
    Hash,            // #
    LBrace, RBrace,
    LParen, RParen,
    LBracket, RBracket,
    Semi,
    Comma,
    Star,
    Minus,
    Eof,
}

struct CTokenizer<'a> {
    src:  &'a [u8],
    pos:  usize,
    line: u32,
    path: String,
}

impl<'a> CTokenizer<'a> {
    fn new(src: &'a str, path: &str) -> Self {
        Self { src: src.as_bytes(), pos: 0, line: 1, path: path.to_string() }
    }

    fn err(&self, msg: &str) -> String {
        format!("{}:{}: {}", self.path, self.line, msg)
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            while self.pos < self.src.len() && (self.src[self.pos] as char).is_ascii_whitespace() {
                if self.src[self.pos] == b'\n' { self.line += 1; }
                self.pos += 1;
            }
            if self.pos + 1 < self.src.len() && self.src[self.pos] == b'/' && self.src[self.pos+1] == b'/' {
                while self.pos < self.src.len() && self.src[self.pos] != b'\n' { self.pos += 1; }
                continue;
            }
            if self.pos + 1 < self.src.len() && self.src[self.pos] == b'/' && self.src[self.pos+1] == b'*' {
                self.pos += 2;
                while self.pos + 1 < self.src.len()
                      && !(self.src[self.pos] == b'*' && self.src[self.pos+1] == b'/')
                {
                    if self.src[self.pos] == b'\n' { self.line += 1; }
                    self.pos += 1;
                }
                if self.pos + 1 < self.src.len() { self.pos += 2; }
                continue;
            }
            break;
        }
    }

    fn next(&mut self) -> Result<CTok, String> {
        self.skip_ws_and_comments();
        if self.pos >= self.src.len() { return Ok(CTok::Eof); }
        let c = self.src[self.pos];

        if (c as char).is_ascii_alphabetic() || c == b'_' {
            let start = self.pos;
            while self.pos < self.src.len()
                  && ((self.src[self.pos] as char).is_ascii_alphanumeric()
                      || self.src[self.pos] == b'_')
            {
                self.pos += 1;
            }
            let id = std::str::from_utf8(&self.src[start..self.pos]).unwrap().to_string();
            return Ok(CTok::Ident(id));
        }

        if (c as char).is_ascii_digit() {
            let start = self.pos;
            if c == b'0' && self.pos + 1 < self.src.len()
                && (self.src[self.pos+1] == b'x' || self.src[self.pos+1] == b'X')
            {
                self.pos += 2;
                let hs = self.pos;
                while self.pos < self.src.len()
                      && (self.src[self.pos] as char).is_ascii_hexdigit()
                {
                    self.pos += 1;
                }
                let raw = std::str::from_utf8(&self.src[hs..self.pos]).unwrap();
                let v = u64::from_str_radix(raw, 16)
                    .map_err(|e| self.err(&format!("bad hex literal: {e}")))? as i64;
                self.skip_int_suffix();
                return Ok(CTok::Int(v));
            }
            while self.pos < self.src.len() && (self.src[self.pos] as char).is_ascii_digit() {
                self.pos += 1;
            }
            let raw = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
            let v: i64 = raw.parse()
                .map_err(|e: std::num::ParseIntError| self.err(&format!("bad int literal: {e}")))?;
            self.skip_int_suffix();
            return Ok(CTok::Int(v));
        }

        let tok = match c {
            b'#' => CTok::Hash,
            b'{' => CTok::LBrace,    b'}' => CTok::RBrace,
            b'(' => CTok::LParen,    b')' => CTok::RParen,
            b'[' => CTok::LBracket,  b']' => CTok::RBracket,
            b';' => CTok::Semi,
            b',' => CTok::Comma,
            b'*' => CTok::Star,
            b'-' => CTok::Minus,
            _ => return Err(self.err(&format!("unexpected character `{}`", c as char))),
        };
        self.pos += 1;
        Ok(tok)
    }

    fn skip_int_suffix(&mut self) {
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if c == b'u' || c == b'U' || c == b'l' || c == b'L' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
}


// PARSER
struct CParser<'a> {
    tok:      CTokenizer<'a>,
    cur:      CTok,
    /// Currently-known type names. Starts with the C primitive type-spelling
    /// vocabulary; grows as the file declares typedefs, structs, and unions.
    typedefs: std::collections::HashMap<String, String>,
    /// Struct/union tags declared so far. Used to resolve struct Tag and
    /// union Tag references.
    struct_tags: std::collections::HashSet<String>,
    out:      CImport,
    path:     String,
    /// Counter for anonymous nested struct/union types synthesized from
    /// struct { ... } name; fields.
    anon_counter: usize,
}

impl<'a> CParser<'a> {
    fn new(src: &'a str, path: &str) -> Self {
        let mut typedefs = std::collections::HashMap::new();
        for (c_name, ek_name) in PRIMITIVES {
            typedefs.insert(c_name.to_string(), ek_name.to_string());
        }
        let mut tok = CTokenizer::new(src, path);
        let cur = tok.next().unwrap_or(CTok::Eof);
        Self {
            tok,
            cur,
            typedefs,
            struct_tags: std::collections::HashSet::new(),
            out: CImport::default(),
            path: path.to_string(),
            anon_counter: 0,
        }
    }

    fn err(&self, msg: &str) -> String {
        format!("{}:{}: {}", self.path, self.tok.line, msg)
    }

    fn advance(&mut self) -> Result<CTok, String> {
        let prev = std::mem::replace(&mut self.cur, CTok::Eof);
        self.cur = self.tok.next()?;
        Ok(prev)
    }

    fn peek_ident(&self) -> Option<&str> {
        if let CTok::Ident(s) = &self.cur { Some(s.as_str()) } else { None }
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        match &self.cur {
            CTok::Ident(s) => { let s = s.clone(); self.advance()?; Ok(s) }
            other => Err(self.err(&format!("expected identifier, got {other:?}"))),
        }
    }

    fn expect(&mut self, t: &CTok, what: &str) -> Result<(), String> {
        if std::mem::discriminant(&self.cur) == std::mem::discriminant(t) {
            self.advance()?; Ok(())
        } else {
            Err(self.err(&format!("expected {what}, got {:?}", self.cur)))
        }
    }

    /// Skip "__attribute__((...))", "__declspec"", and SAL annotation
    /// idents like _In_, _Out_, _Reserved_. Returns true if at least
    /// one annotation was eaten so callers can re-check cur.
    fn skip_annotations(&mut self) -> Result<bool, String> {
        let mut ate = false;
        loop {
            let name = match self.peek_ident() {
                Some(s) => s.to_string(),
                None => break,
            };
            let is_attr = name == "__attribute__"
                       || name == "__declspec"
                       || name == "__cdecl"
                       || name == "__stdcall"
                       || name == "__fastcall"
                       || name == "__pragma"
                       || name == "STDMETHODCALLTYPE"
                       || name == "WINAPI"
                       || name == "CALLBACK"
                       || name == "APIENTRY"
                       || name == "NTAPI"
                       || name == "WSAAPI";
            let is_sal = name.starts_with('_')
                      && name.ends_with('_')
                      && name.len() >= 3
                      && name.chars().nth(1).map_or(false, |c| c.is_ascii_uppercase());
            if !(is_attr || is_sal) { break; }
            self.advance()?;
            // Some attributes are followed by (...). Eat balanced parens.
            if matches!(self.cur, CTok::LParen) {
                self.eat_balanced_parens()?;
            }
            ate = true;
        }
        Ok(ate)
    }

    /// Process a balanced "(...)"" block. The opening paren must be the
    /// current token. We process it and everything up to (and including) its matching close.
    /// Used for annotation arguments and to skip function-pointer parameter lists we don't model.
    fn eat_balanced_parens(&mut self) -> Result<(), String> {
        self.expect(&CTok::LParen, "`(`")?;
        let mut depth: i32 = 1;
        while depth > 0 {
            match &self.cur {
                CTok::LParen => depth += 1,
                CTok::RParen => depth -= 1,
                CTok::Eof    => return Err(self.err("unterminated `(...)`")),
                _ => {}
            }
            self.advance()?;
        }
        Ok(())
    }

    fn parse_all(&mut self) -> Result<(), String> {
        loop {
            self.skip_annotations()?;
            match &self.cur {
                CTok::Eof => return Ok(()),
                CTok::Hash => self.parse_define()?,
                CTok::Ident(s) if s == "typedef" => self.parse_typedef()?,
                CTok::Ident(s) if s == "struct"  => self.parse_record_decl(false)?,
                CTok::Ident(s) if s == "union"   => self.parse_record_decl(true)?,
                CTok::Semi => { self.advance()?; }
                other => return Err(self.err(&format!(
                    "expected `#define`, `typedef`, `struct`, or `union` at top level, got {other:?}"
                ))),
            }
        }
    }

    /// # define IDENT INTEGER
    fn parse_define(&mut self) -> Result<(), String> {
        self.advance()?; // eat #
        let kw = self.expect_ident()?;
        if kw != "define" {
            return Err(self.err(&format!("only `#define` is supported, got `#{kw}`")));
        }
        let name = self.expect_ident()?;
        let negate = if matches!(self.cur, CTok::Minus) {
            self.advance()?;
            true
        } else {
            false
        };
        let val = match &self.cur {
            CTok::Int(n) => { let v = *n; self.advance()?; if negate { -v } else { v } }
            other => return Err(self.err(&format!(
                "`#define {name}` must be followed by an integer literal (got {other:?}); \
                 function-like macros aren't supported"
            ))),
        };
        self.out.statics.push(StaticDecl {
            name,
            ty: "u32".to_string(),
            init: Some(Expr::Int(val)),
        });
        Ok(())
    }

    fn parse_typedef(&mut self) -> Result<(), String> {
        self.advance()?; // eat `typedef`
        self.skip_annotations()?;

        // typedef struct/union ...
        if let CTok::Ident(s) = &self.cur {
            if s == "struct" || s == "union" {
                let is_union = s == "union";
                self.advance()?;
                self.skip_annotations()?;
                // Optional tag.
                let tag = if let CTok::Ident(t) = &self.cur {
                    let t = t.clone();
                    self.advance()?;
                    if matches!(self.cur, CTok::LBrace) {
                        Some(t)
                    } else {
                        // typedef struct OldTag NEW [, *PALIAS]*;
                        let new_name = self.expect_ident()?;
                        self.skip_pointer_aliases()?;
                        self.expect(&CTok::Semi, "`;`")?;
                        self.typedefs.insert(new_name, t);
                        return Ok(());
                    }
                } else { None };
                self.expect(&CTok::LBrace, "`{`")?;
                let fields = self.parse_field_list()?;
                self.expect(&CTok::RBrace, "`}`")?;
                let typedef_name = self.expect_ident()?;
                self.skip_pointer_aliases()?;
                self.expect(&CTok::Semi, "`;`")?;
                self.out.structs.push(StructDef {
                    name: typedef_name.clone(),
                    fields,
                    is_union,
                    attrs: Vec::new(),
                });
                self.struct_tags.insert(typedef_name.clone());
                if let Some(t) = tag {
                    self.typedefs.insert(t.clone(), typedef_name.clone());
                    self.struct_tags.insert(t);
                }
                return Ok(());
            }
        }

        // Plain typedef: typedef <type> <newname> [array]?;
        // OR function pointer:  typedef <ret> [CC] (*NEW)(PARAMS);
        let base = self.parse_type_specifier()?;
        let stars = self.eat_pointer_stars();
        self.skip_annotations()?;

        // Function pointer: an open paren here means we're in
        // typedef RET (*NAME)(...) or typedef RET (CC *NAME)(...).
        if matches!(self.cur, CTok::LParen) {
            return self.parse_function_pointer_typedef();
        }

        let resolved = if stars > 0 { "u64".to_string() } else { base };
        let new_name = self.expect_ident()?;
        // Optional array suffix: typedef int Foo[3];  to  register Foo as
        // an array typedef int[3]. Common in WinSDK headers.
        let final_ty = if matches!(self.cur, CTok::LBracket) {
            self.advance()?;
            let n = match &self.cur {
                CTok::Int(n) => { let v = *n as usize; self.advance()?; v }
                other => return Err(self.err(&format!(
                    "expected integer array length in typedef, got {other:?}"
                ))),
            };
            self.expect(&CTok::RBracket, "`]`")?;
            format!("{resolved}[{n}]")
        } else {
            resolved
        };
        self.skip_pointer_aliases()?;
        self.expect(&CTok::Semi, "`;`")?;
        self.typedefs.insert(new_name, final_ty);
        Ok(())
    }

    fn parse_function_pointer_typedef(&mut self) -> Result<(), String> {
        self.expect(&CTok::LParen, "`(`")?;
        self.skip_annotations()?;
        // Optional inner * (or several). At least one is required for a
        // function-pointer typedef but we're forgiving.
        let _stars = self.eat_pointer_stars();
        self.skip_annotations()?;
        let name = self.expect_ident()?;
        self.expect(&CTok::RParen, "`)`")?;
        // Skip the parameter list.
        self.eat_balanced_parens()?;
        // Some headers stick attributes between the params and ;.
        self.skip_annotations()?;
        self.expect(&CTok::Semi, "`;`")?;
        self.typedefs.insert(name, "u64".to_string());
        Ok(())
    }

    /// struct|union NAME { fields }; - declaration without typedef.
    /// Or struct NAME; - forward declaration, registered as a struct
    /// tag of opaque size (treated as void* if used as a field).
    fn parse_record_decl(&mut self, is_union: bool) -> Result<(), String> {
        self.advance()?; // eat `struct` or `union`
        self.skip_annotations()?;
        let name = self.expect_ident()?;
        if matches!(self.cur, CTok::Semi) {
            self.advance()?;
            self.struct_tags.insert(name);
            return Ok(());
        }
        self.expect(&CTok::LBrace, "`{`")?;
        let fields = self.parse_field_list()?;
        self.expect(&CTok::RBrace, "`}`")?;
        self.expect(&CTok::Semi, "`;`")?;
        self.struct_tags.insert(name.clone());
        self.out.structs.push(StructDef { name, fields, is_union, attrs: Vec::new() });
        Ok(())
    }

    /// <type> <name> [[N]] ; repeated until }. Also handles
    /// nested struct|union { fields } name; and RET (*name)(...)
    /// function-pointer fields.
    fn parse_field_list(&mut self) -> Result<Vec<(String, String)>, String> {
        let mut fields = Vec::new();
        while !matches!(self.cur, CTok::RBrace) {
            self.skip_annotations()?;

            // Nested record: struct { ... } name; or union { ... } name;
            // (named or anonymous tag). The tag, if present, is recorded
            // and the synthesized name is used for the field type.
            if let CTok::Ident(s) = &self.cur {
                if s == "struct" || s == "union" {
                    let is_union_inner = s == "union";
                    // Peek-by-advance: save state for the rare case the
                    // construct is struct Tag field; (use of a
                    // previously-declared record by tag, no braces).
                    self.advance()?;
                    self.skip_annotations()?;
                    let tag = if let CTok::Ident(t) = &self.cur {
                        let t = t.clone();
                        self.advance()?;
                        Some(t)
                    } else { None };

                    if matches!(self.cur, CTok::LBrace) {
                        // Inline definition. Synthesize a name.
                        let syn = match &tag {
                            Some(t) if !t.is_empty() => t.clone(),
                            _ => {
                                self.anon_counter += 1;
                                format!("__anon_{}_{}", if is_union_inner {"u"} else {"s"}, self.anon_counter)
                            }
                        };
                        self.expect(&CTok::LBrace, "`{`")?;
                        let inner_fields = self.parse_field_list()?;
                        self.expect(&CTok::RBrace, "`}`")?;
                        self.out.structs.push(StructDef {
                            name: syn.clone(),
                            fields: inner_fields,
                            is_union: is_union_inner,
                            attrs: Vec::new(),
                        });
                        self.struct_tags.insert(syn.clone());

                        self.skip_annotations()?;
                        if matches!(self.cur, CTok::Semi) {
                            // Anonymous member - synthesize a field name.
                            self.advance()?;
                            let fname = format!("__anon_field_{}", self.anon_counter);
                            fields.push((fname, syn));
                            continue;
                        }
                        let fname = self.expect_ident()?;
                        let arr = self.maybe_array_suffix()?;
                        self.expect(&CTok::Semi, "`;`")?;
                        let final_ty = match arr {
                            None    => syn,
                            Some(n) => format!("{syn}[{n}]"),
                        };
                        fields.push((fname, final_ty));
                        continue;
                    } else {
                        let base = tag.clone().ok_or_else(|| self.err(
                            "expected `{` or a tag after `struct`/`union` in field"
                        ))?;
                        let stars = self.eat_pointer_stars();
                        self.skip_annotations()?;
                        let fname = self.expect_ident()?;
                        let arr = self.maybe_array_suffix()?;
                        self.expect(&CTok::Semi, "`;`")?;
                        let elem_ty = if stars > 0 { "u64".to_string() } else { base };
                        let final_ty = match arr {
                            None    => elem_ty,
                            Some(n) => format!("{elem_ty}[{n}]"),
                        };
                        fields.push((fname, final_ty));
                        continue;
                    }
                }
            }

            // Standard field: <type-spec> [*]* <name> [[N]]?;. Also
            // handles function-pointer fields: <ret> (CC *name)(...);.
            let base = self.parse_type_specifier()?;
            let stars = self.eat_pointer_stars();
            self.skip_annotations()?;

            // Function-pointer field: <ret> (*name)(params) or with
            // calling-convention prefix. Collapses to u64.
            if matches!(self.cur, CTok::LParen) {
                self.expect(&CTok::LParen, "`(`")?;
                self.skip_annotations()?;
                let _inner_stars = self.eat_pointer_stars();
                self.skip_annotations()?;
                let fname = self.expect_ident()?;
                self.expect(&CTok::RParen, "`)`")?;
                self.eat_balanced_parens()?;
                self.skip_annotations()?;
                self.expect(&CTok::Semi, "`;`")?;
                fields.push((fname, "u64".to_string()));
                continue;
            }

            let fname = self.expect_ident()?;
            let arr = self.maybe_array_suffix()?;
            self.skip_annotations()?;
            self.expect(&CTok::Semi, "`;`")?;

            let elem_ty = if stars > 0 { "u64".to_string() } else { base };
            let final_ty = match arr {
                None    => elem_ty,
                Some(n) => format!("{elem_ty}[{n}]"),
            };
            fields.push((fname, final_ty));
        }
        Ok(fields)
    }

    /// Optional [N] after an identifier in a field/typedef. Returns
    /// Some if present, None if not.
    fn maybe_array_suffix(&mut self) -> Result<Option<usize>, String> {
        if !matches!(self.cur, CTok::LBracket) { return Ok(None); }
        self.advance()?;
        let n = match &self.cur {
            CTok::Int(n) => { let v = *n as usize; self.advance()?; v }
            other => return Err(self.err(&format!(
                "expected integer array length, got {other:?}"
            ))),
        };
        self.expect(&CTok::RBracket, "`]`")?;
        Ok(Some(n))
    }

    /// Read one type-specifier: optionally signed/unsigned followed by an
    /// integer keyword (char/short/int/long/long long), OR a struct Tag,
    /// OR a union Tag, OR a previously-defined typedef.
    fn parse_type_specifier(&mut self) -> Result<String, String> {
        loop {
            if let CTok::Ident(s) = &self.cur {
                if s == "const" || s == "volatile" || s == "restrict" { self.advance()?; continue; }
            }
            break;
        }
        // struct Tag or union Tag
        if let CTok::Ident(s) = &self.cur {
            if s == "struct" || s == "union" {
                self.advance()?;
                let tag = self.expect_ident()?;
                // Auto-register the tag as a known type so forward
                // references through pointers (struct Foo*) work
                // even if the definition appears later.
                self.struct_tags.insert(tag.clone());
                return Ok(tag);
            }
        }
        let mut is_unsigned = None::<bool>;
        if let CTok::Ident(s) = &self.cur {
            if s == "unsigned" { is_unsigned = Some(true);  self.advance()?; }
            else if s == "signed" { is_unsigned = Some(false); self.advance()?; }
        }
        let kw = match &self.cur {
            CTok::Ident(s) => s.clone(),
            other => return Err(self.err(&format!("expected type, got {other:?}"))),
        };
        match kw.as_str() {
            "char"     => { self.advance()?; Ok(if is_unsigned.unwrap_or(true)  { "u8".into() } else { "i8".into() }) }
            "short"    => { self.advance()?; Ok(if is_unsigned.unwrap_or(false) { "u16".into() } else { "i16".into() }) }
            "int"      => { self.advance()?; Ok(if is_unsigned.unwrap_or(false) { "u32".into() } else { "i32".into() }) }
            "long"     => {
                self.advance()?;
                let is_ll = matches!(&self.cur, CTok::Ident(s) if s == "long");
                if is_ll { self.advance()?; }
                let size_bits = if is_ll { 64 } else { 32 };
                Ok(match (is_unsigned.unwrap_or(false), size_bits) {
                    (true,  64) => "u64".into(),
                    (false, 64) => "i64".into(),
                    (true,  32) => "u32".into(),
                    (false, 32) => "i32".into(),
                    _ => unreachable!(),
                })
            }
            other => {
                if is_unsigned.is_some() {
                    return Err(self.err(&format!(
                        "`{}{kw}` is not a valid C integer type",
                        if is_unsigned == Some(true) { "unsigned " } else { "signed " }
                    )));
                }
                if other == "void" {
                    self.advance()?;
                    return Ok("void".into());
                }
                self.advance()?;
                if let Some(resolved) = self.typedefs.get(other) {
                    Ok(resolved.clone())
                } else if self.struct_tags.contains(other) {
                    Ok(other.to_string())
                } else {
                    Err(self.err(&format!("unknown type `{other}`")))
                }
            }
        }
    }

    fn eat_pointer_stars(&mut self) -> usize {
        let mut n = 0;
        while matches!(self.cur, CTok::Star) {
            let _ = self.advance();
            n += 1;
        }
        n
    }

    /// , *ALIAS [, *ALIAS2]* - common C pattern after a typedef to also
    /// expose a pointer alias. We register the alias names as u64 typedefs
    /// so they're usable in subsequent <type> name positions.
    fn skip_pointer_aliases(&mut self) -> Result<(), String> {
        while matches!(self.cur, CTok::Comma) {
            self.advance()?;
            let _stars = self.eat_pointer_stars();
            if let CTok::Ident(s) = &self.cur {
                let n = s.clone();
                self.advance()?;
                self.typedefs.insert(n, "u64".to_string());
            } else {
                return Err(self.err("expected identifier after `,`"));
            }
        }
        Ok(())
    }
}

/// C primitive spellings  to  Entropia canonical type names.
// These get pre-loaded into the typedef table so user-written headers can refer to them by either form.
const PRIMITIVES: &[(&str, &str)] = &[
    ("uint8_t",  "u8"),
    ("uint16_t", "u16"),
    ("uint32_t", "u32"),
    ("uint64_t", "u64"),
    ("int8_t",   "i8"),
    ("int16_t",  "i16"),
    ("int32_t",  "i32"),
    ("int64_t",  "i64"),
    ("size_t",   "u64"),
    ("ptrdiff_t","i64"),
    ("uintptr_t","u64"),
    ("intptr_t", "i64"),
    ("FILE",     "u64"),
];
