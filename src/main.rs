
use std::env;
use std::fs;
use std::io::Write;
use std::process::ExitCode;

mod ast;
mod asm;
mod cimport;
mod codegen;
mod coff;
mod dce;
mod encoder;
mod gc;
mod lexer;
mod macros;
mod parser;
pub mod polymorphism;
mod resolver;
mod shared;
mod veh;
mod typecheck;
mod overflow;

const SRC_EXT: &str = ".etpy";

fn compile(
    path:    &str,
    gc_mode: codegen::GcMode,
    kind:    codegen::BuildKind,
    opsec:   polymorphism::OpsecConfig,
) -> Result<codegen::CompiledBlob, String> {
    if !path.ends_with(SRC_EXT) {
        return Err(format!(
            "input file `{path}` does not end in `{SRC_EXT}` - \
             did you mean the source, not the compiled output?"
        ));
    }
    let src = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let tokens = lexer::tokenize(&src)?;
    let mut prog = parser::Parser::new(tokens.clone(), path).parse_program()?;

    let mut auto_includes: Vec<(&str, String)> = Vec::new();

    let syscall_stub_subpath = if opsec.indirect_syscalls {
        Some(("opsec/indirect_syscall.etpy", "indirect_syscalls"))
    } else if opsec.direct_syscalls {
        Some(("opsec/direct_syscall.etpy", "direct_syscalls"))
    } else {
        None
    };
    if let Some((subpath, label)) = syscall_stub_subpath {
        let has_user_ntcall = prog.functions.iter().any(|f| {
            f.attrs.iter().any(|a|
                a.kind == "Override" && a.arg.as_deref() == Some("NtCall"))
        });
        if !has_user_ntcall {
            let resolved = resolve_stdlib_subpath(path, subpath)
                .ok_or_else(|| format!(
                    "--opsec={label}: couldn't locate `stdlib/{subpath}` \
                     walking up from the source. Build from inside \
                     the workspace, or add a manual `use \"...\";` \
                     to your source."
                ))?;
            auto_includes.push((label, resolved));
        }
    }

    if let Some(subpath) = opsec.sleep_mask.stdlib_subpath() {
        let has_user_sleep_hook = prog.functions.iter().any(|f| {
            f.attrs.iter().any(|a|
                a.kind == "Hook" && a.arg.as_deref() == Some("KERNEL32$Sleep"))
        });
        if !has_user_sleep_hook {
            let label = "sleep_mask";
            let resolved = resolve_stdlib_subpath(path, subpath)
                .ok_or_else(|| format!(
                    "--opsec=sleep_mask={}: couldn't locate \
                     `stdlib/{subpath}` walking up from the source. \
                     Build from inside the workspace, or write the \
                     hook by hand and drop the flag.",
                    opsec.sleep_mask.name()
                ))?;
            auto_includes.push((label, resolved));
        }
    }

    if !auto_includes.is_empty() {
        let mut combined: Vec<lexer::Token> = Vec::new();
        for (_, resolved) in &auto_includes {
            combined.extend(synthetic_use_tokens(resolved));
        }
        let mut body = tokens.clone();
        let _ = body.pop();   // drop trailing EOF
        combined.extend(body);
        combined.push(lexer::Token {
            kind: lexer::Tok::Eof,
            line: 1, col: 1,
        });
        prog = parser::Parser::new(combined, path).parse_program()?;
    }

    auto_include_win32_constants(&mut prog, path)?;

    synthesize_bof_arg_parsers(&mut prog);

    resolve_enum_accesses(&mut prog)?;

    if let Err(errs) = typecheck::check_with_kind(&prog, kind) {
        return Err(errs.join("\n\n"));
    }
    if let Err(errs) = overflow::check(&prog) {
        return Err(errs.join("\n\n"));
    }

    dce::eliminate_with_kind(&mut prog, kind);

    let cna_script = build_cna_script(&prog, path);

    let mut blob = codegen::CodeGen::with_opsec(gc_mode, kind, opsec).generate_with_debug(&prog)?;
    blob.cna_script = cna_script;
    Ok(blob)
}

fn build_cna_script(prog: &ast::Program, source_path: &str) -> Option<String> {
    // Find [BofCommand] on go.
    let go_fn = prog.functions.iter().find(|f| f.name == "go" && !f.is_extern)?;
    let cmd_attr = go_fn.attrs.iter().find(|a| a.kind == "BofCommand")?;
    let cmd_name = cmd_attr.arg.clone()?;

    // Find the [BofArgs] struct (zero or one). If present, derive
    // the bof_pack format string and parameter list.
    let bof_args = prog.structs.iter()
        .find(|s| s.attrs.iter().any(|a| a.kind == "BofArgs"));

    let (pack_spec, sleep_param_names, usage_args) = if let Some(s) = bof_args {
        let mut spec = String::new();
        let mut names = Vec::new();
        let mut usage = Vec::new();
        for (fname, fty) in &s.fields {
            let c = match fty.as_str() {
                "int" | "i32" | "u32" => 'i',
                "i16" | "u16"          => 's',
                "str" | "char*" | "u8*" => 'z',
                _ => {
                    eprintln!(
                        "warning: [BofCommand] cna gen: field `{fname}: {fty}` \
                         in struct `{}` has no bof_pack mapping. The generated \
                         .cna will skip this argument; edit it by hand if you \
                         need the field.", s.name);
                    continue;
                }
            };
            spec.push(c);
            names.push(format!("${fname}"));
            usage.push(format!("<{fname}>"));
        }
        (spec, names, usage)
    } else {
        (String::new(), Vec::new(), Vec::new())
    };

    // Cobalt Strike convention: BOFs ship as name.x64.o so the
    // operator-side script_resource lookup matches.
    let obj_basename = std::path::Path::new(source_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| format!("{s}.x64.o"))
        .unwrap_or_else(|| format!("{cmd_name}.x64.o"));

    let expected_args = sleep_param_names.len();
    let usage_str = if usage_args.is_empty() { String::new() } else { format!(" {}", usage_args.join(" ")) };
    let pack_call = if pack_spec.is_empty() {
        format!("bof_inline_execute($bid, script_resource(\"{obj_basename}\"), \"{cmd_name}\", \"\");")
    } else {
        format!(
            "$args = bof_pack($bid, \"{pack_spec}\", {});\n\
             \tbof_inline_execute($bid, script_resource(\"{obj_basename}\"), \"{cmd_name}\", $args);",
            sleep_param_names.join(", ")
        )
    };
    let destructure = if sleep_param_names.is_empty() {
        format!("local('$bid');\n\t$bid = $1;")
    } else {
        format!(
            "local('$bid {}');\n\tif (size(@_) != {}) {{ berror($1, \"usage: {cmd_name}{usage_str}\"); return; }}\n\t($bid, {}) = @_;",
            sleep_param_names.join(" "),
            expected_args + 1,
            sleep_param_names.join(", ")
        )
    };

    Some(format!(
        "# {cmd_name}.cna\n\
         # Auto-generated by entc from {source_path}.\n\
         # Do not edit by hand; regenerate by rebuilding the .obj.\n\n\
         alias {cmd_name} {{\n\
         \t{destructure}\n\
         \t{pack_call}\n\
         }}\n\n\
         beacon_command_register(\n\
         \t\"{cmd_name}\",\n\
         \t\"Auto-generated BOF command from {source_path}\",\n\
         \t\"Usage: {cmd_name}{usage_str}\");\n"
    ))
}

fn resolve_enum_accesses(prog: &mut ast::Program) -> Result<(), String> {
    use ast::{Expr, Stmt};

    if prog.enums.is_empty() { return Ok(()); }

    let mut variants: std::collections::HashMap<(String, String), i128> =
        std::collections::HashMap::new();
    let mut enum_names: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for e in &prog.enums {
        enum_names.insert(e.name.clone());
        for (vname, value) in &e.variants {
            variants.insert((e.name.clone(), vname.clone()), *value as i128);
        }
    }

    fn rewrite_expr(
        e: &mut Expr,
        variants: &std::collections::HashMap<(String, String), i128>,
        enums: &std::collections::HashSet<String>,
    ) -> Result<(), String> {
        match e {
            Expr::Field { base, field } => {
                // Recurse first so nested expressions get rewritten.
                rewrite_expr(base, variants, enums)?;
                if let Expr::Var(name) = base.as_ref() {
                    if enums.contains(name) {
                        let key = (name.clone(), field.clone());
                        let value = variants.get(&key).ok_or_else(|| format!(
                            "enum `{name}` has no variant `{field}`"
                        ))?;
                        *e = Expr::Int(*value as i128);
                        return Ok(());
                    }
                }
            }
            Expr::Call { args, .. } => {
                for a in args { rewrite_expr(a, variants, enums)?; }
            }
            Expr::Binary { lhs, rhs, .. } => {
                rewrite_expr(lhs, variants, enums)?;
                rewrite_expr(rhs, variants, enums)?;
            }
            Expr::Unary { operand, .. } => rewrite_expr(operand, variants, enums)?,
            Expr::Assign { value, .. } => rewrite_expr(value, variants, enums)?,
            Expr::FieldAssign { base, value, .. } => {
                rewrite_expr(base, variants, enums)?;
                rewrite_expr(value, variants, enums)?;
            }
            Expr::DerefAssign { ptr, value } => {
                rewrite_expr(ptr, variants, enums)?;
                rewrite_expr(value, variants, enums)?;
            }
            Expr::Index { base, index } => {
                rewrite_expr(base, variants, enums)?;
                rewrite_expr(index, variants, enums)?;
            }
            Expr::IndexAssign { base, index, value } => {
                rewrite_expr(base, variants, enums)?;
                rewrite_expr(index, variants, enums)?;
                rewrite_expr(value, variants, enums)?;
            }
            Expr::Cast { expr, .. } => rewrite_expr(expr, variants, enums)?,
            Expr::StructLit { fields, .. } => {
                for (_, fv) in fields { rewrite_expr(fv, variants, enums)?; }
            }
            Expr::Int(_) | Expr::Bool(_) | Expr::Str(_)
                | Expr::Var(_) | Expr::SizeOf { .. } => {}
        }
        Ok(())
    }

    fn rewrite_stmt(
        s: &mut Stmt,
        variants: &std::collections::HashMap<(String, String), i128>,
        enums: &std::collections::HashSet<String>,
    ) -> Result<(), String> {
        match s {
            Stmt::Var { value, .. } => {
                if let Some(v) = value { rewrite_expr(v, variants, enums)?; }
            }
            Stmt::Expr { value, .. } => rewrite_expr(value, variants, enums)?,
            Stmt::If { cond, then_body, else_body } => {
                rewrite_expr(cond, variants, enums)?;
                for st in then_body { rewrite_stmt(st, variants, enums)?; }
                for st in else_body { rewrite_stmt(st, variants, enums)?; }
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond, variants, enums)?;
                for st in body { rewrite_stmt(st, variants, enums)?; }
            }
            Stmt::For { init, cond, step, body } => {
                if let Some(i) = init { rewrite_stmt(i, variants, enums)?; }
                if let Some(c) = cond { rewrite_expr(c, variants, enums)?; }
                if let Some(st) = step { rewrite_stmt(st, variants, enums)?; }
                for st in body { rewrite_stmt(st, variants, enums)?; }
            }
            Stmt::Ret { value: Some(v), .. } => rewrite_expr(v, variants, enums)?,
            Stmt::Raise { value, .. } => rewrite_expr(value, variants, enums)?,
            Stmt::Try { body, handler, .. } => {
                for st in body    { rewrite_stmt(st, variants, enums)?; }
                for st in handler { rewrite_stmt(st, variants, enums)?; }
            }
            Stmt::Asm(_)
                | Stmt::Ret { value: None, .. }
                | Stmt::Break
                | Stmt::Continue => {}
        }
        Ok(())
    }

    for f in &mut prog.functions {
        for st in &mut f.body {
            rewrite_stmt(st, &variants, &enum_names)?;
        }
    }
    for s in &mut prog.statics {
        if let Some(init) = &mut s.init {
            rewrite_expr(init, &variants, &enum_names)?;
        }
    }
    Ok(())
}

fn synthesize_bof_arg_parsers(prog: &mut ast::Program) {
    use ast::{Expr, Function, Param, Span, Stmt};

    let bof_arg_structs: Vec<(String, Vec<(String, String)>)> = prog.structs.iter()
        .filter(|s| s.attrs.iter().any(|a| a.kind == "BofArgs"))
        .map(|s| (s.name.clone(), s.fields.clone()))
        .collect();

    for (struct_name, fields) in bof_arg_structs {
        let fn_name = format!("bof_parse_{struct_name}");
        // Don't synthesise twice (e.g. if the user wrote their own).
        if prog.functions.iter().any(|f| f.name == fn_name) {
            continue;
        }

        let mut body: Vec<Stmt> = Vec::new();
        let zero_span = Span::default();
        let mk_call = |ns: &str, fname: &str, args: Vec<Expr>| -> Expr {
            Expr::Call {
                ns: ns.to_string(),
                fname: fname.to_string(),
                args,
                span: zero_span,
            }
        };
        let mk_addr_local = |name: &str| -> Expr {
            Expr::Unary { op: "&".to_string(), operand: Box::new(Expr::Var(name.to_string())) }
        };
        let mk_field_write = |base: &str, field: &str, value: Expr| -> Stmt {
            Stmt::Expr {
                value: Expr::FieldAssign {
                    base: Box::new(Expr::Var(base.to_string())),
                    field: field.to_string(),
                    value: Box::new(value),
                },
                span: zero_span,
            }
        };

        //   var parser: datap;
        // BeaconDataParse expects datap*; declaring as datap and
        // passing &parser matches the signature exactly.
        body.push(Stmt::Var {
            name: "parser".to_string(),
            ty:   "datap".to_string(),
            value: None,
            span: zero_span,
        });

        //   BeaconDataParse;
        body.push(Stmt::Expr {
            value: mk_call("", "BeaconDataParse", vec![
                mk_addr_local("parser"),
                Expr::Var("args".to_string()),
                Expr::Var("len".to_string()),
            ]),
            span: zero_span,
        });

        // Per-field assignment.
        for (fname, fty) in &fields {
            let extractor = match fty.as_str() {
                "int" | "i32" | "u32" => Some("BeaconDataInt"),
                "i16" | "u16"          => Some("BeaconDataShort"),
                "str" | "char*" | "u8*" => Some("BeaconDataExtract"),
                _ => None,
            };
            let call_args: Vec<Expr> = if let Some(ex) = extractor {
                if ex == "BeaconDataExtract" {
                    // BeaconDataExtract takes (parser, &size_out). We
                    // don't capture the size here; pass a null
                    // pointer (cast from 0) to ignore it.
                    vec![
                        mk_addr_local("parser"),
                        Expr::Cast {
                            ty: "int*".to_string(),
                            expr: Box::new(Expr::Int(0)),
                        },
                    ]
                } else {
                    vec![mk_addr_local("parser")]
                }
            } else {
                // Insert a clearly-failing call so typecheck flags
                // the user's struct rather than a synthesised name.
                eprintln!(
                    "warning: [BofArgs] struct `{struct_name}`: field \
                     `{fname}: {fty}` has an unsupported type. Supported: \
                     int/i32/u32 (BeaconDataInt), i16/u16 (BeaconDataShort), \
                     str/char*/u8* (BeaconDataExtract). Skipping this field.");
                continue;
            };
            let call = mk_call("", extractor.unwrap(), call_args);
            // Result types: extract returns char*. Int/Short return
            // int. Cast to the field's declared type so the
            // FieldAssign typecheck is happy.
            let casted = Expr::Cast {
                ty: fty.clone(),
                expr: Box::new(call),
            };
            // out.<field> = <casted>
            body.push(Stmt::Expr {
                value: Expr::FieldAssign {
                    base: Box::new(Expr::Var("out".to_string())),
                    field: fname.clone(),
                    value: Box::new(casted),
                },
                span: zero_span,
            });
        }
        // Suppress unused-helper warning for early-return path.
        let _ = mk_field_write;

        body.push(Stmt::Ret { value: None, span: zero_span });

        let f = Function {
            name: fn_name,
            // u8* is the canonical spelling for char* internally;
            // using it here makes the typecheck happy regardless of
            // whether the caller wrote char* or u8* for args.
            params: vec![
                Param { name: "args".to_string(), ty: "u8*".to_string() },
                Param { name: "len".to_string(),  ty: "int".to_string() },
                Param { name: "out".to_string(),  ty: format!("{struct_name}*") },
            ],
            ret_ty: "void".to_string(),
            body,
            attrs: Vec::new(),
            is_extern: false,
        };
        prog.functions.push(f);
    }
}

fn synthetic_use_tokens(path: &str) -> Vec<lexer::Token> {
    vec![
        lexer::Token { kind: lexer::Tok::Use, line: 1, col: 1 },
        lexer::Token { kind: lexer::Tok::Str(path.to_string()), line: 1, col: 1 },
        lexer::Token { kind: lexer::Tok::Semi, line: 1, col: 1 },
    ]
}

fn resolve_stdlib_subpath(source_path: &str, subpath: &str) -> Option<String> {
    let abs_source = std::fs::canonicalize(source_path).ok()?;
    let mut cursor = abs_source.parent()?.to_path_buf();
    loop {
        let candidate = cursor.join("stdlib").join(subpath);
        if candidate.exists() {
            let canon = std::fs::canonicalize(&candidate).ok()?;
            let s = canon.to_string_lossy();
            let cleaned = s.trim_start_matches(r"\\?\").to_string();
            return Some(cleaned);
        }
        match cursor.parent() {
            Some(p) if p != cursor => cursor = p.to_path_buf(),
            _ => return None,
        }
    }
}

fn auto_include_win32_constants(
    prog: &mut ast::Program,
    source_path: &str,
) -> Result<(), String> {
    // Locate the stdlib/win32 directory by walking up from the
    // source. Matches resolve_stdlib_subpath but returns a
    // directory rather than a single-file path.
    let abs_source = std::fs::canonicalize(source_path)
        .map_err(|e| format!("auto-include win32: {e}"))?;
    let mut cursor = match abs_source.parent() {
        Some(p) => p.to_path_buf(),
        // Source has no parent - nothing to walk up from. Bail
        // silently; the operator still gets the language without
        // the constants.
        None => return Ok(()),
    };
    let win32_dir = loop {
        let candidate = cursor.join("stdlib").join("win32");
        if candidate.is_dir() {
            break candidate;
        }
        match cursor.parent() {
            Some(p) if p != cursor => cursor = p.to_path_buf(),
            // Reached the root without finding stdlib/win32. Not
            // an error - operators outside the workspace just
            // don't get the auto-include.
            _ => return Ok(()),
        }
    };

    // Build a set of names that are already declared so the
    // auto-include skips anything the user owns.
    let mut existing_static_names: std::collections::HashSet<String> =
        prog.statics.iter().map(|s| s.name.clone()).collect();
    let mut existing_struct_names: std::collections::HashSet<String> =
        prog.structs.iter().map(|s| s.name.clone()).collect();

    // Walk every .h in stdlib/win32 in alphabetical order so
    // the merge order is deterministic.
    let mut headers: Vec<std::path::PathBuf> = std::fs::read_dir(&win32_dir)
        .map_err(|e| format!("auto-include win32: read_dir {}: {e}", win32_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "h").unwrap_or(false))
        .collect();
    headers.sort();

    for header in headers {
        let header_str = header.to_string_lossy().to_string();
        let imported = match cimport::parse_header(&header_str) {
            Ok(i)  => i,
            Err(e) => {
                eprintln!(
                    "warning: auto-include win32: failed to parse {header_str}: {e}"
                );
                continue;
            }
        };
        for s in imported.structs {
            if existing_struct_names.insert(s.name.clone()) {
                prog.structs.push(s);
            }
        }
        for mut s in imported.statics {
            if existing_static_names.insert(s.name.clone()) {
                s.attrs.push(crate::ast::Attr { kind: "AutoInclude".into(), arg: None });
                prog.statics.push(s);
            }
        }
    }
    Ok(())
}

/// Format the in-memory debug breadcrumbs as a human-readable sidecar.
/// Each line is <code_offset_hex>  <line>:<col>  <kind>  <src>. Sorted
/// by offset so a grep on a crash PC's hex finds the nearest entry.
fn format_dbg(
    src_path: &str,
    marks: &[encoder::DbgMark],
    vars:  &[encoder::DbgVar],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("# entropy debug map for {src_path}\n"));
    out.push_str("# offset    line:col  kind      source\n");
    for m in marks {
        out.push_str(&format!(
            "{:08x}  {:>5}:{:<3}  {:<8}  {}\n",
            m.code_off, m.line, m.col, m.kind, src_path
        ));
    }
    if !vars.is_empty() {
        out.push_str("\n# variables\n");
        out.push_str("# name : type : loc : line_start..line_end\n");
        for v in vars {
            let end = if v.line_end == u32::MAX { "max".to_string() }
                      else { v.line_end.to_string() };
            out.push_str(&format!(
                "{} : {} : {} : {}..{}\n",
                v.name, v.ty, v.loc, v.line_start, end
            ));
        }
    }
    out
}


fn parse_gc_mode(arg: &str) -> Result<codegen::GcMode, String> {
    match arg {
        "auto"             => Ok(codegen::GcMode::Auto),
        "on"               => Ok(codegen::GcMode::On),
        "off"              => Ok(codegen::GcMode::Off),
        "manual" | "unsafe" => Ok(codegen::GcMode::Manual),
        other => Err(format!(
            "--gc value must be auto|on|off|manual (got `{other}`)"
        )),
    }
}

fn parse_build_kind(arg: &str) -> Result<codegen::BuildKind, String> {
    match arg {
        "standard" | "bin" => Ok(codegen::BuildKind::Standard),
        "bof"              => Ok(codegen::BuildKind::Bof),
        "coff"             => Ok(codegen::BuildKind::Coff),
        other              => Err(format!("--type value must be standard|bof|coff (got `{other}`)")),
    }
}

fn dump_hex(bytes: &[u8]) {
    let mut stdout = std::io::stdout().lock();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(stdout, "{:08x}  ", i * 16);
        for b in chunk { let _ = write!(stdout, "{b:02x} "); }
        for _ in chunk.len()..16 { let _ = write!(stdout, "   "); }
        let _ = write!(stdout, " |");
        for &b in chunk {
            let c = if (0x20..0x7e).contains(&b) { b as char } else { '.' };
            let _ = write!(stdout, "{c}");
        }
        let _ = writeln!(stdout, "|");
    }
}

fn default_output(input: &str) -> String {
    let p = std::path::Path::new(input);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("a");
    let parent = p.parent();
    let bin_dir = match parent {
        Some(d) if !d.as_os_str().is_empty() => d.join("bin"),
        _ => std::path::PathBuf::from("bin"),
    };
    bin_dir.join(format!("{stem}.bin")).to_string_lossy().to_string()
}

fn ensure_parent_dir(out: &str) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(out).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create_dir_all {}: {e}", parent.display()))?;
        }
    }
    Ok(())
}

fn output_stem(out: &str) -> String {
    if let Some(s) = out.strip_suffix(".x64.o") { return s.to_string(); }
    if let Some(s) = out.strip_suffix(".x86.o") { return s.to_string(); }
    out.trim_end_matches(".bin")
        .trim_end_matches(".obj")
        .trim_end_matches(".coff")
        .to_string()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        // Strip argv[0] to its basename so the usage line reads
        // entc.exe compile ... instead of leaking the full path.
        let prog = std::path::Path::new(&args[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("entc");
        let ext = SRC_EXT;
        eprintln!("Entropia compiler - Windows x86-64 PIC / BOF code generator");
        eprintln!("Copyright (c) EntropyKit\n");
        eprintln!("USAGE");
        eprintln!("  {prog} compile <input{ext}> [options]");
        eprintln!("  {prog} dump    <input{ext}> [options]\n");
        eprintln!("OUTPUT");
        eprintln!("  -o <path>            output file. Defaults land in `<source-dir>/bin/`:");
        eprintln!("                         example/foo.etpy  to  example/bin/foo.bin");
        eprintln!("                       Extension follows the build kind: .bin for");
        eprintln!("                       shellcode, .x64.o for --type=bof, .obj for --type=coff.");
        eprintln!("                       Sidecar files (`.dbg`, `.cna`) live alongside the");
        eprintln!("                       artifact. `-o <path>` is honoured verbatim - pass an");
        eprintln!("                       explicit path to bypass the `bin/` subdirectory.");
        eprintln!("  --debug, -g          emit a `.dbg` sidecar with source-line + var");
        eprintln!("                       breadcrumbs for the VS Code adapter (F5/F9).\n");
        eprintln!("BUILD KIND");
        eprintln!("  --type=standard|bin  raw PIC shellcode `.bin` (default).");
        eprintln!("  --type=bof           Cobalt Strike BOF `.x64.o` (COFF). Entry is");
        eprintln!("                       `fn go(args, len)`; uses Beacon API.");
        eprintln!("  --type=coff          generic Windows COFF `.obj`, no Beacon-API assumptions.\n");
        eprintln!("RUNTIME");
        eprintln!("  --gc=auto            emit GC runtime iff `mem.alloc` is used (default).");
        eprintln!("  --gc=on              always emit (for dynamic / inline-asm callers).");
        eprintln!("  --gc=off             never emit; `mem.alloc` becomes a compile error.");
        eprintln!("  --gc=manual|unsafe   no GC runtime; `mem.alloc` and `mem.free` lower");
        eprintln!("                       to direct HeapAlloc/HeapFree through the process");
        eprintln!("                       heap. Operator is responsible for matching pairs.\n");
        eprintln!("OPSEC  (--opsec=<list>, comma-separated; flags accumulate)");
        eprintln!("  poly                 same-length instruction-substitution pass (xor/sub, mov");
        eprintln!("                       MR/RM/lea, test/or/and, NOP-run re-decompose). Reloc-aware.");
        eprintln!("  poly=deep            all of `poly` PLUS length-changing equivalent code");
        eprintln!("                       expansion (xor reg,reg rewrites as and reg,0, mov reg,0,");
        eprintln!("                       or nop; xor). Defeats semantic-normalising matchers.");
        eprintln!("  strings_xor          XOR-encrypt .rdata/.data with a per-build key.");
        eprintln!("                       Standard shellcode only; silently skipped for BOF");
        eprintln!("                       (loader maps .rdata read-only).");
        eprintln!("  nop_sled             0..=64 B multi-byte NOP at the entry function,");
        eprintln!("                       0..=16 B at every other function. Shifts offsets");
        eprintln!("                       so whole-binary fuzzy hashes drift per build.");
        eprintln!("  direct_syscalls      auto-include stdlib/opsec/direct_syscall.etpy so");
        eprintln!("                       every Ntdll.X(...) dispatches via `syscall` inside");
        eprintln!("                       our own code region.");
        eprintln!("  indirect_syscalls    auto-include stdlib/opsec/indirect_syscall.etpy so");
        eprintln!("                       Ntdll.X(...) jumps to a `syscall;ret` gadget INSIDE");
        eprintln!("                       ntdll. Mutually exclusive with direct_syscalls.");
        eprintln!("  hashed_imports       BOF only: drop `__imp_LIB$Func` external symbols");
        eprintln!("                       from the COFF. Win32 imports resolved at runtime");
        eprintln!("                       via PEB-walk + LoadLibraryA + GetProcAddress. Beacon");
        eprintln!("                       API (`Beacon*`) stays on the standard external path.");
        eprintln!("  stack_strings        rebuild short string literals on the stack at runtime");
        eprintln!("                       (`mov [rsp+N], imm64` runs) instead of pointing at");
        eprintln!("                       `.rdata`. Defeats `strings`-based triage. Composes");
        eprintln!("                       with `strings_xor` - stack-built strings are excluded");
        eprintln!("                       from the XOR pool.");
        eprintln!("  sleep_mask=<variant> auto-include a `[Hook(\"KERNEL32$Sleep\")]` template");
        eprintln!("                       that encrypts the implant region across the wait.");
        eprintln!("                       Variants:");
        eprintln!("                         simple   XOR + real Sleep (smallest, weakest).");
        eprintln!("                         ekko     XOR + VirtualProtect RX to RW + sleep via");
        eprintln!("                                  WaitForSingleObject. Call stack at scan");
        eprintln!("                                  time shows a wait frame, not a Sleep");
        eprintln!("                                  frame - the Ekko signature trick.");
        eprintln!("                         foliage  XOR + VirtualProtect flip + sleep via");
        eprintln!("                                  NtDelayExecution. Pairs with");
        eprintln!("                                  --opsec=direct_syscalls so the syscall");
        eprintln!("                                  comes out of our own code region.");
        eprintln!("                       Skipped if the source already has a");
        eprintln!("                       `[Hook(\"KERNEL32$Sleep\")]` - operator's mask wins.");
        eprintln!("  all                  every technique above. Does NOT pick a sleep_mask");
        eprintln!("                       variant - masks are implant-specific.");
        eprintln!("  none                 explicit no-op.\n");
        eprintln!("  --seed=<n>|0x<hex>|random");
        eprintln!("                       RNG seed driving every randomised pass. Same seed  to ");
        eprintln!("                       byte-identical output. Default: system-time nanos.\n");
        eprintln!("EXAMPLES");
        eprintln!("  {prog} compile example/asm_demo.etpy --opsec=all --seed=42");
        eprintln!("  {prog} compile example/bof_pslist.etpy --type=bof --opsec=all");
        eprintln!("  {prog} compile prog.etpy --type=bof --opsec=poly,nop_sled,direct_syscalls");
        return Err("missing args".into());
    }
    match args[1].as_str() {
        "compile" => {
            let inp = &args[2];
            let mut out = default_output(inp);
            let mut gc_mode = codegen::GcMode::Auto;
            let mut kind    = codegen::BuildKind::Standard;
            let mut emit_dbg = false;
            let mut opsec   = polymorphism::OpsecConfig::default();
            let mut i = 3;
            while i < args.len() {
                let a = &args[i];
                if a == "-o" && i + 1 < args.len() {
                    out = args[i+1].clone(); i += 2;
                } else if let Some(v) = a.strip_prefix("--gc=") {
                    gc_mode = parse_gc_mode(v)?; i += 1;
                } else if let Some(v) = a.strip_prefix("--type=") {
                    kind = parse_build_kind(v)?; i += 1;
                } else if a == "--type" && i + 1 < args.len() {
                    kind = parse_build_kind(&args[i+1])?; i += 2;
                } else if let Some(v) = a.strip_prefix("--opsec=") {
                    let new_cfg = polymorphism::OpsecConfig::parse(v)?;
                    opsec.poly              |= new_cfg.poly;
                    opsec.poly_deep         |= new_cfg.poly_deep;
                    opsec.reorder_functions |= new_cfg.reorder_functions;
                    if new_cfg.junk_level > opsec.junk_level {
                        opsec.junk_level = new_cfg.junk_level;
                    }
                    opsec.strings_xor       |= new_cfg.strings_xor;
                    opsec.stack_strings     |= new_cfg.stack_strings;
                    opsec.nop_sled          |= new_cfg.nop_sled;
                    opsec.direct_syscalls   |= new_cfg.direct_syscalls;
                    opsec.indirect_syscalls |= new_cfg.indirect_syscalls;
                    opsec.hashed_imports    |= new_cfg.hashed_imports;
                    if new_cfg.sleep_mask != polymorphism::SleepMaskVariant::None {
                        opsec.sleep_mask = new_cfg.sleep_mask;
                    }
                    // Same "indirect wins" disambiguation as
                    // OpsecConfig::parse: both occupy the NtCall
                    // override slot, so we keep at most one.
                    if opsec.indirect_syscalls {
                        opsec.direct_syscalls = false;
                    }
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--seed=") {
                    opsec.seed = Some(polymorphism::OpsecConfig::parse_seed(v)?);
                    i += 1;
                } else if a == "--debug" || a == "-g" {
                    emit_dbg = true; i += 1;
                } else {
                    return Err(format!("unknown arg: {a}"));
                }
            }
            if out.ends_with(".bin") {
                let stem = out.trim_end_matches(".bin");
                out = match kind {
                    codegen::BuildKind::Standard => out.clone(),
                    codegen::BuildKind::Bof      => format!("{stem}.x64.o"),
                    codegen::BuildKind::Coff     => format!("{stem}.obj"),
                };
            }
            let blob = compile(inp, gc_mode, kind, opsec.clone())?;
            ensure_parent_dir(&out)?;
            fs::write(&out, &blob.code).map_err(|e| e.to_string())?;
            let kind_str = match kind {
                codegen::BuildKind::Standard => "shellcode",
                codegen::BuildKind::Bof      => "BOF (COFF .x64.o)",
                codegen::BuildKind::Coff     => "COFF .obj",
            };
            let opsec_suffix = if opsec.any() {
                let mut techniques = Vec::<String>::new();
                if opsec.poly              { techniques.push("poly".into()); }
                if opsec.poly_deep         { techniques.push("poly=deep".into()); }
                if opsec.junk_level > 0    { techniques.push(format!("junk={}", opsec.junk_level)); }
                if opsec.reorder_functions { techniques.push("reorder".into()); }
                if opsec.strings_xor       { techniques.push("strings_xor".into()); }
                if opsec.stack_strings     { techniques.push("stack_strings".into()); }
                if opsec.nop_sled          { techniques.push("nop_sled".into()); }
                if opsec.direct_syscalls   { techniques.push("direct_syscalls".into()); }
                if opsec.indirect_syscalls { techniques.push("indirect_syscalls".into()); }
                if opsec.hashed_imports    { techniques.push("hashed_imports".into()); }
                if opsec.sleep_mask != polymorphism::SleepMaskVariant::None {
                    techniques.push(format!("sleep_mask={}", opsec.sleep_mask.name()));
                }
                format!(", opsec=[{}]", techniques.join(","))
            } else {
                String::new()
            };
            eprintln!("wrote {} ({} bytes, {}{})",
                      out, blob.code.len(), kind_str, opsec_suffix);
            if emit_dbg {
                let stem = output_stem(&out);
                let dbg_path = format!("{stem}.dbg");
                let dbg = format_dbg(inp, &blob.dbg_marks, &blob.dbg_vars);
                ensure_parent_dir(&dbg_path)?;
                fs::write(&dbg_path, dbg).map_err(|e| e.to_string())?;
                eprintln!("wrote {} ({} entries)", dbg_path, blob.dbg_marks.len());
            }
            if let Some(cna) = &blob.cna_script {
                let stem = output_stem(&out);
                let cna_path = format!("{stem}.cna");
                ensure_parent_dir(&cna_path)?;
                fs::write(&cna_path, cna).map_err(|e| e.to_string())?;
                eprintln!("wrote {} ({} bytes, Aggressor script)",
                          cna_path, cna.len());
            }
        }
        "dump" => {
            let mut gc_mode = codegen::GcMode::Auto;
            let mut i = 3;
            while i < args.len() {
                let a = &args[i];
                if let Some(v) = a.strip_prefix("--gc=") {
                    gc_mode = parse_gc_mode(v)?; i += 1;
                } else {
                    return Err(format!("unknown arg: {a}"));
                }
            }
            let blob = compile(&args[2], gc_mode, codegen::BuildKind::Standard,
                               polymorphism::OpsecConfig::default())?;
            dump_hex(&blob.code);
            eprintln!("total {} bytes", blob.code.len());
        }
        other => return Err(format!("unknown subcommand: {other}")),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => { eprintln!("error: {e}"); ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod compiler_gauntlet_tests {
    use super::*;
    use crate::ast::{Expr, Stmt};
    use std::path::PathBuf;

    fn parse_source(src: &str) -> ast::Program {
        let tokens = lexer::tokenize(src).expect("source should tokenize");
        parser::Parser::new(tokens, "gauntlet.etpy")
            .parse_program()
            .expect("source should parse")
    }

    fn typecheck_source(src: &str) -> Result<(), Vec<String>> {
        let prog = parse_source(src);
        typecheck::check(&prog)
    }

    fn test_source_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("target");
        path.push("entropia-rust-gauntlet");
        path.push(format!("{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&path).expect("test output directory should be created");
        path.push(format!("{name}.etpy"));
        path
    }

    fn compile_test_source(
        name: &str,
        src: &str,
        kind: codegen::BuildKind,
    ) -> codegen::CompiledBlob {
        let path = test_source_path(name);
        std::fs::write(&path, src).expect("test source should be written");
        compile(
            path.to_str().expect("test source path should be utf-8"),
            codegen::GcMode::Auto,
            kind,
            polymorphism::OpsecConfig::default(),
        )
        .expect("test source should compile")
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    unsafe fn run_shellcode_i64(code: &[u8]) -> i64 {
        use std::ffi::c_void;

        const PROT_READ: i32 = 1;
        const PROT_WRITE: i32 = 2;
        const PROT_EXEC: i32 = 4;
        const MAP_PRIVATE: i32 = 0x02;
        const MAP_ANON: i32 = 0x20;

        extern "C" {
            fn mmap(
                addr: *mut c_void,
                len: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                off: i64,
            ) -> *mut c_void;
            fn munmap(addr: *mut c_void, len: usize) -> i32;
        }

        assert!(!code.is_empty(), "shellcode should not be empty");
        let len = (code.len() + 4095) & !4095;
        let mem = mmap(
            std::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );
        assert_ne!(mem as isize, -1, "mmap should allocate executable memory");
        std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());

        let entry: extern "win64" fn() -> i64 = std::mem::transmute(mem);
        let result = entry();
        let rc = munmap(mem, len);
        assert_eq!(rc, 0, "munmap should release executable memory");
        result
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    fn compile_and_run_shellcode(name: &str, src: &str) -> i64 {
        let blob = compile_test_source(name, src, codegen::BuildKind::Standard);
        unsafe { run_shellcode_i64(&blob.code) }
    }

    #[test]
    fn crimson_cloak_parses_core_language_shapes() {
        let prog = parse_source(
            r#"
fn main() -> int {
    var a: int = 1;
    var b: int = a + 41;
    var p: char* = "ok";
    while b > 0 {
        if b == 42 {
            ret b;
        }
        b = b - 1;
    }
    ret 0;
}
"#,
        );

        assert_eq!(prog.functions.len(), 1);
        let main = &prog.functions[0];
        assert_eq!(main.name, "main");
        assert_eq!(main.ret_ty, "int");
        assert!(main.body.iter().any(|stmt| matches!(
            stmt,
            Stmt::Var { name, ty, value: Some(Expr::Int(1)), .. }
                if name == "a" && ty == "int"
        )));
        assert!(main.body.iter().any(|stmt| matches!(
            stmt,
            Stmt::Var { name, ty, value: Some(Expr::Binary { op, .. }), .. }
                if name == "b" && ty == "int" && op == "+"
        )));
        assert!(main.body.iter().any(|stmt| matches!(
            stmt,
            Stmt::Var { name, ty, value: Some(Expr::Str(_)), .. }
                if name == "p" && ty == "u8*"
        )));
        assert!(main.body.iter().any(|stmt| matches!(stmt, Stmt::While { .. })));
    }

    #[test]
    fn grey_hat_accepts_int_return_from_int_function() {
        typecheck_source(
            r#"
fn main() -> int {
    var a: int = 40;
    var b: int = 2;
    ret a + b;
}
"#,
        )
        .expect("int function returning int expression should typecheck");
    }

    #[test]
    fn grey_hat_rejects_incompatible_assignment() {
        let errs = typecheck_source(
            r#"
fn main() -> int {
    var a: int = "bad";
    ret 0;
}
"#,
        )
        .expect_err("string literal assigned to int should fail typecheck");

        assert!(
            errs.iter().any(|e| e.contains("error[T003]") && e.contains("var `a`")),
            "expected T003 var assignment diagnostic, got: {errs:#?}"
        );
    }

    #[test]
    fn grey_hat_reports_undeclared_variables_without_panicking() {
        let result = std::panic::catch_unwind(|| {
            typecheck_source(
                r#"
fn main() -> int {
    ret missing_name;
}
"#,
            )
        });

        let errs = result
            .expect("undeclared variable should be reported, not panic")
            .expect_err("undeclared variable should fail typecheck");
        assert!(
            errs.iter().any(|e| e.contains("error[T012]") && e.contains("missing_name")),
            "expected T012 undeclared variable diagnostic, got: {errs:#?}"
        );
    }

    #[test]
    fn iron_forge_codegen_emits_non_empty_raw_shellcode_blob() {
        let blob = compile_test_source(
            "shellcode_blob",
            r#"
fn main() -> int {
    var a: int = 40;
    var b: int = 2;
    ret a + b;
}
"#,
            codegen::BuildKind::Standard,
        );

        assert!(!blob.code.is_empty(), "shellcode blob should not be empty");
        assert_ne!(&blob.code[..blob.code.len().min(2)], b"MZ", "shellcode should be raw, not PE");
    }

    #[test]
    fn iron_forge_codegen_emits_x64_coff_for_bof() {
        let blob = compile_test_source(
            "bof_object",
            r#"
fn go(args: char*, len: int) -> void {
    ret;
}
"#,
            codegen::BuildKind::Bof,
        );

        assert!(blob.code.len() >= 20, "COFF object should include a file header");
        let machine = u16::from_le_bytes([blob.code[0], blob.code[1]]);
        let sections = u16::from_le_bytes([blob.code[2], blob.code[3]]);
        assert_eq!(machine, coff::IMAGE_FILE_MACHINE_AMD64);
        assert!(sections >= 1, "COFF object should include at least one section");
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn runtime_minimal_execution_returns_42() {
        let result = compile_and_run_shellcode(
            "runtime_ret_42",
            r#"
fn main() -> int {
    ret 42;
}
"#,
        );

        assert_eq!(result, 42);
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn runtime_loop_million_returns_count() {
        let result = compile_and_run_shellcode(
            "runtime_loop_million",
            r#"
fn main() -> int {
    var i: int = 0;
    while i < 1000000 {
        i = i + 1;
    }
    ret i;
}
"#,
        );

        assert_eq!(result, 1_000_000);
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn runtime_stack_depth_recursive_factorial() {
        let result = compile_and_run_shellcode(
            "runtime_factorial",
            r#"
fn fact(n: int) -> int {
    if n <= 1 {
        ret 1;
    }
    ret n * fact(n - 1);
}

fn main() -> int {
    ret fact(6);
}
"#,
        );

        assert_eq!(result, 720);
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn runtime_pointer_arithmetic_lands_on_expected_byte() {
        let result = compile_and_run_shellcode(
            "runtime_pointer_arithmetic",
            r#"
fn main() -> int {
    var buf: u8[8];
    buf[0] = (u8)10;
    buf[1] = (u8)20;
    buf[2] = (u8)30;
    buf[3] = (u8)40;
    buf[4] = (u8)50;
    buf[5] = (u8)60;
    var p: u8* = (u8*)buf;
    p = p + 5;
    p = p - 2;
    ret (int)*p;
}
"#,
        );

        assert_eq!(result, 40);
    }


    // ----------------------------------------------------------------
    // Overflow detection pass — unit tests against parse + overflow::check.
    // Each test either asserts that exactly the expected errors fire
    // (or none), so we can catch regressions in the type-range rules.
    // ----------------------------------------------------------------

    fn overflow_errors(src: &str) -> Vec<String> {
        let prog = parse_source(src);
        match overflow::check(&prog) {
            Ok(()) => Vec::new(),
            Err(errs) => errs,
        }
    }

    // ---- Literal overflows — values that don't fit the declared type ----

    #[test]
    fn literal_overflow_u8_256_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u8 = 256; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("u8")),
            "u8 = 256 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn literal_overflow_i8_positive_128_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i8 = 128; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("i8")),
            "i8 = 128 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn literal_overflow_u32_4294967296_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u32 = 4294967296; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("u32")),
            "u32 = 4294967296 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn literal_overflow_u16_65536_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u16 = 65536; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("u16")),
            "u16 = 65536 should fire T030, got: {errs:#?}");
    }

    // ---- Arithmetic overflows — result exceeds declared type ----

    #[test]
    fn arithmetic_overflow_i8_100_plus_50_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i8 = 100 + 50; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("i8")),
            "i8 = 100+50 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn arithmetic_overflow_u8_200_plus_100_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u8 = 200 + 100; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("u8")),
            "u8 = 200+100 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn arithmetic_overflow_i16_32000_plus_1000_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i16 = 32000 + 1000; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("i16")),
            "i16 = 32000+1000 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn arithmetic_overflow_u16_65535_plus_1_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u16 = 65535 + 1; ret a; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("u16")),
            "u16 = 65535+1 should fire T030, got: {errs:#?}");
    }

    // ---- Cast overflows — value doesn't fit the cast target type ----

    #[test]
    fn cast_overflow_u8_300_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { ret (u8)300; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("u8")),
            "(u8)300 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn cast_overflow_i8_200_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { ret (i8)200; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("i8")),
            "(i8)200 should fire T030, got: {errs:#?}");
    }

    #[test]
    fn cast_overflow_u16_70000_fires() {
        let errs = overflow_errors(
            r#"fn main() -> int { ret (u16)70000; }"#,
        );
        assert!(errs.iter().any(|e| e.contains("T030") && e.contains("u16")),
            "(u16)70000 should fire T030, got: {errs:#?}");
    }

    // ---- Negation overflow — unary result is *not* checked (known gap) ----

    #[test]
    fn negation_overflow_i8_min_fires() {
        // -(i8::MIN) = -(-128) = 128, which exceeds i8::MAX (127). The
        // overflow pass now checks the result of unary negation against
        // both the operand's declared type and the expression's expected
        // type — so 128 overflow i8 fires T030.
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i8 = -128; ret -a; }"#,
        );
        assert!(
            errs.iter().any(|e| e.contains("error[T030]")),
            "negating i8::MIN should fire T030, got: {errs:#?}"
        );
    }

    #[test]
    fn negation_literal_129_fires_overflow() {
        // -129 parsed as Unary("-", Int(129)); unary negation yields -129
        // which does not fit i8::MIN..i8::MAX [-128..127]. The overflow
        // pass now validates the result of unary negation.
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i8 = -129; ret a; }"#,
        );
        assert!(
            errs.iter().any(|e| e.contains("error[T030]")),
            "unary negation of 129 should fire T030, got: {errs:#?}"
        );
    }

    // ---- Valid values — nothing should error ----

    #[test]
    fn valid_u8_255_no_error() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u8 = 255; ret a; }"#,
        );
        assert!(errs.is_empty(), "u8 = 255 is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_i8_127_no_error() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i8 = 127; ret a; }"#,
        );
        assert!(errs.is_empty(), "i8 = 127 is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_i8_min_128_no_error() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i8 = -128; ret a; }"#,
        );
        assert!(errs.is_empty(), "i8 = -128 is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_u32_4294967295_no_error() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u32 = 4294967295; ret a; }"#,
        );
        assert!(errs.is_empty(), "u32 = 4294967295 is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_u64_hex_max_no_error() {
        // Hex path parses as full u64 then casts to i64; the value
        // 0x7FFFFFFFFFFFFFFF = i64::MAX = 9223372036854775807 fits u64.
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u64 = 0x7FFFFFFFFFFFFFFF; ret a; }"#,
        );
        assert!(errs.is_empty(), "u64 hex MAX is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_u64_decimal_max_no_error() {
        // Decimal integer parsing now uses u128 internally, so u64::MAX
        // (18446744073709551615) can be written in decimal without
        // overflowing the lexer. The overflow pass sees the literal
        // value and confirms it fits u64's range.
        let errs = overflow_errors(
            r#"fn main() -> int { var a: u64 = 18446744073709551615; ret a; }"#,
        );
        assert!(errs.is_empty(),
            "u64::MAX written in decimal is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_cast_u8_0_no_error() {
        let errs = overflow_errors(
            r#"fn main() -> int { ret (u8)0; }"#,
        );
        assert!(errs.is_empty(), "(u8)0 is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_cast_i32_42_no_error() {
        let errs = overflow_errors(
            r#"fn main() -> int { ret (i32)42; }"#,
        );
        assert!(errs.is_empty(), "(i32)42 is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_arithmetic_i8_1_plus_1_no_error() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: i8 = 1 + 1; ret a; }"#,
        );
        assert!(errs.is_empty(), "i8 = 1+1 is valid, got: {errs:#?}");
    }

    #[test]
    fn valid_arithmetic_int_no_overflow() {
        let errs = overflow_errors(
            r#"fn main() -> int { var a: int = 100 + 50; ret a; }"#,
        );
        assert!(errs.is_empty(), "int = 100+50 is valid, got: {errs:#?}");
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn runtime_asm_read_local_via_register() {
        let result = compile_and_run_shellcode(
            "runtime_asm_read",
            r#"
fn main() -> int {
    var a: int = 73;
    asm {
        mov rax, a
    }
    ret a;
}
"#,
        );
        assert_eq!(result, 73);
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn runtime_asm_write_local_via_register() {
        let result = compile_and_run_shellcode(
            "runtime_asm_write",
            r#"
fn main() -> int {
    var a: int = 100;
    asm {
        mov rax, 200
        mov a, rax
    }
    ret a;
}
"#,
        );
        assert_eq!(result, 200);
    }


    #[cfg(all(unix, target_arch = "x86_64"))]
    #[test]
    fn runtime_asm_compound_bytes_inline() {
        // Verify db directives emit the correct bytes into the text section.
        // We don't execute this shellcode: the inline `ret` fires before the
        // compiler's epilogue restores rsp, which segfaults on Linux.
        // Byte-level assertion is sufficient to prove the asm block works.
        let blob = compile_test_source("runtime_asm_db", r#"
fn main() -> int {
    asm {
        db 0x48, 0xB8, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        db 0xC3
    }
    ret 0;
}
"#, codegen::BuildKind::Standard);
        // mov rax, 90 = 48 B8 5A 00 00 00 00 00 00 00
        let expected = [0x48u8, 0xB8, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let found = blob.code.windows(expected.len()).any(|w| w == expected);
        assert!(found, "inline asm db bytes not found in output: {:02x?}", &blob.code);
    }

}
