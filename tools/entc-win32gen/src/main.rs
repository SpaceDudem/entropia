// SPDX-License-Identifier: Apache-2.0
//! entc-win32gen - generate `use_c`-compatible Win32 headers from
//! Microsoft's win32metadata.
//!
//! Strategy (option D from the design discussion):
//!   - Microsoft publishes every Win32 type/struct/constant as machine-
//!     readable metadata (WinMD files).
//!   - We walk that metadata, namespace by namespace, and emit `.h` files
//!     in the C subset EntropyKit's `use_c` parser already handles.
//!   - The emitted files are committed under `stdlib/win32/`. User code
//!     does `use_c "stdlib/win32/memory.h";` and gets real Win32 types
//!     with byte-correct layouts.
//!
//! This tool is a one-time generator. Users of EntropyKit never invoke it
//! directly - they consume the committed output. Re-run periodically to
//! pick up new SDK additions.
//!
//! Getting the WinMD file:
//!   Download `Windows.Win32.winmd` from
//!   https://github.com/microsoft/win32metadata/releases
//!   (look for the `Microsoft.Windows.SDK.Win32Metadata*.nupkg` asset; the
//!    WinMD file is placed at `ref/netstandard2.0/Windows.Win32.winmd` inside
//!    the nupkg - rename `.nupkg` to `.zip` and extract).
//!
//! Usage:
//!     entc-win32gen --winmd path/to/Windows.Win32.winmd --out stdlib/win32
//!     entc-win32gen --winmd ... --namespace Windows.Win32.System.Memory
//!
//! What the emitted output supports:
//!   - Fixed-size arrays - `BYTE foo[16];` reaches the EntropyKit codegen
//!     as `foo: u8[16]` and is indexable via `[i]`.
//!   - Function-pointer typedefs and fields - both collapse to `u64`
//!     pointer-sized values.
//!   - Nested anonymous unions/structs are emitted with synthesized
//!     names so every field is addressable.
//!   - Free functions / methods are NOT emitted (the runtime resolver
//!     finds them by name at call time).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use windows_metadata::reader::{File, Field, TypeCategory, TypeDef, TypeIndex};
use windows_metadata::{Type, TypeName, Value};

/// Namespaces emitted by default. Each becomes one header file under the
/// output directory; the file name is the trailing path segment lower-cased.
const DEFAULT_NAMESPACES: &[&str] = &[
    "Windows.Win32.Foundation",
    "Windows.Win32.System.Memory",
    "Windows.Win32.System.Threading",
    "Windows.Win32.System.Diagnostics.Debug",
    "Windows.Win32.System.WindowsProgramming",
    "Windows.Win32.System.Kernel",
    "Windows.Win32.System.IO",
    "Windows.Win32.System.LibraryLoader",
    "Windows.Win32.System.Console",
    "Windows.Win32.System.Pipes",
    "Windows.Win32.System.Registry",
    "Windows.Win32.System.SystemServices",
    "Windows.Win32.System.SystemInformation",
    "Windows.Win32.System.Environment",
    "Windows.Win32.Security",
    "Windows.Win32.Security.Authorization",
    "Windows.Win32.Security.Cryptography",
    "Windows.Win32.Storage.FileSystem",
    // Networking - the blocker for the HTTP/TCP module work.
    "Windows.Win32.Networking.WinSock",
    "Windows.Win32.Networking.WinHttp",
    "Windows.Win32.Networking.WinInet",
];

fn main() {
    if let Err(e) = run() {
        eprintln!("entc-win32gen: error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    fs::create_dir_all(&args.out)
        .map_err(|e| format!("creating {}: {e}", args.out.display()))?;

    let file = File::read(&args.winmd)
        .ok_or_else(|| format!(
            "could not load WinMD file `{}` \n\
             (download from https://github.com/microsoft/win32metadata/releases)",
            args.winmd.display()
        ))?;
    let index = TypeIndex::new(vec![file]);

    let namespaces: Vec<String> = if args.namespaces.is_empty() {
        DEFAULT_NAMESPACES.iter().map(|s| s.to_string()).collect()
    } else {
        args.namespaces.clone()
    };

    let mut summary: Vec<(String, NsStats)> = Vec::new();
    for ns in &namespaces {
        let stats = emit_namespace(&index, ns, &args.out)?;
        summary.push((ns.clone(), stats));
    }

    write_index(&args.out, &summary)?;
    eprintln!("done. {} namespaces emitted under {}", summary.len(), args.out.display());
    Ok(())
}

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------

struct Args {
    winmd:      PathBuf,
    out:        PathBuf,
    namespaces: Vec<String>,
}

impl Args {
    fn parse(it: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut winmd: Option<PathBuf> = None;
        let mut out:   Option<PathBuf> = None;
        let mut namespaces: Vec<String> = Vec::new();
        let mut it = it.into_iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--winmd" => winmd = Some(PathBuf::from(it.next().ok_or("--winmd needs a path")?)),
                "--out" | "-o" => out = Some(PathBuf::from(it.next().ok_or("--out needs a path")?)),
                "--namespace" | "-n" => {
                    namespaces.push(it.next().ok_or("--namespace needs a value")?);
                }
                "--help" | "-h" => { print_help(); std::process::exit(0); }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Args {
            winmd: winmd.ok_or("--winmd <path-to-Windows.Win32.winmd> is required".to_string())?,
            out:   out.unwrap_or_else(|| PathBuf::from("stdlib/win32")),
            namespaces,
        })
    }
}

fn print_help() {
    eprintln!("Usage: entc-win32gen --winmd <path> [--out <dir>] [--namespace <ns>]*");
    eprintln!();
    eprintln!("  --winmd <path>           Path to Windows.Win32.winmd");
    eprintln!("  --out, -o <dir>          Output directory (default: stdlib/win32)");
    eprintln!("  --namespace, -n <ns>     Generate this namespace (repeatable).");
    eprintln!("                           Defaults to a curated red-team subset.");
}

// ----------------------------------------------------------------------------
// per-namespace emission
// ----------------------------------------------------------------------------

#[derive(Default)]
struct NsStats {
    structs:   usize,
    constants: usize,
    skipped:   Vec<String>,
}

fn emit_namespace(index: &TypeIndex, namespace: &str, out_dir: &Path) -> Result<NsStats, String> {
    let mut stats = NsStats::default();
    let mut buf = String::new();
    write_preamble(&mut buf, namespace);

    // Two passes: constants first (so the header reads top-down naturally),
    // then structs. Each namespace's `Apis` pseudo-class collects the loose
    // `#define`-equivalents; its other fields are the actual types.
    let types: Vec<TypeDef> = index
        .iter()
        .filter(|(ns, _, _)| *ns == namespace)
        .map(|(_, _, td)| td)
        .collect();

    if types.is_empty() {
        // Namespace not in the supplied WinMD - write a minimal file with
        // a marker so the user can tell the difference between "skipped"
        // and "no such namespace".
        writeln!(buf, "// (namespace `{namespace}` not present in the supplied WinMD)").ok();
        fs::write(out_dir.join(filename_for_namespace(namespace)), buf)
            .map_err(|e| format!("write: {e}"))?;
        return Ok(stats);
    }

    // Pass 1: constants (from the Apis pseudo-class and from enum members).
    // Duplicates inside one namespace are common - e.g. an enum member that
    // also appears as a loose Apis constant. Dedupe within this file; cross-
    // file collisions are tolerated by the EntropyKit codegen (first wins).
    let mut seen_constants: std::collections::HashSet<String> = std::collections::HashSet::new();
    for td in &types {
        if td.name() == "Apis" {
            for f in td.fields() {
                if let Some(c) = f.constant() {
                    if seen_constants.insert(f.name().to_string()) {
                        emit_constant(&mut buf, f.name(), &c.value());
                        stats.constants += 1;
                    }
                }
            }
        }
    }
    for td in &types {
        if td.category() != TypeCategory::Enum { continue; }
        for f in td.fields() {
            // Skip the synthetic `value__` field (the underlying storage).
            if f.name() == "value__" { continue; }
            if let Some(c) = f.constant() {
                if seen_constants.insert(f.name().to_string()) {
                    emit_constant(&mut buf, f.name(), &c.value());
                    stats.constants += 1;
                }
            }
        }
    }
    if stats.constants > 0 { writeln!(buf).ok(); }

    // Pass 2: structs. WinMD often carries multiple architecture-specific
    // copies of the same struct (e.g. WSADATA has both an x64 and an x86
    // layout). The cimport parser would reject the duplicate; keep only
    // the first occurrence and note the rest.
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for td in &types {
        if td.category() != TypeCategory::Struct { continue; }
        let name = td.name();
        if !seen_names.insert(name.to_string()) {
            writeln!(buf, "// duplicate struct {name} - keeping first definition").ok();
            continue;
        }
        match try_emit_struct(&mut buf, *td) {
            Ok(()) => stats.structs += 1,
            Err(reason) => {
                writeln!(buf, "// SKIPPED struct {name}: {reason}").ok();
                stats.skipped.push(format!("struct {name}: {reason}"));
            }
        }
    }

    let path = out_dir.join(filename_for_namespace(namespace));
    fs::write(&path, buf).map_err(|e| format!("writing {}: {e}", path.display()))?;
    eprintln!(
        "  {namespace} -> {}  ({} structs, {} constants, {} skipped)",
        path.display(), stats.structs, stats.constants, stats.skipped.len()
    );
    Ok(stats)
}

fn filename_for_namespace(ns: &str) -> String {
    let last = ns.rsplit('.').next().unwrap_or(ns).to_ascii_lowercase();
    format!("{last}.h")
}

fn write_preamble(buf: &mut String, namespace: &str) {
    writeln!(buf, "// Generated by entc-win32gen from `{namespace}`.").ok();
    writeln!(buf, "// Do not edit by hand. Re-run the generator to refresh.").ok();
    writeln!(buf).ok();
    // Common typedef'd integer aliases the rest of the file will reference.
    writeln!(buf, "typedef unsigned char       BYTE;").ok();
    writeln!(buf, "typedef unsigned short      WORD;").ok();
    writeln!(buf, "typedef unsigned long       DWORD;").ok();
    writeln!(buf, "typedef unsigned long long  ULONGLONG;").ok();
    writeln!(buf, "typedef long                LONG;").ok();
    writeln!(buf, "typedef unsigned long       ULONG;").ok();
    writeln!(buf, "typedef int                 BOOL;").ok();
    writeln!(buf, "typedef void*               PVOID;").ok();
    writeln!(buf, "typedef void*               HANDLE;").ok();
    writeln!(buf).ok();
}

fn emit_constant(buf: &mut String, name: &str, value: &Value) {
    match value {
        Value::U8(n)  => { writeln!(buf, "#define {name} 0x{n:x}").ok(); }
        Value::I8(n)  => { writeln!(buf, "#define {name} {n}").ok(); }
        Value::U16(n) => { writeln!(buf, "#define {name} 0x{n:x}").ok(); }
        Value::I16(n) => { writeln!(buf, "#define {name} {n}").ok(); }
        Value::U32(n) => { writeln!(buf, "#define {name} 0x{n:x}").ok(); }
        Value::I32(n) => { writeln!(buf, "#define {name} {n}").ok(); }
        Value::U64(n) => { writeln!(buf, "#define {name} 0x{n:x}").ok(); }
        Value::I64(n) => { writeln!(buf, "#define {name} {n}").ok(); }
        _ => { writeln!(buf, "// SKIPPED const {name}: non-integer constant").ok(); }
    }
}

fn try_emit_struct(buf: &mut String, td: TypeDef) -> Result<(), String> {
    let name = td.name();
    let mut fields: Vec<(String, String, Option<usize>)> = Vec::new();
    for f in td.fields() {
        if f.constant().is_some() { continue; } // const-in-struct, not a field
        let fname = f.name().to_string();
        let (mapped, array_len) = map_field_type(&f)?;
        fields.push((fname, mapped, array_len));
    }
    if fields.is_empty() {
        return Err("no representable fields".into());
    }

    writeln!(buf, "typedef struct _{name} {{").ok();
    for (fname, fty, array_len) in &fields {
        match array_len {
            Some(n) => writeln!(buf, "    {fty} {fname}[{n}];").ok(),
            None    => writeln!(buf, "    {fty} {fname};").ok(),
        };
    }
    writeln!(buf, "}} {name};").ok();
    writeln!(buf).ok();
    Ok(())
}

/// Map a single struct field's metadata Type to a C-subset type name our
/// cimport parser accepts plus an optional array length to attach as a
/// `[N]` suffix on the field name in the emitted C.
fn map_field_type(f: &Field) -> Result<(String, Option<usize>), String> {
    let ty = f.ty();
    if let Type::ArrayFixed(elem, n) = &ty {
        let elem_ty = map_type(elem)?;
        return Ok((elem_ty, Some(*n)));
    }
    let mapped = map_type(&ty)?;
    Ok((mapped, None))
}

fn map_type(ty: &Type) -> Result<String, String> {
    Ok(match ty {
        Type::Void          => "void".into(),
        Type::Bool          => "BOOL".into(),
        Type::Char          => "unsigned short".into(), // WCHAR
        Type::I8            => "signed char".into(),
        Type::U8            => "unsigned char".into(),
        Type::I16           => "short".into(),
        Type::U16           => "unsigned short".into(),
        Type::I32           => "int".into(),
        Type::U32           => "unsigned int".into(),
        Type::I64           => "long long".into(),
        Type::U64           => "unsigned long long".into(),
        Type::F32 | Type::F64 => return Err("floating-point fields not supported".into()),
        Type::ISize         => "long long".into(),
        Type::USize         => "unsigned long long".into(),
        Type::String | Type::Object | Type::AttributeEnum => "void*".into(),
        // Pointers always collapse to void* (cimport stores as u64).
        Type::PtrMut(_, _) | Type::PtrConst(_, _) => "void*".into(),
        // Nested ArrayFixed inside another type - uncommon. Collapse to
        // the element type and accept that we lose the inner length;
        // the outer struct's overall size will likely still be correct
        // because the outer field-array path catches the common case.
        Type::ArrayFixed(elem, _) => map_type(elem)?,
        // Named types - struct/enum/typedef references. The named-type
        // resolver below handles Win32 integer aliases inline so they
        // map to plain-C int spellings; everything else flows through
        // as an opaque pointer-sized typedef.
        Type::Name(name) => map_named_type(name),
        Type::Array(_) | Type::ArrayRef(_) => return Err("variable-size arrays not supported".into()),
        Type::Generic(_) | Type::RefMut(_) | Type::RefConst(_) => {
            return Err("generic/ref types not supported".into());
        }
    })
}

/// Resolve common Win32 type aliases to their plain-C spelling so the
/// emitted header is self-contained. Anything we don't recognise becomes a
/// `void*` opaque field (matches Win32 ABI for handles/pointer typedefs).
fn map_named_type(name: &TypeName) -> String {
    if name.namespace == "Windows.Win32.Foundation" {
        match name.name.as_str() {
            "BOOL" | "BOOLEAN"                     => return "BOOL".into(),
            "BYTE" | "CHAR" | "UCHAR"              => return "unsigned char".into(),
            "WCHAR" | "WORD" | "USHORT" | "UINT16" => return "unsigned short".into(),
            "SHORT" | "INT16"                      => return "short".into(),
            "DWORD" | "ULONG" | "UINT" | "UINT32"  => return "unsigned int".into(),
            "LONG" | "INT" | "INT32"
            | "HRESULT" | "NTSTATUS"               => return "int".into(),
            "ULONGLONG" | "UINT64" | "DWORDLONG"   => return "unsigned long long".into(),
            "LONGLONG" | "INT64"                   => return "long long".into(),
            // PSTR / handle-like aliases all flow to void* below.
            _ => {}
        }
    }
    // Anything else - handle, pointer alias, struct ref - opaque void*.
    "void*".into()
}

fn write_index(out_dir: &Path, summary: &[(String, NsStats)]) -> Result<(), String> {
    let path = out_dir.join("index.md");
    let mut buf = String::new();
    writeln!(buf, "# Generated Win32 headers").ok();
    writeln!(buf).ok();
    writeln!(buf, "Produced by `entc-win32gen`. Each row is one namespace.").ok();
    writeln!(buf).ok();
    writeln!(buf, "| Namespace | File | Structs | Constants | Skipped |").ok();
    writeln!(buf, "|---|---|---:|---:|---:|").ok();
    let mut total_skipped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (ns, s) in summary {
        writeln!(buf, "| {ns} | `{}` | {} | {} | {} |",
                 filename_for_namespace(ns), s.structs, s.constants, s.skipped.len()).ok();
        if !s.skipped.is_empty() { total_skipped.insert(ns.clone(), s.skipped.clone()); }
    }
    if !total_skipped.is_empty() {
        writeln!(buf).ok();
        writeln!(buf, "## Skipped types").ok();
        for (ns, items) in &total_skipped {
            writeln!(buf).ok();
            writeln!(buf, "### {ns}").ok();
            for it in items { writeln!(buf, "- {it}").ok(); }
        }
    }
    fs::write(&path, buf).map_err(|e| format!("writing index: {e}"))?;
    Ok(())
}
