// SPDX-License-Identifier: Apache-2.0
//! Loader for the `<stem>.dbg` text map the compiler emits with
//! `--debug`. Format (one entry per line):
//!
//!     # entropy debug map for example/foo.etpy
//!     # offset    line:col  kind      source
//!     0000000d     30:5    call      example/foo.etpy
//!     ...
//!
//! Lines starting with `#` are comments. The leading hex offset is the
//! shellcode byte offset; the rest of the fields are derived from the
//! source.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Entry {
    pub offset: usize,
    pub line:   u32,
    pub col:    u32,
    pub kind:   String,
}

/// A named local emitted by the compiler. `loc` is a tiny textual
/// expression the adapter parses to figure out where the value lives:
///
///   - `rbp-0x8` / `rbp+0x10`   - frame-relative (currently the only form)
///   - `rax`, `rcx`, ...        - direct register (future)
///   - `rip+0x40`               - rip-relative (future; for globals)
///
/// `line_start` / `line_end` bracket the source lines where the
/// variable is live. `line_end == u32::MAX` means "until end of
/// function".
#[derive(Debug, Clone)]
pub struct VarInfo {
    pub name:       String,
    pub ty:         String,
    pub loc:        String,
    pub line_start: u32,
    pub line_end:   u32,
}

/// Parsed source map ready for byte-offset  to  source lookups. Cloneable
/// because the DAP server and tracer thread each want their own view.
#[derive(Debug, Clone)]
pub struct SourceMap {
    /// Absolute path to the .etpy. Stored absolute so the DAP server can
    /// hand it back to VS Code in stackTrace responses without relying
    /// on the debugger's cwd matching the workspace root (which it
    /// often doesn't - VS Code passes its workspace as cwd, but
    /// extensions can override it).
    pub source_path: PathBuf,
    pub entries:     Vec<Entry>,   // sorted by offset ascending
    pub vars:        Vec<VarInfo>, // declaration order
}

impl SourceMap {
    /// Read and parse a `.dbg` file. Errors propagate as plain strings
    /// so the DAP server can include them in an Output event.
    pub fn load(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("read {path}: {e}"))?;
        let dbg_dir: PathBuf = Path::new(path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let mut raw_source: Option<PathBuf> = None;
        let mut entries: Vec<Entry> = Vec::new();
        let mut vars: Vec<VarInfo> = Vec::new();
        // The .dbg has two sections - entries (offset  to  line:col) and
        // an optional variables block introduced by `# variables`. We
        // track which section we're in by header comment, since the
        // grammars are different (positional vs `name : type : loc`).
        let mut in_vars = false;

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() { continue; }
            if let Some(rest) = line.strip_prefix("# entropy debug map for ") {
                raw_source = Some(PathBuf::from(rest.trim()));
                in_vars = false;
                continue;
            }
            if line.starts_with("# variables") {
                in_vars = true;
                continue;
            }
            if line.starts_with('#') { continue; }

            if in_vars {
                // Format: `name : type : loc : line_start..line_end`
                let parts: Vec<&str> = line.splitn(4, " : ").collect();
                if parts.len() != 4 { continue; }
                let (name, ty, loc) = (parts[0].trim(), parts[1].trim(), parts[2].trim());
                let range = parts[3].trim();
                let (s, e) = match range.split_once("..") {
                    Some(p) => p, None => continue,
                };
                let line_start: u32 = match s.trim().parse() { Ok(n) => n, Err(_) => continue };
                let line_end: u32 = if e.trim() == "max" {
                    u32::MAX
                } else {
                    match e.trim().parse() { Ok(n) => n, Err(_) => continue }
                };
                vars.push(VarInfo {
                    name:       name.to_string(),
                    ty:         ty.to_string(),
                    loc:        loc.to_string(),
                    line_start, line_end,
                });
                continue;
            }

            // Entry row: `<hex_off>  <line>:<col>  <kind>  <src>`
            let mut it = line.split_whitespace();
            let off_hex  = match it.next() { Some(s) => s, None => continue };
            let line_col = match it.next() { Some(s) => s, None => continue };
            let kind     = match it.next() { Some(s) => s, None => continue };
            let src      = it.next().unwrap_or("");
            let Ok(offset) = usize::from_str_radix(off_hex, 16) else { continue };
            let (lstr, cstr) = match line_col.split_once(':') {
                Some(p) => p, None => continue,
            };
            let Ok(line_n) = lstr.parse::<u32>() else { continue };
            let Ok(col_n)  = cstr.parse::<u32>() else { continue };
            entries.push(Entry {
                offset, line: line_n, col: col_n,
                kind: kind.to_string(),
            });
            if raw_source.is_none() && !src.is_empty() {
                raw_source = Some(PathBuf::from(src));
            }
        }
        entries.sort_by_key(|e| e.offset);

        let source_path = resolve_source_path(raw_source.as_deref(), &dbg_dir);
        Ok(SourceMap { source_path, entries, vars })
    }

    /// Return all variables in scope at `line`. Used by the DAP
    /// server's `variables(LOCALS)` handler.
    pub fn vars_in_scope(&self, line: u32) -> Vec<&VarInfo> {
        self.vars.iter()
            .filter(|v| line >= v.line_start && line <= v.line_end)
            .collect()
    }

    /// Find the source entry whose offset matches `offset` exactly -
    /// software breakpoints land at the exact planted byte.
    pub fn at(&self, offset: usize) -> Option<&Entry> {
        match self.entries.binary_search_by_key(&offset, |e| e.offset) {
            Ok(i) => Some(&self.entries[i]),
            Err(_) => None,
        }
    }

    /// Find the nearest preceding entry - used when the breakpoint
    /// isn't an exact match (e.g. a runaway PC between lowered
    /// statements).
    pub fn nearest(&self, offset: usize) -> Option<&Entry> {
        if self.entries.is_empty() { return None; }
        match self.entries.binary_search_by_key(&offset, |e| e.offset) {
            Ok(i) => Some(&self.entries[i]),
            Err(0) => None,
            Err(i) => Some(&self.entries[i - 1]),
        }
    }
}

/// Turn whatever the .dbg's header reported into an absolute path.
/// Strategy, in order:
///
///   1. Absolute already + exists: trust it.
///   2. `dbg_dir / <filename>`: most common case, the .etpy lives
///      next to its .dbg.
///   3. `dbg_dir / <raw>` joined as written.
///   4. `dbg_dir.parent() / <raw>`: covers `example/foo.etpy` written
///      in a .dbg that is placed inside `example/` - the path was
///      workspace-relative even though we have a per-folder dbg.
///   5. Last resort: return `dbg_dir / <filename>` even if not present,
///      so VS Code at least sees a sensible-looking path it can offer
///      to create.
fn resolve_source_path(raw: Option<&Path>, dbg_dir: &Path) -> PathBuf {
    let raw = match raw {
        Some(p) => p,
        None    => return dbg_dir.join("<unknown>"),
    };
    if raw.is_absolute() && raw.exists() {
        return canonicalize_pretty(raw);
    }
    if let Some(name) = raw.file_name() {
        let same_dir = dbg_dir.join(name);
        if same_dir.exists() {
            return canonicalize_pretty(&same_dir);
        }
    }
    let as_written = dbg_dir.join(raw);
    if as_written.exists() {
        return canonicalize_pretty(&as_written);
    }
    if let Some(parent) = dbg_dir.parent() {
        let workspace_relative = parent.join(raw);
        if workspace_relative.exists() {
            return canonicalize_pretty(&workspace_relative);
        }
    }
    // Couldn't actually find it on disk. Hand back the most plausible
    // guess so VS Code shows SOMETHING in the stackTrace.
    raw.file_name()
        .map(|n| dbg_dir.join(n))
        .unwrap_or_else(|| dbg_dir.join(raw))
}

/// `std::fs::canonicalize` on Windows returns a `\\?\` prefixed path
/// that VS Code doesn't love. Strip it.
fn canonicalize_pretty(p: &Path) -> PathBuf {
    match std::fs::canonicalize(p) {
        Ok(c) => {
            let s = c.to_string_lossy();
            let trimmed = s.trim_start_matches(r"\\?\");
            PathBuf::from(trimmed)
        }
        Err(_) => p.to_path_buf(),
    }
}
