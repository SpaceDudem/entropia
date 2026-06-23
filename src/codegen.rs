
use std::collections::{HashMap, HashSet};

use crate::asm::{AsmBody, AsmLine, AsmMem, AsmMemBase, AsmOperand};
use crate::ast::*;
use crate::encoder::{Cond, DbgMark, Encoder, Reg64};
use crate::gc;
use crate::macros;
use crate::polymorphism;
use crate::resolver::{self, Import};
use crate::veh;
use crate::shared;

/// Namespaces the compiler interprets directly instead of treating them as
/// Win32 DLL prefixes. Add to this list when introducing new intrinsic
/// groups (mem.*, shared.*, str.*, future syscall.*).
const INTRINSIC_NAMESPACES: &[&str] = &["mem", "shared", "str"];

pub struct CompiledBlob {
    pub code:      Vec<u8>,
    pub dbg_marks: Vec<DbgMark>,
    pub dbg_vars:  Vec<crate::encoder::DbgVar>,
    pub cna_script: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcMode {
    /// Default. Emit the GC runtime iff the program calls mem.alloc.
    Auto,
    /// Always emit the GC runtime.
    On,
    /// Never emit the runtime. mem.alloc becomes a compile error.
    Off,
    Manual,
}

impl Default for GcMode {
    fn default() -> Self { GcMode::Auto }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildKind { Standard, Bof, Coff }

impl Default for BuildKind {
    fn default() -> Self { BuildKind::Standard }
}

impl BuildKind {
    pub fn is_object(self) -> bool {
        matches!(self, BuildKind::Bof | BuildKind::Coff)
    }
    pub fn entry_name(self) -> &'static str {
        match self {
            BuildKind::Standard => "main",
            BuildKind::Bof | BuildKind::Coff => "go",
        }
    }
}

const FMT_BUF_SIZE: usize = 256;

const STACK_STR_MAX_BYTES: usize = 64;

/// T* is the canonical type spelling for "pointer to T". Any number of
/// trailing *s is allowed (the parser keeps them) - only the rightmost
/// * is consumed by a single deref / pointee lookup.
fn is_pointer_type(ty: &str) -> bool {
    ty.ends_with('*')
}

fn parse_array_type(ty: &str) -> Option<(&str, usize)> {
    let close = ty.strip_suffix(']')?;
    let open  = close.rfind('[')?;
    let elem  = &close[..open];
    let n_str = &close[open + 1..];
    let n: usize = n_str.parse().ok()?;
    Some((elem, n))
}

#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub bootstrap: Option<String>,
    pub resolver:  Option<String>,
    pub ntcall:    Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct HookTable {
    /// Target symbol (e.g. USER32$MessageBoxA or BeaconPrintf)  to
    /// hook function name. Lookup is by the SAME key the call site
    /// would otherwise emit as __imp_<key>.
    pub map: HashMap<String, String>,
}

#[derive(Debug, Default, Clone)]
pub struct StageTable {
    /// Functions called after init, before user code. Source order.
    pub init: Vec<String>,
    /// Functions called at the ret_label, before frame tear-down.
    /// Source order. Each call is wrapped in a save/restore of rax
    /// so the user's return value survives.
    pub exit: Vec<String>,
}

/// Parsed view of one function's hook-related attributes. Lifetime
/// of these objects is the codegen pass; they sit alongside the
/// frame metadata while a function is being lowered.
#[derive(Debug, Default, Clone)]
struct FnHookCtx {
    /// Some when this function is a [Hook]
    /// implementation. Codegen uses it to suppress recursion: a hook
    /// for X calling X internally redirects to the real X.
    is_hook_for: Option<String>,
    /// True when [NoHook] (no arg) appears on this function - all
    /// hooked targets bypass the hook table inside this body.
    no_hook_all: bool,
    /// [NoHook] entries - targets to skip individually.
    no_hook:     HashSet<String>,
}

/// Walk every function's attribute list and resolve OPSEC overrides
/// + the aspect-oriented hook table. Returns both, paired so codegen
/// only walks attribute lists once.
fn build_attributes(prog: &Program) -> Result<(Overrides, HookTable, StageTable), String> {
    let mut overrides = Overrides::default();
    let mut hooks = HookTable::default();
    let mut stages = StageTable::default();
    for f in &prog.functions {
        for a in &f.attrs {
            match a.kind.as_str() {
                "Override" => {
                    let slot = a.arg.as_deref().ok_or_else(|| format!(
                        "function `{}`: `[Override]` needs a slot name - try `[Override(Bootstrap)]`, \
                         `[Override(Resolver)]`, or `[Override(NtCall)]`",
                        f.name
                    ))?;
                    let target: &mut Option<String> = match slot {
                        "Bootstrap" => &mut overrides.bootstrap,
                        "Resolver"  => &mut overrides.resolver,
                        "NtCall"    => &mut overrides.ntcall,
                        other => return Err(format!(
                            "function `{}`: unknown override slot `{other}` \
                             (valid: Bootstrap, Resolver, NtCall)",
                            f.name
                        )),
                    };
                    if let Some(existing) = target {
                        return Err(format!(
                            "two functions claim `[Override({slot})]`: `{existing}` and `{}`. \
                             Only one override per slot is allowed.",
                            f.name
                        ));
                    }
                    *target = Some(f.name.clone());
                }
                "Hook" => {
                    let target = a.arg.as_deref().ok_or_else(|| format!(
                        "function `{}`: `[Hook]` needs a target symbol - \
                         try `[Hook(\"USER32$MessageBoxA\")]` or `[Hook(\"BeaconPrintf\")]`",
                        f.name
                    ))?;
                    if let Some(existing) = hooks.map.get(target) {
                        return Err(format!(
                            "two functions claim `[Hook(\"{target}\")]`: \
                             `{existing}` and `{}`. A hook target may have \
                             only one implementation.",
                            f.name
                        ));
                    }
                    if f.is_extern {
                        return Err(format!(
                            "function `{}`: `[Hook]` cannot apply to an `extern fn` - \
                             a hook needs a body to redirect into.",
                            f.name
                        ));
                    }
                    hooks.map.insert(target.to_string(), f.name.clone());
                }
                "NoHook" => {
                }
                "BofCommand" => {
                }
                "Stage" => {
                    let slot = a.arg.as_deref().ok_or_else(|| format!(
                        "function `{}`: `[Stage]` needs a phase name - \
                         try `[Stage(Init)]` (runs after init, before user code) or \
                         `[Stage(Exit)]` (runs before the entry function returns)",
                        f.name
                    ))?;
                    if !f.params.is_empty() || f.ret_ty != "void" {
                        return Err(format!(
                            "function `{}`: `[Stage({slot})]` requires the signature \
                             `fn {}() -> void` - stage hooks take no arguments and \
                             return nothing.",
                            f.name, f.name
                        ));
                    }
                    if f.is_extern {
                        return Err(format!(
                            "function `{}`: `[Stage({slot})]` cannot apply to an \
                             `extern fn` - a stage handler needs a body to emit.",
                            f.name
                        ));
                    }
                    match slot {
                        "Init" => stages.init.push(f.name.clone()),
                        "Exit" => stages.exit.push(f.name.clone()),
                        other => return Err(format!(
                            "function `{}`: unknown stage `{other}` \
                             (valid: Init, Exit)",
                            f.name
                        )),
                    }
                }
                other => return Err(format!(
                    "function `{}`: unknown attribute `{}` (valid: `Override(...)`, \
                     `Hook(\"...\")`, `NoHook[(\"...\")]`, `BofCommand(\"...\")`, \
                     `Stage(Init|Exit)`)",
                    f.name, other
                )),
            }
        }
    }
    Ok((overrides, hooks, stages))
}

/// Distil the per-function hook context. Cheap to call repeatedly -
/// runs once at the top of gen_function.
fn collect_fn_hook_ctx(f: &Function) -> FnHookCtx {
    let mut ctx = FnHookCtx::default();
    for a in &f.attrs {
        match a.kind.as_str() {
            "Hook" => {
                if let Some(t) = &a.arg {
                    ctx.is_hook_for = Some(t.clone());
                }
            }
            "NoHook" => match &a.arg {
                None    => ctx.no_hook_all = true,
                Some(t) => { ctx.no_hook.insert(t.clone()); }
            },
            _ => {}
        }
    }
    ctx
}

fn printf_spec_for(spec: &str, arg_ty: &str) -> Result<String, String> {
    Ok(match spec {
        "" => {
            if arg_ty == "str"             { "%s".into() }
            else if arg_ty == "wstr"       { "%S".into() }  // wide-string
            else if arg_ty.ends_with('*')  { "%p".into() }
            else                           { "%I64d".into() }
        }
        "d" => "%I64d".into(),
        "u" => "%I64u".into(),
        "x" => "%I64x".into(),
        "X" => "%I64X".into(),
        "s" => "%s".into(),
        "p" => "%p".into(),
        other => return Err(format!(
            "str.format: unknown specifier `{{{other}}}` \
             (try `{{}}`, `{{d}}`, `{{u}}`, `{{x}}`, `{{X}}`, `{{s}}`, `{{p}}`)"
        )),
    })
}

/// Strip exactly one trailing * to get the pointee type. u32*  to  u32, Beacon**  to  Beacon*. Returns None if ty doesn't end in *.
fn pointee(ty: &str) -> Option<&str> {
    ty.strip_suffix('*')
}

/// Per-field metadata after layout. offset is the field's byte offset
/// from the start of its enclosing struct; size is the field's storage
/// width in bytes. Computed by [CodeGen::layout_struct].
#[derive(Debug, Clone)]
pub struct StructField {
    pub ty:     String,
    pub offset: i32,
    pub size:   usize,
}

#[derive(Debug, Clone)]
pub struct StructLayout {
    pub size:   usize,
    pub align:  usize,
    pub fields: HashMap<String, StructField>,
}

/// A global declared at module scope. The label is the data-section anchor
/// the codegen uses for every read/write of this global.
#[derive(Debug, Clone)]
struct GlobalSlot {
    label: String,
    ty:    String,
    /// Saved at codegen time so main's prologue can replay the initialiser
    /// after the runtime bootstraps but before user code.
    init:  Option<Expr>,
}

#[derive(Debug, Clone)]
enum ResolvedMem {
    /// [rbp + disp] - frame-relative slot. Distinguished from
    /// the generic BaseDisp so the encoder's specialised
    /// mov_r64_rbp_disp / lea_r64_r64disp paths get picked.
    RbpDisp(i32),
    /// [base + disp] - base-register relative.
    BaseDisp { base: Reg64, disp: i32 },
    /// [base + idx*scale + disp] - SIB-indexed.
    BaseIdx  { base: Reg64, idx: Reg64, scale: u32, disp: i32 },
    /// [rip + label] - global / static data, resolved by name.
    RipData  (String),
    /// [disp] (no base/index). Only valid with a segment override.
    SegAbs   { disp: i32 },
}

pub struct CodeGen {
    enc: Encoder,
    /// fname -> stack-offset map for the current function
    locals: HashMap<String, i32>,
    local_types: HashMap<String, String>,
    loop_stack: Vec<(String, String)>,
    next_off: i32,
    label_counter: u32,
    current_ret_label: String,
    imports: Vec<Import>,
    /// Set by the pre-scan in generate so main's prologue knows whether to
    /// emit call __resolve_imports. Without this, the prologue check would
    /// race with gen_call populating self.imports later in the same pass.
    needs_resolver: bool,
    needs_veh: bool,
    needs_gc: bool,
    /// Build-level GC selection (CLI: --gc=auto|on|off). Auto is the
    /// historical behaviour - runtime is emitted iff mem.alloc is used.
    gc_mode: GcMode,
    kind: BuildKind,
    /// Set when the program calls shared.get/shared.put. Controls both
    /// the __host_services slot + the get/put trampolines and the rcx save
    /// in main's prologue.
    needs_shared: bool,
    overrides: Overrides,
    stages: StageTable,
    hooks:     HookTable,
    /// Per-function hook context for the function currently being
    /// lowered. [Hook] self-recursion bypass and [NoHook] /
    /// [NoHook] per-call-site exclusion both read from this.
    current_fn_hook: FnHookCtx,
    /// Layout of every struct declared in the program. Populated once at
    /// the top of generate so field offsets are available throughout.
    struct_layouts: HashMap<String, StructLayout>,
    /// Every static declared in the program. Insertion-ordered to keep
    /// initialiser emission deterministic.
    globals: Vec<GlobalSlot>,
    /// Reverse index from variable name to its position in globals so
    /// lookups in gen_expr are O.
    globals_idx: HashMap<String, usize>,
    /// Cached fn_name -> ret_ty for every locally-declared function.
    /// Built once at the top of generate so callsite lowering can ask
    /// "does this fn return a struct?" without re-walking the AST.
    fn_ret_types: HashMap<String, String>,
    extern_fns: HashSet<String>,
    current_ret_dst_off: Option<i32>,
    /// Declared return type of the function currently being lowered.
    /// Stmt::Ret reads it when the type is a struct so it knows the
    /// size of the memcpy into the hidden destination.
    current_ret_ty: String,
    opsec: polymorphism::OpsecConfig,
    rng: polymorphism::Rng,
}

impl CodeGen {
    /// Convenience constructor with default GcMode::Auto. Kept for
    /// external Rust callers / future test harnesses; the CLI driver goes
    /// through with_gc_mode so the flag actually reaches the codegen.
    #[allow(dead_code)]
    pub fn new() -> Self { Self::with_options(GcMode::Auto, BuildKind::Standard) }

    pub fn with_gc_mode(gc_mode: GcMode) -> Self {
        Self::with_options(gc_mode, BuildKind::Standard)
    }

    pub fn with_options(gc_mode: GcMode, kind: BuildKind) -> Self {
        Self::with_opsec(gc_mode, kind, polymorphism::OpsecConfig::default())
    }

    pub fn with_opsec(
        gc_mode: GcMode,
        kind: BuildKind,
        opsec: polymorphism::OpsecConfig,
    ) -> Self {
        // Resolve the seed once so every randomised pass in this
        // build shares the same RNG state. opsec.seed == None
        // means "draw from system-time nanos".
        let resolved_seed = opsec.seed.unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xDEAD_BEEF_DEAD_BEEF)
        });
        Self {
            enc: Encoder::new(),
            locals: HashMap::new(),
            local_types: HashMap::new(),
            loop_stack: Vec::new(),
            overrides: Overrides::default(),
            stages: StageTable::default(),
            hooks: HookTable::default(),
            current_fn_hook: FnHookCtx::default(),
            next_off: 0,
            label_counter: 0,
            current_ret_label: String::new(),
            imports: Vec::new(),
            needs_resolver: false,
            needs_veh: false,
            needs_gc: false,
            needs_shared: false,
            gc_mode,
            kind,
            struct_layouts: HashMap::new(),
            globals: Vec::new(),
            globals_idx: HashMap::new(),
            fn_ret_types: HashMap::new(),
            extern_fns:   HashSet::new(),
            current_ret_dst_off: None,
            current_ret_ty: String::new(),
            opsec,
            rng: polymorphism::Rng::new(resolved_seed),
        }
    }

    fn new_label(&mut self, prefix: &str) -> String {
        self.label_counter += 1;
        format!(".L{prefix}_{}", self.label_counter)
    }

    fn ensure_win32_import(&mut self, dll: &str, func: &str) -> Win32CallSite {
        let bof_external = self.kind.is_object() && !self.opsec.hashed_imports;
        if bof_external {
            let lib_upper = dll.trim_end_matches(".dll").to_ascii_uppercase();
            let ext = format!("__imp_{lib_upper}${func}");
            Win32CallSite::Extern(ext)
        } else {
            let slot = resolver::slot_label(dll, func);
            if !self.imports.iter().any(|i| i.slot == slot) {
                self.imports.push(Import {
                    dll: dll.to_string(),
                    func: func.to_string(),
                    slot: slot.clone(),
                });
                self.enc.add_bss(&slot, 8);
            }
            Win32CallSite::Slot(slot)
        }
    }

    /// Emit a call through the call-site descriptor returned by
    /// ensure_win32_import. Caller is responsible for argument
    /// setup + shadow space + alignment.
    fn emit_win32_call(&mut self, site: &Win32CallSite) {
        match site {
            Win32CallSite::Extern(sym) => self.enc.call_extern(sym),
            Win32CallSite::Slot(slot)  => self.enc.call_indirect_data(slot),
        }
    }

    /// VEH: emit the AddVectoredExceptionHandler
    /// call at the start of the entry function. Stores the returned
    /// HANDLE into __opsec_veh_handle so the epilogue can remove it.
    fn emit_veh_register(&mut self) {
        veh::ensure_veh_slot(&mut self.enc);
        let site = self.ensure_win32_import("kernel32.dll", "AddVectoredExceptionHandler");
        self.enc.sub_r64_imm32(Reg64::Rsp, 0x20);
        self.enc.mov_r64_imm64(Reg64::Rcx, 1);                 // First = TRUE
        self.enc.lea_r64_code(Reg64::Rdx, veh::VEH_FN);        // handler
        self.emit_win32_call(&site);
        self.enc.add_r64_imm32(Reg64::Rsp, 0x20);
        self.enc.mov_data_r64(veh::VEH_HANDLE_SLOT, Reg64::Rax);
    }

    /// VEH: emit the RemoveVectoredExceptionHandler call at
    /// the entry function's epilogue. Preserves rax (the function's
    /// return value) across the call via a .bss scratch slot.
    fn emit_veh_unregister(&mut self) {
        veh::ensure_veh_slot(&mut self.enc);
        const SAVED_RAX_SLOT: &str = "__opsec_veh_saved_rax";
        if !self.enc.data_has(SAVED_RAX_SLOT) {
            self.enc.add_bss(SAVED_RAX_SLOT, 8);
        }
        let site = self.ensure_win32_import("kernel32.dll", "RemoveVectoredExceptionHandler");
        let skip_label = self.new_label("veh_no_unreg");

        // Save the function's return value before clobbering rax.
        self.enc.mov_data_r64(SAVED_RAX_SLOT, Reg64::Rax);

        // Load handle. Skip the call if it's zero (registration
        // probably failed at startup; nothing to remove).
        self.enc.mov_r64_data(Reg64::Rcx, veh::VEH_HANDLE_SLOT);
        self.enc.test_r64_r64(Reg64::Rcx, Reg64::Rcx);
        self.enc.jcc_label(crate::encoder::Cond::Z, &skip_label);

        self.enc.sub_r64_imm32(Reg64::Rsp, 0x20);
        self.emit_win32_call(&site);
        self.enc.add_r64_imm32(Reg64::Rsp, 0x20);

        self.enc.place_code_label(&skip_label);
        // Restore the return value.
        self.enc.mov_r64_data(Reg64::Rax, SAVED_RAX_SLOT);
    }

    fn alloc_local(&mut self, name: &str) -> i32 {
        self.alloc_local_sized(name, 8)
    }

    /// Allocate size bytes (rounded up to 8) in the current frame for
    /// name. Returns the offset from rbp (negative). Used by Stmt::Let
    /// to lay down in-frame value-typed struct locals.
    fn alloc_local_sized(&mut self, name: &str, size: usize) -> i32 {
        let rounded = ((size + 7) / 8) * 8;
        self.next_off -= rounded as i32;
        let off = self.next_off;
        self.locals.insert(name.to_string(), off);
        off
    }

    fn count_local_bytes(&self, stmts: &[Stmt]) -> usize {
        let mut n = 0;
        for s in stmts {
            match s {
                Stmt::Var { ty, value, .. } => {
                    // Struct- and array-typed locals carve a sized slot
                    // out of the frame. Scalar locals always cost 8 (one
                    // qword slot regardless of declared sized-int width).
                    let raw_size = if self.struct_layouts.contains_key(ty) {
                        self.struct_layouts[ty].size
                    } else if Self::is_array_type(ty) {
                        self.type_size(ty)
                    } else {
                        8
                    };
                    n += ((raw_size + 7) / 8) * 8;
                    if let Some(v) = value {
                        if let Expr::StructLit { fields, .. } = v {
                            for (_, fv) in fields {
                                n += self.count_hidden_lit_bytes(fv);
                            }
                        } else {
                            n += self.count_hidden_lit_bytes(v);
                        }
                    }
                }
                Stmt::Expr { value: e, .. }  => n += self.count_hidden_lit_bytes(e),
                Stmt::Ret { value: Some(e), .. } => n += self.count_hidden_lit_bytes(e),
                Stmt::Raise { value, .. }    => n += self.count_hidden_lit_bytes(value),
                Stmt::If { cond, then_body, else_body } => {
                    n += self.count_hidden_lit_bytes(cond)
                       + self.count_local_bytes(then_body)
                       + self.count_local_bytes(else_body);
                }
                Stmt::While { cond, body } => {
                    n += self.count_hidden_lit_bytes(cond)
                       + self.count_local_bytes(body);
                }
                Stmt::For { init, cond, step, body } => {
                    if let Some(i) = init { n += self.count_local_bytes(std::slice::from_ref(i)); }
                    if let Some(c) = cond { n += self.count_hidden_lit_bytes(c); }
                    if let Some(s) = step { n += self.count_local_bytes(std::slice::from_ref(s)); }
                    n += self.count_local_bytes(body);
                }
                Stmt::Try { body, handler, .. } => {
                    // The catch-binding gets its own 8-byte slot. Add it
                    // here so the prologue's frame is sized correctly even
                    // if the try is the only "local" in the function.
                    n += 8;
                    n += self.count_local_bytes(body)
                       + self.count_local_bytes(handler);
                }
                _ => {}
            }
        }
        n
    }

    fn should_stack_build_str(&self, s: &str) -> bool {
        self.opsec.stack_strings && s.len() + 1 <= STACK_STR_MAX_BYTES
    }

    fn emit_stack_string(&mut self, s: &str) -> Result<(), String> {
        let slot_bytes = Self::stack_str_slot_bytes(s);
        let n = self.label_counter;
        self.label_counter += 1;
        let off = self.alloc_local_sized(&format!("__stack_str_{n}"), slot_bytes);

        // Pack the literal (plus its terminating NUL, plus any
        // pad bytes up to the slot boundary) into 8-byte chunks.
        let mut bytes: Vec<u8> = Vec::with_capacity(slot_bytes);
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
        while bytes.len() < slot_bytes { bytes.push(0); }

        let mut key = self.rng.next_u64();
        if key == 0 { key = 0xA5A5_A5A5_DEAD_BEEF; }

        self.enc.mov_r64_imm64(Reg64::R11, key);

        for (chunk_idx, chunk) in bytes.chunks(8).enumerate() {
            let mut q: u64 = 0;
            for (i, b) in chunk.iter().enumerate() {
                q |= (*b as u64) << (8 * i);
            }
            let encrypted = q ^ key;
            // mov rax, <encrypted>
            self.enc.mov_r64_imm64(Reg64::Rax, encrypted);
            // xor rax, r11   to  rax now holds the plaintext qword
            self.enc.xor_r64_r64(Reg64::Rax, Reg64::R11);
            let disp = off + (chunk_idx * 8) as i32;
            self.enc.mov_rbp_disp_r64(disp, Reg64::Rax);
        }

        // Leave the slot's address in rax. Callers consume this as
        // the str value exactly like a lea r64, [rdata_label].
        self.enc.lea_r64_r64disp(Reg64::Rax, Reg64::Rbp, off);
        Ok(())
    }

    /// Frame-byte cost of rebuilding s on the stack: round
    /// len + 1 (NUL) up to the next 8-byte boundary.
    fn stack_str_slot_bytes(s: &str) -> usize {
        let raw = s.len() + 1;
        ((raw + 7) / 8) * 8
    }

    fn count_hidden_lit_bytes(&self, e: &Expr) -> usize {
        let mut n = 0;
        match e {
            Expr::StructLit { ty, fields, .. } => {
                let raw = self.struct_layouts.get(ty).map(|l| l.size).unwrap_or(0);
                n += ((raw + 7) / 8) * 8;
                for (_, fv) in fields { n += self.count_hidden_lit_bytes(fv); }
            }
            Expr::Call { ns, fname, args, .. } => {
                if ns.is_empty() {
                    if let Some(rt) = self.fn_ret_types.get(fname) {
                        if let Some(l) = self.struct_layouts.get(rt) {
                            n += ((l.size + 7) / 8) * 8;
                        }
                    }
                }
                let first_skip = ns == "str" && fname == "format";
                for (i, a) in args.iter().enumerate() {
                    if first_skip && i == 0 { continue; }
                    n += self.count_hidden_lit_bytes(a);
                }
            }
            Expr::Binary { lhs, rhs, .. } => {
                n += self.count_hidden_lit_bytes(lhs)
                   + self.count_hidden_lit_bytes(rhs);
            }
            Expr::Unary  { operand, .. } => n += self.count_hidden_lit_bytes(operand),
            Expr::Assign { value, .. }   => n += self.count_hidden_lit_bytes(value),
            Expr::Field  { base, .. }    => n += self.count_hidden_lit_bytes(base),
            Expr::FieldAssign { base, value, .. } => {
                n += self.count_hidden_lit_bytes(base)
                   + self.count_hidden_lit_bytes(value);
            }
            Expr::DerefAssign { ptr, value } => {
                n += self.count_hidden_lit_bytes(ptr)
                   + self.count_hidden_lit_bytes(value);
            }
            Expr::Index { base, index } => {
                n += self.count_hidden_lit_bytes(base)
                   + self.count_hidden_lit_bytes(index);
            }
            Expr::IndexAssign { base, index, value } => {
                n += self.count_hidden_lit_bytes(base)
                   + self.count_hidden_lit_bytes(index)
                   + self.count_hidden_lit_bytes(value);
            }
            Expr::Cast { expr, .. } => n += self.count_hidden_lit_bytes(expr),
            Expr::Str(s) => {
                if self.should_stack_build_str(s) {
                    n += Self::stack_str_slot_bytes(s);
                }
            }
            Expr::Int(_) | Expr::Bool(_) | Expr::Var(_) | Expr::SizeOf { .. } => {}
        }
        n
    }

    /// Like [generate] but discards the debug-info sidecar. Kept for
    /// any future test harness that only cares about the byte blob.
    #[allow(dead_code)]
    pub fn generate(self, prog: &Program) -> Result<Vec<u8>, String> {
        Ok(self.generate_with_debug(prog)?.code)
    }

    pub fn generate_with_debug(mut self, prog: &Program) -> Result<CompiledBlob, String> {
        // Resolve [Override] + [Hook] attributes once up
        // front. Errors here (duplicate slots, unknown slot names,
        // conflicting hooks) surface before any bytes are emitted.
        let (overrides, hooks, stages) = build_attributes(prog)?;
        self.overrides = overrides;
        self.hooks     = hooks;
        self.stages    = stages;

        let want_string_xor = self.opsec.strings_xor && !self.kind.is_object();
        if want_string_xor {
            self.enc.mark_rdata_position("__rdata_start");
        }

        // Cache fn return types so callsite lowering can detect struct
        // returns without rewalking. This is built before struct
        // layouts so layout-lookup correctness is independent of order.
        for f in &prog.functions {
            self.fn_ret_types.insert(f.name.clone(), f.ret_ty.clone());
            if f.is_extern {
                self.extern_fns.insert(f.name.clone());
            }
        }

        self.needs_resolver = program_uses(prog, |e| is_win32_call(e));
        // VEH integration: enabled when the program has any try block.
        // Forces the import resolver too, because we need
        // Kernel32.AddVectoredExceptionHandler at startup.
        self.needs_veh = program_uses_try(prog);
        if self.needs_veh {
            self.needs_resolver = true;
        }
        let uses_alloc = program_uses(prog, |e|
            is_intrinsic(e, "mem", "alloc") || is_intrinsic(e, "mem", "collect"));
        self.needs_gc = if self.kind.is_object() {
            false
        } else {
            match self.gc_mode {
                GcMode::Auto => uses_alloc,
                GcMode::On   => true,
                GcMode::Manual => {
                    if uses_alloc { self.needs_resolver = true; }
                    false
                }
                GcMode::Off  => {
                    if uses_alloc {
                        return Err(
                            "build was configured with `--gc=off` but this program \
                             calls `mem.alloc(...)`. Switch to `--gc=manual` to use \
                             HeapAlloc + explicit mem.free, or `--gc=auto` (default) / \
                             `--gc=on` for managed allocation.".into()
                        );
                    }
                    false
                }
            }
        };
        self.needs_shared   = program_uses(prog, |e| is_shared_call(e));

        for s in &prog.structs {
            // First-wins semantics for duplicate struct names - mirrors
            // statics. Lets users import overlapping use_c headers
            // without bookkeeping.
            if self.struct_layouts.contains_key(&s.name) {
                continue;
            }
            let mut off = 0usize;
            let mut max_size = 0usize;
            let mut max_align = 1usize;
            let mut fields = HashMap::new();
            for (fname, fty) in &s.fields {
                if fields.contains_key(fname) {
                    let kind = if s.is_union { "union" } else { "struct" };
                    return Err(format!("{kind} {}: duplicate field {fname}", s.name));
                }
                let size  = self.type_size(fty);
                let align = self.type_align(fty);
                let field_off = if s.is_union {
                    0
                } else {
                    off = (off + align - 1) & !(align - 1);
                    off
                };
                fields.insert(fname.clone(), StructField {
                    ty: fty.clone(),
                    offset: field_off as i32,
                    size,
                });
                if s.is_union {
                    if size > max_size { max_size = size; }
                } else {
                    off += size;
                }
                if align > max_align { max_align = align; }
            }
            let base = if s.is_union { max_size } else { off };
            let total = if max_align == 0 { base } else { (base + max_align - 1) & !(max_align - 1) };
            self.struct_layouts.insert(
                s.name.clone(),
                StructLayout { size: total, align: max_align, fields },
            );
        }

        for st in &prog.statics {
            if self.globals_idx.contains_key(&st.name) {
                continue;
            }
            let size = self.size_of_type(&st.ty);
            let label = format!("__static_{}", st.name);
            self.enc.add_bss(&label, size);
            self.globals_idx.insert(st.name.clone(), self.globals.len());
            self.globals.push(GlobalSlot {
                label,
                ty: st.ty.clone(),
                init: st.init.clone(),
            });
        }

        let entry = self.kind.entry_name();
        if let Some(entry_fn) = prog.functions.iter().find(|f| f.name == entry && !f.is_extern) {
            self.gen_function(entry_fn)?;
        }
        let mut order: Vec<usize> = (0..prog.functions.len())
            .filter(|&i| !prog.functions[i].is_extern
                && prog.functions[i].name != entry)
            .collect();
        if self.opsec.reorder_functions {
            // Fisher-Yates shuffle using our seeded RNG so the
            // resulting layout is reproducible from --seed=N.
            for i in (1..order.len()).rev() {
                let j = (self.rng.range((i + 1) as u64)) as usize;
                order.swap(i, j);
            }
        }
        for idx in order {
            self.gen_function(&prog.functions[idx])?;
        }

        if !self.kind.is_object() {
            if self.needs_gc      { gc::emit_runtime(&mut self.enc); }
            if self.needs_shared  { shared::emit_runtime(&mut self.enc); }
            if self.needs_resolver {
                if let Some(name) = self.overrides.resolver.clone() {
                    resolver::emit_with_user_resolver(&mut self.enc, &self.imports, &name);
                } else {
                    // Default path: PEB walk via gs:[0x60]; on non-Windows
                    // OSes that AVs, so the Linux test harness only stays
                    // runnable for programs that don't touch Win32.
                    resolver::emit(&mut self.enc, &self.imports);
                }
            }
        }

        if self.kind.is_object() && self.opsec.hashed_imports {
            resolver::emit(&mut self.enc, &self.imports);
        }

        if self.needs_veh {
            veh::emit_veh_handler(&mut self.enc);
        }

        if want_string_xor {
            polymorphism::emit_decryptor(&mut self.enc);
        }

        let mut opsec_for_pass = self.opsec.clone();
        if self.kind.is_object() {
            opsec_for_pass.strings_xor = false;
        }
        polymorphism::transform(&mut self.enc, &opsec_for_pass, &mut self.rng);

        // Snapshot the dbg marks + vars before finalize consumes the encoder.
        let dbg_marks = std::mem::take(&mut self.enc.dbg_marks);
        let dbg_vars  = std::mem::take(&mut self.enc.dbg_vars);

        let code = if self.kind.is_object() {
            let kind = self.kind;
            let enc = std::mem::replace(&mut self.enc, crate::encoder::Encoder::new());
            let artifact = enc.finalize_for_coff()?;
            Self::emit_coff(kind, artifact)?
        } else {
            self.enc.finalize()?
        };

        Ok(CompiledBlob { code, dbg_marks, dbg_vars, cna_script: None })
    }

    fn emit_coff(kind: BuildKind, artifact: crate::encoder::CoffArtifact) -> Result<Vec<u8>, String> {
        use crate::coff::{CoffObject, CoffReloc, SectionId, SymKind, IMAGE_REL_AMD64_REL32};
        use crate::encoder::DataSection;
        let mut obj = CoffObject::new();
        obj.text.bytes  = artifact.text;
        obj.rdata.bytes = artifact.rdata;
        obj.data.bytes  = artifact.data;
        obj.bss_size    = artifact.bss_size as u32;

        // Entry symbol. Look up go's offset; for the standard build
        // it's always 0 (we emit the entry first), but read it from
        // the labels map anyway in case future refactors move it.
        let entry_name = kind.entry_name();
        let entry_off = *artifact.code_labels.get(entry_name)
            .ok_or_else(|| format!("BOF entry `{entry_name}` was never emitted"))?
            as u32;
        obj.intern(entry_name, SymKind::TextExtern, entry_off);

        for ext in &artifact.externals {
            let sym_idx = obj.intern(&ext.sym, SymKind::Undefined, 0);
            obj.text.relocs.push(CoffReloc {
                at:  ext.at,
                sym: sym_idx,
                ty:  IMAGE_REL_AMD64_REL32,
            });
        }

        let mut rdata_sym: Option<usize> = None;
        let mut data_sym:  Option<usize> = None;
        let mut bss_sym:   Option<usize> = None;
        for dr in &artifact.data_relocs {
            let sym_idx = match dr.section {
                DataSection::Rdata => *rdata_sym.get_or_insert_with(|| {
                    obj.intern(
                        ".rdata",
                        SymKind::DataStatic { section: SectionId::Rdata },
                        0,
                    )
                }),
                DataSection::Data => *data_sym.get_or_insert_with(|| {
                    obj.intern(
                        ".data",
                        SymKind::DataStatic { section: SectionId::Data },
                        0,
                    )
                }),
                DataSection::Bss => *bss_sym.get_or_insert_with(|| {
                    obj.intern(
                        ".bss",
                        SymKind::DataStatic { section: SectionId::Bss },
                        0,
                    )
                }),
            };
            obj.text.relocs.push(CoffReloc {
                at:  dr.at,
                sym: sym_idx,
                ty:  IMAGE_REL_AMD64_REL32,
            });
        }

        crate::coff::emit(&obj)
    }

    fn gen_function(&mut self, fn_: &Function) -> Result<(), String> {
        self.locals.clear();
        self.local_types.clear();
        self.next_off = 0;
        self.current_ret_label = format!(".L{}_ret", fn_.name);
        self.current_ret_dst_off = None;
        self.current_ret_ty = fn_.ret_ty.clone();
        // Per-function aspect-oriented context - drives the hook
        // bypass logic in should_hook. Reset at the top of every
        // function so calls inside fn A don't see fn B's [NoHook].
        self.current_fn_hook = collect_fn_hook_ctx(fn_);

        let naked = self.overrides.ntcall.as_deref() == Some(fn_.name.as_str());
        if naked {
            self.enc.place_code_label(&fn_.name);
            self.gen_block(&fn_.body)?;
            // No epilogue, no implicit ret. User's body must end with
            // its own ret (usually via asm { ret; }).
            return Ok(());
        }

        let returns_struct = self.struct_layouts.contains_key(&fn_.ret_ty);
        let hidden_dst_bytes = if returns_struct { 8 } else { 0 };
        let want = self.count_local_bytes(&fn_.body)
                 + fn_.params.len() * 8 + 32
                 + hidden_dst_bytes;
        let frame = ((want + 15) / 16) * 16;

        self.enc.place_code_label(&fn_.name);

        let is_entry = fn_.name == self.kind.entry_name();
        if self.opsec.nop_sled {
            let max = if is_entry { 65 } else { 17 };
            let n = self.rng.range(max) as usize;
            polymorphism::emit_nop_sled(&mut self.enc, &mut self.rng, n);
        }

        self.enc.push_r64(Reg64::Rbp);
        self.enc.mov_r64_r64(Reg64::Rbp, Reg64::Rsp);
        self.enc.sub_r64_imm32(Reg64::Rsp, frame as i32);

        let arg_regs = [Reg64::Rcx, Reg64::Rdx, Reg64::R8, Reg64::R9];
        let arg_shift: usize = if returns_struct { 1 } else { 0 };
        if returns_struct {
            let off = self.alloc_local("__ret_dst");
            self.local_types.insert("__ret_dst".into(), format!("{}*", fn_.ret_ty));
            self.enc.mov_rbp_disp_r64(off, Reg64::Rcx);
            self.current_ret_dst_off = Some(off);
        }
        for (i, p) in fn_.params.iter().enumerate() {
            let is_struct_param = self.struct_layouts.contains_key(&p.ty);
            if Self::is_array_type(&p.ty) {
                let elem = parse_array_type(&p.ty).map(|(e, _)| e).unwrap_or("u8");
                return Err(format!(
                    "param `{}: {}`: array-typed params aren't supported - \
                     declare as `{elem}*` and the caller's array decays to a pointer.",
                    p.name, p.ty
                ));
            }
            let off = self.alloc_local(&p.name);
            let internal_ty = if is_struct_param {
                format!("{}*", p.ty)
            } else {
                p.ty.clone()
            };
            self.local_types.insert(p.name.clone(), internal_ty);
            let abi_i = i + arg_shift;
            if abi_i < 4 {
                self.enc.mov_rbp_disp_r64(off, arg_regs[abi_i]);
            } else {
                let caller_off = 48 + ((abi_i - 4) as i32) * 8;
                self.enc.mov_r64_rbp_disp(Reg64::Rax, caller_off);
                self.enc.mov_rbp_disp_r64(off, Reg64::Rax);
            }
        }

        if is_entry && self.opsec.strings_xor && !self.kind.is_object() {
            self.enc.call_label(polymorphism::DECRYPT_FN_LABEL);
        }

        if is_entry && self.opsec.hashed_imports && self.kind.is_object() {
            self.enc.call_label("__resolve_imports");
        }

        // main initialises only the subsystems the program actually uses,
        // chosen by the pre-scan in generate. Each if here saves both a
        // call instruction and the runtime block it would invoke.
        if fn_.name == "main" {
            if self.needs_shared {
                // Caller's rcx is the HostServices* under our entry
                // convention (Win64 first-arg register). Save it before any
                // of our calls can clobber it.
                self.enc.mov_data_r64(shared::SLOT_HOST_SERVICES, Reg64::Rcx);
            }
            if let Some(name) = self.overrides.bootstrap.clone() {
                self.enc.call_label(&name);
            }
            if self.needs_gc {
                self.enc.lea_r64_r64disp(Reg64::Rax, Reg64::Rbp, 16);
                self.enc.mov_data_r64(gc::STACK_TOP, Reg64::Rax);
                self.enc.call_label("__gc_init");
            }
            if self.needs_resolver {
                self.enc.call_label("__resolve_imports");
            }
        }

        if is_entry {
            self.emit_static_initializers()?;
        }

        if is_entry && self.needs_veh {
            self.emit_veh_register();
        }

        if is_entry {
            for name in self.stages.init.clone() {
                self.enc.call_label(&name);
            }
        }

        self.gen_block(&fn_.body)?;

        // Implicit ret 0 fall-through.
        self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
        self.enc.place_code_label(&self.current_ret_label.clone());

        if is_entry && !self.stages.exit.is_empty() {
            const SAVED_RAX_SLOT: &str = "__opsec_stage_exit_saved_rax";
            if !self.enc.data_has(SAVED_RAX_SLOT) {
                self.enc.add_bss(SAVED_RAX_SLOT, 8);
            }
            self.enc.mov_data_r64(SAVED_RAX_SLOT, Reg64::Rax);
            self.enc.sub_r64_imm32(Reg64::Rsp, 0x20);
            for name in self.stages.exit.clone() {
                self.enc.call_label(&name);
            }
            self.enc.add_r64_imm32(Reg64::Rsp, 0x20);
            self.enc.mov_r64_data(Reg64::Rax, SAVED_RAX_SLOT);
        }

        // VEH cleanup before tearing down the frame. Saved-rax dance
        // inside emit_veh_unregister preserves whatever value the
        // user ret-ed (and any Stage handlers left intact).
        if is_entry && self.needs_veh {
            self.emit_veh_unregister();
        }

        self.enc.mov_r64_r64(Reg64::Rsp, Reg64::Rbp);
        self.enc.pop_r64(Reg64::Rbp);
        self.enc.ret();
        Ok(())
    }

    fn gen_block(&mut self, stmts: &[Stmt]) -> Result<(), String> {
        for s in stmts { self.gen_stmt(s)?; }
        Ok(())
    }

    fn gen_stmt(&mut self, s: &Stmt) -> Result<(), String> {
        let (span, kind) = stmt_breadcrumb(s);
        self.enc.dbg_mark(span.line, span.col, kind);
        match s {
            Stmt::Var { name, ty, value, span } => {
                let is_struct = self.struct_layouts.contains_key(ty);
                let is_array  = Self::is_array_type(ty);
                if is_struct || is_array {
                    if is_array && value.is_some() {
                        return Err(format!(
                            "`var {name}: {ty} = ...` - array locals can't have an \
                             initialiser. Drop the `=` for an in-frame zero-initialised slot."
                        ));
                    }
                    let raw_size = if is_struct {
                        self.struct_layouts[ty].size
                    } else {
                        self.type_size(ty)
                    };
                    let off = self.alloc_local_sized(name, raw_size);
                    self.local_types.insert(name.clone(), ty.clone());
                    self.enc.dbg_var(name, ty, off, span.line, u32::MAX);
                    self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
                    let qwords = ((raw_size + 7) / 8) as i32;
                    for i in 0..qwords {
                        self.enc.mov_rbp_disp_r64(off + i * 8, Reg64::Rax);
                    }
                    if let Some(v) = value {
                        match v {
                            Expr::StructLit { ty: lit_ty, fields, .. } => {
                                if lit_ty != ty {
                                    return Err(format!(
                                        "var `{name}` declared as `{ty}` but initialised with \
                                         `{lit_ty} {{...}}` - types must match"
                                    ));
                                }
                                self.emit_struct_lit_into_rbp(lit_ty, fields, off)?;
                            }
                            _ => {
                                // Evaluate source-address in rax; memcpy bytes
                                // from src  to  [rbp+off]. rsi/rdi are non-volatile
                                // under Win64; preserve them.
                                self.gen_expr(v)?;
                                self.enc.push_r64(Reg64::Rsi);
                                self.enc.push_r64(Reg64::Rdi);
                                self.enc.mov_r64_r64(Reg64::Rsi, Reg64::Rax);
                                self.enc.lea_r64_r64disp(Reg64::Rdi, Reg64::Rbp, off);
                                self.enc.mov_r64_imm64(Reg64::Rcx, raw_size as u64);
                                self.enc.cld();
                                self.enc.rep_movsb();
                                self.enc.pop_r64(Reg64::Rdi);
                                self.enc.pop_r64(Reg64::Rsi);
                            }
                        }
                    }
                } else {
                    let off = self.alloc_local(name);
                    self.local_types.insert(name.clone(), ty.clone());
                    self.enc.dbg_var(name, ty, off, span.line, u32::MAX);
                    if let Some(v) = value {
                        self.gen_expr(v)?;
                    } else {
                        self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
                    }
                    self.enc.mov_rbp_disp_r64(off, Reg64::Rax);
                }
            }
            Stmt::Expr { value: e, .. } => { self.gen_expr(e)?; }
            Stmt::Ret { value, .. } => {
                if let (Some(e), Some(dst_off)) = (value, self.current_ret_dst_off) {
                    let size = self.struct_layouts.get(&self.current_ret_ty)
                        .map(|l| l.size)
                        .unwrap_or(0);
                    self.gen_expr(e)?;
                    self.enc.push_r64(Reg64::Rsi);
                    self.enc.push_r64(Reg64::Rdi);
                    self.enc.mov_r64_r64(Reg64::Rsi, Reg64::Rax);
                    self.enc.mov_r64_rbp_disp(Reg64::Rdi, dst_off);
                    self.enc.mov_r64_imm64(Reg64::Rcx, size as u64);
                    self.enc.cld();
                    self.enc.rep_movsb();
                    self.enc.pop_r64(Reg64::Rdi);
                    self.enc.pop_r64(Reg64::Rsi);
                    self.enc.mov_r64_rbp_disp(Reg64::Rax, dst_off);
                    self.enc.jmp_label(&self.current_ret_label.clone());
                } else {
                    if let Some(e) = value { self.gen_expr(e)?; }
                    else                   { self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax); }
                    self.enc.jmp_label(&self.current_ret_label.clone());
                }
            }
            Stmt::If { cond, then_body, else_body } => {
                let l_else = self.new_label("else");
                let l_end  = self.new_label("endif");
                self.gen_expr(cond)?;
                self.enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
                self.enc.jcc_label(Cond::Z, &l_else);
                self.gen_block(then_body)?;
                self.enc.jmp_label(&l_end);
                self.enc.place_code_label(&l_else);
                self.gen_block(else_body)?;
                self.enc.place_code_label(&l_end);
            }
            Stmt::While { cond, body } => {
                let l_top = self.new_label("while_top");
                let l_end = self.new_label("while_end");
                self.enc.place_code_label(&l_top);
                self.gen_expr(cond)?;
                self.enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
                self.enc.jcc_label(Cond::Z, &l_end);
                // continue in a while re-tests the condition, so the
                // continue target is the same label as the top.
                self.loop_stack.push((l_top.clone(), l_end.clone()));
                self.gen_block(body)?;
                self.loop_stack.pop();
                self.enc.jmp_label(&l_top);
                self.enc.place_code_label(&l_end);
            }
            Stmt::For { init, cond, step, body } => {
                let l_top = self.new_label("for_top");
                let l_cont = self.new_label("for_cont");
                let l_end = self.new_label("for_end");
                if let Some(i) = init { self.gen_stmt(i)?; }
                self.enc.place_code_label(&l_top);
                if let Some(c) = cond {
                    self.gen_expr(c)?;
                    self.enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
                    self.enc.jcc_label(Cond::Z, &l_end);
                }
                self.loop_stack.push((l_cont.clone(), l_end.clone()));
                self.gen_block(body)?;
                self.loop_stack.pop();
                self.enc.place_code_label(&l_cont);
                if let Some(s) = step { self.gen_stmt(s)?; }
                self.enc.jmp_label(&l_top);
                self.enc.place_code_label(&l_end);
            }
            Stmt::Break => {
                let (_, l_end) = self.loop_stack.last().cloned()
                    .ok_or_else(|| "`break` outside of a loop".to_string())?;
                self.enc.jmp_label(&l_end);
            }
            Stmt::Continue => {
                let (l_cont, _) = self.loop_stack.last().cloned()
                    .ok_or_else(|| "`continue` outside of a loop".to_string())?;
                self.enc.jmp_label(&l_cont);
            }
            Stmt::Try { body, err_name, handler } => {
                let l_handler = self.new_label("try_handler");
                let l_end     = self.new_label("try_end");

                macros::emit_try_prologue(&mut self.enc, &l_handler);
                self.gen_block(body)?;
                macros::emit_try_epilogue(&mut self.enc);
                self.enc.jmp_label(&l_end);

                // Handler entry: by convention rax holds the raised value.
                // We spill it into a local named err_name if there's room.
                self.enc.place_code_label(&l_handler);
                let off = self.alloc_local(err_name);
                self.local_types.insert(err_name.clone(), "int".into());
                self.enc.mov_rbp_disp_r64(off, Reg64::Rax);
                self.gen_block(handler)?;
                self.enc.place_code_label(&l_end);
            }
            Stmt::Asm(lines) => {
                self.gen_asm(lines)?;
            }
            Stmt::Raise { value, .. } => {
                self.gen_expr(value)?;
                let fail = self.new_label("raise_fail");
                macros::emit_raise(&mut self.enc, &fail);
            }
        }
        Ok(())
    }

    /// Result of an expression is left in rax.
    fn gen_expr(&mut self, e: &Expr) -> Result<(), String> {
        match e {
            Expr::Int(n)  => self.enc.mov_r64_imm64(Reg64::Rax, *n as u64),
            Expr::Bool(b) => self.enc.mov_r64_imm64(Reg64::Rax, if *b {1} else {0}),
            Expr::Str(s)  => {
                if self.should_stack_build_str(s) {
                    self.emit_stack_string(s)?;
                } else {
                    let lbl = format!("__str_{}", self.label_counter);
                    self.label_counter += 1;
                    self.enc.add_string(&lbl, s);
                    self.enc.lea_r64_data(Reg64::Rax, &lbl);
                }
            }
            Expr::Var(name) => {
                if let Some(&off) = self.locals.get(name) {
                    let ty = self.local_types.get(name).cloned().unwrap_or_default();
                    if self.struct_layouts.contains_key(&ty) || Self::is_array_type(&ty) {
                        self.enc.lea_r64_r64disp(Reg64::Rax, Reg64::Rbp, off);
                    } else {
                        self.enc.mov_r64_rbp_disp(Reg64::Rax, off);
                    }
                } else if let Some(&idx) = self.globals_idx.get(name) {
                    // Mirror of the local rules. Struct/array globals lea
                    // their data label; everything else loads the qword.
                    let g = &self.globals[idx];
                    if self.struct_layouts.contains_key(&g.ty) || Self::is_array_type(&g.ty) {
                        self.enc.lea_r64_data(Reg64::Rax, &g.label);
                    } else {
                        self.enc.mov_r64_data(Reg64::Rax, &g.label);
                    }
                } else if self.fn_ret_types.contains_key(name) {
                    self.enc.lea_r64_code(Reg64::Rax, name);
                } else {
                    return Err(format!("undefined variable: {name}"));
                }
            }
            Expr::Assign { name, value } => {
                if let Some(&off) = self.locals.get(name) {
                    self.gen_expr(value)?;
                    self.enc.mov_rbp_disp_r64(off, Reg64::Rax);
                } else if let Some(&idx) = self.globals_idx.get(name) {
                    let label = self.globals[idx].label.clone();
                    self.gen_expr(value)?;
                    self.enc.mov_data_r64(&label, Reg64::Rax);
                } else {
                    return Err(format!("undefined variable: {name}"));
                }
            }
            Expr::Field { base, field } => {
                let (offset, ty, size) = self.resolve_field(base, field)?;
                self.gen_addr(base)?;             // rax = base address
                // Array fields and embedded struct fields don't load - they
                // decay to the address of their first byte. Indexing /
                // field-of-field chains pick up from there.
                if Self::is_array_type(&ty) || self.struct_layouts.contains_key(&ty) {
                    if offset != 0 {
                        self.enc.add_r64_imm32(Reg64::Rax, offset);
                    }
                } else {
                    match size {
                        1 => self.enc.movzx_r64_byte_r64disp(Reg64::Rax, Reg64::Rax, offset),
                        2 => self.enc.movzx_r64_word_r64disp(Reg64::Rax, Reg64::Rax, offset),
                        4 => self.enc.mov_r32_r64disp(Reg64::Rax, Reg64::Rax, offset),
                        8 => self.enc.mov_r64_r64disp(Reg64::Rax, Reg64::Rax, offset),
                        n => return Err(format!("field load: size {n} not supported (use a pointer field)")),
                    }
                }
            }
            Expr::FieldAssign { base, field, value } => {
                let (offset, _ty, size) = self.resolve_field(base, field)?;
                // Evaluate value first, stash on stack (pair-aligned).
                self.gen_expr(value)?;
                self.enc.push_r64(Reg64::Rax);
                self.enc.sub_r64_imm32(Reg64::Rsp, 8);
                self.gen_addr(base)?;             // rax = base address
                self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);
                self.enc.add_r64_imm32(Reg64::Rsp, 8);
                self.enc.pop_r64(Reg64::Rax);     // restore the value
                // Width-correct store; the low size bytes of rax are written.
                match size {
                    1 => self.enc.mov_byte_r64disp_r8(Reg64::Rcx, offset, Reg64::Rax),
                    2 => self.enc.mov_word_r64disp_r16(Reg64::Rcx, offset, Reg64::Rax),
                    4 => self.enc.mov_dword_r64disp_r32(Reg64::Rcx, offset, Reg64::Rax),
                    8 => self.enc.mov_r64disp_r64(Reg64::Rcx, offset, Reg64::Rax),
                    n => return Err(format!("field store: size {n} not supported")),
                }
            }
            Expr::Cast { ty, expr } => {
                if ty == "wstr" {
                    if let Expr::Str(s) = expr.as_ref() {
                        let lbl = format!("__wstr_{}", self.label_counter);
                        self.label_counter += 1;
                        let mut bytes = Vec::with_capacity(s.len() * 2 + 2);
                        for u in s.encode_utf16() {
                            bytes.extend_from_slice(&u.to_le_bytes());
                        }
                        bytes.push(0); bytes.push(0);
                        self.enc.add_data(&lbl, &bytes);
                        self.enc.lea_r64_data(Reg64::Rax, &lbl);
                        return Ok(());
                    }
                    return Err(
                        "(wstr) cast supports only string literals in V1; \
                         runtime ASCII to UTF-16 conversion isn't wired up yet".into()
                    );
                }
                if let Some(lit) = literal_int_value(expr) {
                    if let Some(narrowed) = narrow_int_literal(ty, lit) {
                        self.enc.mov_r64_imm64(Reg64::Rax, narrowed as u64);
                        return Ok(());
                    }
                }
                self.gen_expr(expr)?;
            }
            Expr::SizeOf { ty } => {
                let size = self.type_size(ty) as u64;
                self.enc.mov_r64_imm64(Reg64::Rax, size);
            }
            Expr::Unary { op, operand } => {
                // & and * don't follow the "evaluate operand, then operate"
                // pattern - they need the variable's address or the
                // pointer's value as the starting point.
                if op == "&" {
                    return self.gen_addr_of(operand);
                }
                if op == "*" {
                    // Determine pointee width before clobbering operand
                    // typing. Defaults to qword if we can't infer.
                    let inner_ty = self.expr_type(operand);
                    let pointee_ty = pointee(&inner_ty)
                        .map(String::from)
                        .unwrap_or_else(|| inner_ty.clone());
                    // Loading a struct value into rax doesn't make sense -
                    // structs are multi-byte and we have no in-register
                    // struct representation. Direct user to (*p).field.
                    if self.struct_layouts.contains_key(&pointee_ty) {
                        return Err(format!(
                            "`*` on a `{inner_ty}` doesn't yield a usable value - \
                             use `(*p).field` for fields or pass `p` directly"
                        ));
                    }
                    self.gen_expr(operand)?;             // rax = pointer
                    self.emit_load_width(&pointee_ty, Reg64::Rax);
                    return Ok(());
                }
                self.gen_expr(operand)?;
                match op.as_str() {
                    "-" => {
                        // neg rax = REX.W F7 /3
                        self.enc.emit_raw(0x48);
                        self.enc.emit_raw(0xF7);
                        self.enc.emit_raw(0xD8); // mod=11 /3 rm=000(rax)
                    }
                    "!" => {
                        self.enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
                        // sete al = 0F 94 C0
                        self.enc.emit_raw(0x0F);
                        self.enc.emit_raw(0x94);
                        self.enc.emit_raw(0xC0);
                        // movzx eax, al  = 0F B6 C0 - implicit zero-extend
                        // to rax. 3 bytes vs 4 for the REX.W form.
                        self.enc.emit_raw(0x0F);
                        self.enc.emit_raw(0xB6);
                        self.enc.emit_raw(0xC0);
                    }
                    "~" => self.enc.not_r64(Reg64::Rax),
                    _ => return Err(format!("unknown unary op: {op}")),
                }
            }
            Expr::Binary { op, lhs, rhs } => self.gen_binary(op, lhs, rhs)?,
            Expr::Call { ns, fname, args, .. } => self.gen_call(ns, fname, args)?,
            Expr::DerefAssign { ptr, value } => {
                // Same shape as FieldAssign - evaluate value, stash it,
                // evaluate ptr, then width-correct store at [rcx].
                let inner_ty = self.expr_type(ptr);
                let pointee_ty = pointee(&inner_ty)
                    .map(String::from)
                    .unwrap_or_else(|| inner_ty.clone());
                self.gen_expr(value)?;
                self.enc.push_r64(Reg64::Rax);
                self.enc.sub_r64_imm32(Reg64::Rsp, 8);
                self.gen_expr(ptr)?;
                self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);
                self.enc.add_r64_imm32(Reg64::Rsp, 8);
                self.enc.pop_r64(Reg64::Rax);
                self.emit_store_width(&pointee_ty, Reg64::Rcx);
            }
            Expr::Index { base, index } => {
                self.gen_index_load(base, index)?;
            }
            Expr::IndexAssign { base, index, value } => {
                self.gen_index_store(base, index, value)?;
            }
            Expr::StructLit { ty, fields, .. } => {
                let layout = self.struct_layouts.get(ty)
                    .ok_or_else(|| format!(
                        "unknown struct `{ty}` in struct literal"
                    ))?;
                let raw_size = layout.size;
                let tmp_name = format!("__lit_tmp_{}", self.label_counter);
                self.label_counter += 1;
                let off = self.alloc_local_sized(&tmp_name, raw_size);
                // Zero-fill, then write each field. Address of the slot
                // ends up in rax for the caller to use as the struct
                // base. Order: zero, fields, lea rax.
                self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
                let qwords = ((raw_size + 7) / 8) as i32;
                for i in 0..qwords {
                    self.enc.mov_rbp_disp_r64(off + i * 8, Reg64::Rax);
                }
                self.emit_struct_lit_into_rbp(ty, fields, off)?;
                self.enc.lea_r64_r64disp(Reg64::Rax, Reg64::Rbp, off);
            }
        }
        Ok(())
    }

    fn emit_struct_lit_into_rbp(
        &mut self,
        ty: &str,
        fields: &[(String, Expr)],
        base_off: i32,
    ) -> Result<(), String> {
        // Clone the layout fields out so we can call back into gen_expr
        // without holding a borrow of self.struct_layouts.
        let layout = self.struct_layouts.get(ty)
            .ok_or_else(|| format!("unknown struct `{ty}` in struct literal"))?
            .clone();
        for (fname, fval) in fields {
            let f = layout.fields.get(fname).ok_or_else(|| format!(
                "struct `{ty}` has no field `{fname}`"
            ))?;
            let foff = base_off + f.offset;
            self.gen_expr(fval)?;
            match f.size {
                1 => self.enc.mov_byte_r64disp_r8(Reg64::Rbp, foff, Reg64::Rax),
                2 => self.enc.mov_word_r64disp_r16(Reg64::Rbp, foff, Reg64::Rax),
                4 => self.enc.mov_dword_r64disp_r32(Reg64::Rbp, foff, Reg64::Rax),
                8 => self.enc.mov_rbp_disp_r64(foff, Reg64::Rax),
                n => return Err(format!(
                    "struct literal: field `{ty}.{fname}` has size {n}; \
                     only 1/2/4/8 byte fields supported"
                )),
            }
        }
        Ok(())
    }

    fn gen_index_load(&mut self, base: &Expr, index: &Expr) -> Result<(), String> {
        let elem_ty = self.index_element_type(base)?;
        let elem_size = self.type_size(&elem_ty);
        if self.struct_layouts.contains_key(&elem_ty) {
            return Err(format!(
                "indexing yields a struct-typed element (`{elem_ty}`) - \
                 in-register struct values aren't supported. Index a pointer or \
                 use `&base[i]` then `.field`."
            ));
        }

        // Evaluate the index first, save it, then evaluate the base. The
        // base is an arbitrary expression (var, field, call, deref) so it
        // gets the standard rcx-scratch path.
        self.gen_expr(index)?;
        self.enc.push_r64(Reg64::Rax);
        self.enc.sub_r64_imm32(Reg64::Rsp, 8);
        self.gen_index_base(base)?;
        self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);   // rcx = base
        self.enc.add_r64_imm32(Reg64::Rsp, 8);
        self.enc.pop_r64(Reg64::Rdx);                    // rdx = index

        match elem_size {
            1 => self.enc.movzx_r64_byte_base_idx(Reg64::Rax, Reg64::Rcx, Reg64::Rdx),
            2 => self.enc.movzx_r64_word_base_idx(Reg64::Rax, Reg64::Rcx, Reg64::Rdx),
            4 => self.enc.mov_r32_base_idx(Reg64::Rax, Reg64::Rcx, Reg64::Rdx),
            8 => self.enc.mov_r64_base_idx(Reg64::Rax, Reg64::Rcx, Reg64::Rdx),
            n => {
                // Fall-back: imul rdx, rdx, n; mov rax, [rcx + rdx]
                self.enc.mov_r64_imm64(Reg64::Rax, n as u64);
                // imul rdx, rax = REX.W 0F AF D0 - uses rdx <- rdx*rax
                self.enc.emit_raw(0x48);
                self.enc.emit_raw(0x0F);
                self.enc.emit_raw(0xAF);
                self.enc.emit_raw(0xD0);
                self.enc.mov_r64_r64disp(Reg64::Rax, Reg64::Rcx, 0);
                // For non-power-of-2 sizes we just deliver the qword at
                // the computed offset. Callers needing partial-width
                // loads should declare a more precise element type.
                let _ = Reg64::Rdx; // suppress unused warning if any
            }
        }
        Ok(())
    }

    /// Lower base[index] = value. Same register convention as
    /// [gen_index_load], plus the value spills to a stack slot while
    /// the base/index are computed.
    fn gen_index_store(&mut self, base: &Expr, index: &Expr, value: &Expr) -> Result<(), String> {
        let elem_ty = self.index_element_type(base)?;
        let elem_size = self.type_size(&elem_ty);
        if self.struct_layouts.contains_key(&elem_ty) {
            return Err(format!(
                "indexed write to a struct-typed element (`{elem_ty}`) isn't supported. \
                 Write field-by-field via `((TYPE)&base[i]).field = ...`."
            ));
        }

        // Save the value to a stack slot, then the index, then evaluate the
        // base. After: rcx = base, rdx = index, rax = value.
        self.gen_expr(value)?;
        self.enc.push_r64(Reg64::Rax);
        self.enc.sub_r64_imm32(Reg64::Rsp, 8);
        self.gen_expr(index)?;
        self.enc.push_r64(Reg64::Rax);
        self.enc.sub_r64_imm32(Reg64::Rsp, 8);
        self.gen_index_base(base)?;
        self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);    // rcx = base
        self.enc.add_r64_imm32(Reg64::Rsp, 8);
        self.enc.pop_r64(Reg64::Rdx);                     // rdx = index
        self.enc.add_r64_imm32(Reg64::Rsp, 8);
        self.enc.pop_r64(Reg64::Rax);                     // rax = value

        match elem_size {
            1 => self.enc.mov_byte_base_idx_r8(Reg64::Rcx, Reg64::Rdx, Reg64::Rax),
            2 => self.enc.mov_word_base_idx_r16(Reg64::Rcx, Reg64::Rdx, Reg64::Rax),
            4 => self.enc.mov_dword_base_idx_r32(Reg64::Rcx, Reg64::Rdx, Reg64::Rax),
            8 => self.enc.mov_qword_base_idx_r64(Reg64::Rcx, Reg64::Rdx, Reg64::Rax),
            n => return Err(format!(
                "indexed store with element size {n} isn't supported \
                 (only 1/2/4/8 today)"
            )),
        }
        Ok(())
    }

    fn gen_index_base(&mut self, base: &Expr) -> Result<(), String> {
        self.gen_expr(base)
    }

    /// Look at the static type of base and decide what element type
    /// base[i] produces. Either T[N]  to  T, T*  to  T, or an error.
    fn index_element_type(&self, base: &Expr) -> Result<String, String> {
        let ty = self.expr_type(base);
        if let Some(elem) = Self::element_type(&ty) {
            Ok(elem)
        } else {
            Err(format!(
                "cannot index a value of type `{ty}` - only pointer (`T*`) \
                 and array (`T[N]`) types support `[i]`"
            ))
        }
    }

    fn gen_binary(&mut self, op: &str, lhs: &Expr, rhs: &Expr) -> Result<(), String> {
        // Short-circuit boolean ops
        if op == "&&" || op == "||" {
            let l_short = self.new_label(if op == "&&" {"and_sc"} else {"or_sc"});
            let l_end   = self.new_label("logic_end");
            self.gen_expr(lhs)?;
            self.enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
            self.enc.jcc_label(if op == "&&" { Cond::Z } else { Cond::Nz }, &l_short);
            self.gen_expr(rhs)?;
            self.enc.test_r64_r64(Reg64::Rax, Reg64::Rax);
            self.enc.jcc_label(if op == "&&" { Cond::Z } else { Cond::Nz }, &l_short);
            self.enc.mov_r64_imm64(Reg64::Rax, if op == "&&" {1} else {0});
            self.enc.jmp_label(&l_end);
            self.enc.place_code_label(&l_short);
            self.enc.mov_r64_imm64(Reg64::Rax, if op == "&&" {0} else {1});
            self.enc.place_code_label(&l_end);
            return Ok(());
        }

        // Standard binary: eval lhs, save (paired for alignment), eval rhs, combine.
        self.gen_expr(lhs)?;
        self.enc.push_r64(Reg64::Rax);
        self.enc.sub_r64_imm32(Reg64::Rsp, 8);    // align padding
        self.gen_expr(rhs)?;
        self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);
        self.enc.add_r64_imm32(Reg64::Rsp, 8);
        self.enc.pop_r64(Reg64::Rax);

        match op {
            "+" => self.enc.add_r64_r64(Reg64::Rax, Reg64::Rcx),
            "-" => self.enc.sub_r64_r64(Reg64::Rax, Reg64::Rcx),
            "*" => {
                // imul rax, rcx = REX.W 0F AF C1
                self.enc.emit_raw(0x48);
                self.enc.emit_raw(0x0F);
                self.enc.emit_raw(0xAF);
                self.enc.emit_raw(0xC1);
            }
            "/" | "%" => {
                // cqo + idiv rcx, then move rdx -> rax for %
                self.enc.emit_raw(0x48); self.enc.emit_raw(0x99);             // cqo
                self.enc.emit_raw(0x48); self.enc.emit_raw(0xF7); self.enc.emit_raw(0xF9); // idiv rcx
                if op == "%" { self.enc.mov_r64_r64(Reg64::Rax, Reg64::Rdx); }
            }
            "==" | "!=" | "<" | ">" | "<=" | ">=" => {
                self.enc.cmp_r64_r64(Reg64::Rax, Reg64::Rcx);
                // setcc al
                let cc = match op {
                    "==" => 0x94, "!=" => 0x95,
                    "<"  => 0x9C, ">=" => 0x9D,
                    "<=" => 0x9E, ">"  => 0x9F,
                    _ => unreachable!(),
                };
                self.enc.emit_raw(0x0F); self.enc.emit_raw(cc); self.enc.emit_raw(0xC0);
                // movzx eax, al - 3 bytes, implicit zero-extend to rax
                self.enc.emit_raw(0x0F);
                self.enc.emit_raw(0xB6); self.enc.emit_raw(0xC0);
            }
            "&" => self.enc.and_r64_r64(Reg64::Rax, Reg64::Rcx),
            "|" => self.enc.or_r64_r64 (Reg64::Rax, Reg64::Rcx),
            "^" => self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rcx),
            "<<" => self.enc.shl_r64_cl(Reg64::Rax),
            ">>" => self.enc.sar_r64_cl(Reg64::Rax),
            _ => return Err(format!("unknown binary op: {op}")),
        }
        Ok(())
    }


    fn gen_asm(&mut self, lines: &[AsmLine]) -> Result<(), String> {
        // Per-asm-block label prefix. Bumped once per asm { ... }
        // so a function with two asm blocks declaring loop_top:
        // doesn't collide.
        let block_id = self.label_counter;
        self.label_counter += 1;
        let mangle = |name: &str| format!("__asm{block_id}_{name}");

        for line in lines {
            if !matches!(line.body, AsmBody::Label(_)) {
                self.enc.dbg_mark(line.line, line.col, "asm");
            }

            match &line.body {
                AsmBody::Label(name) => {
                    let lbl = mangle(name);
                    self.enc.place_code_label(&lbl);
                }
                AsmBody::Db(bytes) => {
                    for b in bytes { self.enc.emit_raw(*b); }
                }
                AsmBody::Op0 { mnem } => self.gen_asm_op0(mnem)?,
                AsmBody::Op1 { mnem, op } => self.gen_asm_op1(mnem, op, &mangle)?,
                AsmBody::Op2 { mnem, dst, src } => self.gen_asm_op2(mnem, dst, src)?,
            }
        }
        Ok(())
    }

    fn gen_asm_op0(&mut self, mnem: &str) -> Result<(), String> {
        match mnem {
            "ret"     => self.enc.ret(),
            "nop"     => self.enc.nop(),
            "int3"    => self.enc.int3(),
            "syscall" => self.enc.syscall_(),
            "cld"     => self.enc.cld(),
            other => return Err(format!("asm: unknown 0-operand mnemonic `{other}`")),
        }
        Ok(())
    }

    fn gen_asm_op1<F: Fn(&str) -> String>(
        &mut self, mnem: &str, op: &AsmOperand, mangle: &F,
    ) -> Result<(), String> {
        // Jump / call mnemonics - operand is a label (asm-local or
        // function-symbol) OR a register (indirect call/jmp).
        let jcc = match mnem {
            "je"  | "jz"  => Some(Cond::Eq),
            "jne" | "jnz" => Some(Cond::Ne),
            "jl"          => Some(Cond::Lt),
            "jg"          => Some(Cond::Gt),
            "jle"         => Some(Cond::Le),
            "jge"         => Some(Cond::Ge),
            "jb"          => Some(Cond::B),
            "jbe"         => Some(Cond::Be),
            "ja"          => Some(Cond::A),
            "jae"         => Some(Cond::Ae),
            "js"          => Some(Cond::S),
            "jns"         => Some(Cond::Ns),
            _             => None,
        };
        if let Some(cond) = jcc {
            return self.gen_asm_branch_to(op, mangle, |enc, lbl| enc.jcc_label(cond, lbl));
        }
        if mnem == "jmp" {
            return match op {
                AsmOperand::Reg(r) => { self.enc.jmp_r64(*r); Ok(()) }
                _ => self.gen_asm_branch_to(op, mangle, |enc, lbl| enc.jmp_label(lbl)),
            };
        }
        if mnem == "call" {
            return match op {
                AsmOperand::Reg(r) => { self.enc.call_r64(*r); Ok(()) }
                AsmOperand::Sym(name) => {
                    if self.fn_ret_types.contains_key(name) && !self.extern_fns.contains(name) {
                        self.enc.call_label(name);
                        Ok(())
                    } else if self.extern_fns.contains(name) {
                        if !self.kind.is_object() {
                            return Err(format!(
                                "asm: `call %{name}` - `{name}` is `extern`, \
                                 only callable in --type=bof|coff builds."
                            ));
                        }
                        let imp = format!("__imp_{name}");
                        self.enc.call_extern(&imp);
                        Ok(())
                    } else {
                        Err(format!("asm: `call %{name}` - no function named `{name}` in scope"))
                    }
                }
                AsmOperand::Mem(mem) => {
                    self.emit_load_mem(Reg64::Rax, mem)?;
                    self.enc.call_r64(Reg64::Rax);
                    Ok(())
                }
                AsmOperand::Imm(_) => Err("asm: `call <imm>` - immediate not supported".into()),
            };
        }

        // Single-register / single-operand ops.
        match mnem {
            "push" => match op {
                AsmOperand::Reg(r) => { self.enc.push_r64(*r); Ok(()) }
                AsmOperand::Imm(n) => {
                    // push imm32 - sign-extended to 64.
                    let imm = (*n as i64) as i32;
                    if (*n as i64) != imm as i64 {
                        return Err(format!("asm: `push {n}` - immediate out of i32 range"));
                    }
                    self.enc.push_imm32(imm);
                    Ok(())
                }
                AsmOperand::Sym(name) => {
                    // push %local - push the local's VALUE.
                    self.emit_load_sym_into(Reg64::Rax, name)?;
                    self.enc.push_r64(Reg64::Rax);
                    Ok(())
                }
                AsmOperand::Mem(mem) => {
                    self.emit_load_mem(Reg64::Rax, mem)?;
                    self.enc.push_r64(Reg64::Rax);
                    Ok(())
                }
            },
            "pop" => match op {
                AsmOperand::Reg(r) => { self.enc.pop_r64(*r); Ok(()) }
                AsmOperand::Sym(name) => {
                    // pop %local - pop into rax, then store.
                    self.enc.pop_r64(Reg64::Rax);
                    self.emit_store_sym_from(name, Reg64::Rax)
                }
                _ => Err("asm: `pop` requires a register or %local destination".into()),
            },
            "inc" | "dec" | "neg" | "not" | "bswap" => {
                let reg = match op {
                    AsmOperand::Reg(r) => *r,
                    _ => return Err(format!("asm: `{mnem}` requires a register operand")),
                };
                match mnem {
                    "inc"   => self.enc.inc_r64(reg),
                    "dec"   => self.enc.dec_r64(reg),
                    "neg"   => self.enc.neg_r64(reg),
                    "not"   => self.enc.not_r64(reg),
                    "bswap" => self.enc.bswap_r64(reg),
                    _ => unreachable!(),
                }
                Ok(())
            }
            other => Err(format!("asm: unknown 1-operand mnemonic `{other}`")),
        }
    }

    /// Helper for jmp/jcc targeting - operand may be a %name
    /// (function symbol) or a bare identifier we wrap as an
    /// asm-local label.
    fn gen_asm_branch_to<F, E>(
        &mut self, op: &AsmOperand, mangle: &F, emit: E,
    ) -> Result<(), String>
    where
        F: Fn(&str) -> String,
        E: FnOnce(&mut Encoder, &str),
    {
        let target = match op {
            AsmOperand::Sym(name) => {
                // A %name in a jump position means a function
                // symbol (e.g. jmp %retry). Anything else is an
                // asm-local label.
                if self.fn_ret_types.contains_key(name) && !self.extern_fns.contains(name) {
                    name.clone()
                } else {
                    mangle(name)
                }
            }
            AsmOperand::Reg(_) | AsmOperand::Imm(_) | AsmOperand::Mem(_) => {
                return Err("asm: jump target must be a label (use `jmp reg` for indirect)".into());
            }
        };
        emit(&mut self.enc, &target);
        Ok(())
    }

    fn gen_asm_op2(
        &mut self, mnem: &str, dst: &AsmOperand, src: &AsmOperand,
    ) -> Result<(), String> {
        // cmovcc - condition nibble shared with jcc.
        let cmov = match mnem {
            "cmove"  | "cmovz"  => Some(Cond::Eq),
            "cmovne" | "cmovnz" => Some(Cond::Ne),
            "cmovl"             => Some(Cond::Lt),
            "cmovg"             => Some(Cond::Gt),
            "cmovle"            => Some(Cond::Le),
            "cmovge"            => Some(Cond::Ge),
            "cmovb"             => Some(Cond::B),
            "cmovbe"            => Some(Cond::Be),
            "cmova"             => Some(Cond::A),
            "cmovae"            => Some(Cond::Ae),
            "cmovs"             => Some(Cond::S),
            "cmovns"            => Some(Cond::Ns),
            _                   => None,
        };
        if let Some(cond) = cmov {
            return self.gen_asm_cmov(cond, dst, src);
        }
        match mnem {
            "mov"   => self.gen_asm_mov(dst, src),
            "lea"   => self.gen_asm_lea(dst, src),
            "movsxb" | "movsxw" | "movsxd" => {
                self.gen_asm_movsx(mnem, dst, src)
            }
            "rol" | "ror" => self.gen_asm_rotate(mnem, dst, src),
            "xchg"  => self.gen_asm_xchg(dst, src),
            "add" | "sub" | "xor" | "and" | "or" | "cmp" | "test" => {
                self.gen_asm_alu2(mnem, dst, src)
            }
            other => Err(format!("asm: unknown 2-operand mnemonic `{other}`")),
        }
    }

    /// cmovcc dst, src - reg-reg only.
    fn gen_asm_cmov(
        &mut self, cond: Cond, dst: &AsmOperand, src: &AsmOperand,
    ) -> Result<(), String> {
        let d = match dst {
            AsmOperand::Reg(r) => *r,
            _ => return Err("asm: `cmovcc` destination must be a register".into()),
        };
        let s = match src {
            AsmOperand::Reg(r) => *r,
            _ => return Err(
                "asm: `cmovcc` source must be a register (load from memory first)".into()
            ),
        };
        self.enc.cmovcc_r64_r64(cond, d, s);
        Ok(())
    }

    /// rol/ror dst, imm8 or rol/ror dst, cl.
    fn gen_asm_rotate(
        &mut self, mnem: &str, dst: &AsmOperand, src: &AsmOperand,
    ) -> Result<(), String> {
        let d = match dst {
            AsmOperand::Reg(r) => *r,
            _ => return Err(format!("asm: `{mnem}` destination must be a register")),
        };
        match src {
            AsmOperand::Imm(n) => {
                let count = u8::try_from(*n & 0x3F).map_err(|_| {
                    format!("asm: `{mnem}` rotate count must fit in u8")
                })?;
                match mnem {
                    "rol" => self.enc.rol_r64_imm8(d, count),
                    "ror" => self.enc.ror_r64_imm8(d, count),
                    _ => unreachable!(),
                }
                Ok(())
            }
            // cl parses as Sym since the parser only knows r64 names.
            AsmOperand::Sym(name) if name == "cl" => {
                match mnem {
                    "rol" => self.enc.rol_r64_cl(d),
                    "ror" => self.enc.ror_r64_cl(d),
                    _ => unreachable!(),
                }
                Ok(())
            }
            AsmOperand::Reg(Reg64::Rcx) => {
                match mnem {
                    "rol" => self.enc.rol_r64_cl(d),
                    "ror" => self.enc.ror_r64_cl(d),
                    _ => unreachable!(),
                }
                Ok(())
            }
            AsmOperand::Reg(_) => Err(format!(
                "asm: `{mnem} reg, reg` - the count register must be cl (or rcx)"
            )),
            _ => Err(format!(
                "asm: `{mnem}` source must be an immediate count or cl"
            )),
        }
    }

    /// movsxb/w/d dst, [mem] or movsxd dst, r32.
    fn gen_asm_movsx(
        &mut self, mnem: &str, dst: &AsmOperand, src: &AsmOperand,
    ) -> Result<(), String> {
        let d = match dst {
            AsmOperand::Reg(r) => *r,
            _ => return Err(format!("asm: `{mnem}` destination must be a register")),
        };
        match (mnem, src) {
            (_, AsmOperand::Mem(mem)) => {
                let seg = mem.seg;
                match self.mem_addressing(mem)? {
                    ResolvedMem::RbpDisp(disp) => {
                        if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                        match mnem {
                            "movsxb" => self.enc.movsx_r64_byte_r64disp(d, Reg64::Rbp, disp),
                            "movsxw" => self.enc.movsx_r64_word_r64disp(d, Reg64::Rbp, disp),
                            "movsxd" => self.enc.movsxd_r64_r64disp(d, Reg64::Rbp, disp),
                            _ => unreachable!(),
                        }
                        Ok(())
                    }
                    ResolvedMem::BaseDisp { base, disp } => {
                        if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                        match mnem {
                            "movsxb" => self.enc.movsx_r64_byte_r64disp(d, base, disp),
                            "movsxw" => self.enc.movsx_r64_word_r64disp(d, base, disp),
                            "movsxd" => self.enc.movsxd_r64_r64disp(d, base, disp),
                            _ => unreachable!(),
                        }
                        Ok(())
                    }
                    ResolvedMem::SegAbs { .. } => Err(format!(
                        "asm: `{mnem}` with a segmented disp-only operand is not supported - \
                         load through a base register first"
                    )),
                    _ => Err(format!(
                        "asm: `{mnem}` indexed / data / sym memory addressing not yet supported"
                    )),
                }
            }
            ("movsxd", AsmOperand::Reg(s)) => {
                self.enc.movsxd_r64_r64(d, *s);
                Ok(())
            }
            (_, AsmOperand::Reg(_)) => Err(format!(
                "asm: `{mnem} reg, reg` is not supported - use a [mem] source"
            )),
            _ => Err(format!(
                "asm: `{mnem}` source must be a memory operand"
            )),
        }
    }

    /// xchg a, b - reg-reg only.
    fn gen_asm_xchg(
        &mut self, dst: &AsmOperand, src: &AsmOperand,
    ) -> Result<(), String> {
        let a = match dst {
            AsmOperand::Reg(r) => *r,
            _ => return Err("asm: `xchg` operands must both be registers".into()),
        };
        let b = match src {
            AsmOperand::Reg(r) => *r,
            _ => return Err("asm: `xchg` operands must both be registers".into()),
        };
        self.enc.xchg_r64_r64(a, b);
        Ok(())
    }

    /// Lower mov dst, src over every dst/src shape we accept.
    fn gen_asm_mov(&mut self, dst: &AsmOperand, src: &AsmOperand) -> Result<(), String> {
        match (dst, src) {
            // mov reg, reg
            (AsmOperand::Reg(d), AsmOperand::Reg(s)) => {
                self.enc.mov_r64_r64(*d, *s); Ok(())
            }
            // mov reg, imm
            (AsmOperand::Reg(d), AsmOperand::Imm(n)) => {
                self.enc.mov_r64_imm64(*d, *n as u64); Ok(())
            }
            // mov reg, %name
            (AsmOperand::Reg(d), AsmOperand::Sym(name)) => {
                self.emit_load_sym_into(*d, name)
            }
            // mov reg, [mem]
            (AsmOperand::Reg(d), AsmOperand::Mem(mem)) => {
                self.emit_load_mem(*d, mem)
            }
            // mov %name, reg
            (AsmOperand::Sym(name), AsmOperand::Reg(s)) => {
                self.emit_store_sym_from(name, *s)
            }
            // mov %name, imm
            (AsmOperand::Sym(name), AsmOperand::Imm(n)) => {
                self.enc.mov_r64_imm64(Reg64::Rax, *n as u64);
                self.emit_store_sym_from(name, Reg64::Rax)
            }
            // mov [mem], reg
            (AsmOperand::Mem(mem), AsmOperand::Reg(s)) => {
                self.emit_store_mem(mem, *s)
            }
            // mov [mem], imm - synthesize via rax scratch.
            (AsmOperand::Mem(mem), AsmOperand::Imm(n)) => {
                self.enc.mov_r64_imm64(Reg64::Rax, *n as u64);
                self.emit_store_mem(mem, Reg64::Rax)
            }
            (AsmOperand::Imm(_), _) => {
                Err("asm: `mov <imm>, ...` - destination can't be an immediate".into())
            }
            _ => Err("asm: unsupported `mov` operand combination".into()),
        }
    }

    /// lea reg, src - load effective address. src must produce
    /// an address: a [mem] operand, a %global (rip-relative
    /// data label), or a %fn (rip-relative code label).
    fn gen_asm_lea(&mut self, dst: &AsmOperand, src: &AsmOperand) -> Result<(), String> {
        let d = match dst {
            AsmOperand::Reg(r) => *r,
            _ => return Err("asm: `lea` destination must be a register".into()),
        };
        match src {
            AsmOperand::Mem(mem) => self.emit_lea_mem(d, mem),
            AsmOperand::Sym(name) => {
                if self.fn_ret_types.contains_key(name) && !self.extern_fns.contains(name) {
                    self.enc.lea_r64_code(d, name);
                    Ok(())
                } else if let Some(label) = self.global_label(name) {
                    self.enc.lea_r64_data(d, &label);
                    Ok(())
                } else if let Some(&off) = self.locals.get(name) {
                    self.enc.lea_r64_r64disp(d, Reg64::Rbp, off);
                    Ok(())
                } else {
                    Err(format!(
                        "asm: `lea {d:?}, %{name}` - `{name}` is not a local, global, or function"
                    ))
                }
            }
            _ => Err("asm: `lea` source must be a memory operand, %local, %global, or %fn".into()),
        }
    }

    /// Lower add/sub/xor/and/or/cmp/test dst, src. Routes by
    /// operand shape - we mostly need (reg,reg), (reg,imm), and
    /// the convenience (reg,%local) load-then-op shape.
    fn gen_asm_alu2(
        &mut self, mnem: &str, dst: &AsmOperand, src: &AsmOperand,
    ) -> Result<(), String> {
        let d = match dst {
            AsmOperand::Reg(r) => *r,
            _ => return Err(format!("asm: `{mnem}` destination must be a register")),
        };
        // Materialise src into a register (rcx if dst != rcx, else rdx).
        let s_reg = match src {
            AsmOperand::Reg(r) => *r,
            AsmOperand::Imm(n) => {
                let imm_i32 = i32::try_from(*n).map_err(|_| {
                    format!("asm: `{mnem}` immediate {n} out of i32 range")
                })?;
                match mnem {
                    "add"  => { self.enc.add_r64_imm32(d, imm_i32); return Ok(()); }
                    "sub"  => { self.enc.sub_r64_imm32(d, imm_i32); return Ok(()); }
                    "xor"  => { self.enc.xor_r64_imm32(d, imm_i32); return Ok(()); }
                    "and"  => { self.enc.and_r64_imm32(d, imm_i32); return Ok(()); }
                    "or"   => { self.enc.or_r64_imm32(d,  imm_i32); return Ok(()); }
                    "cmp"  => { self.enc.cmp_r64_imm32(d, imm_i32); return Ok(()); }
                    "test" => {
                        // No test reg, imm in our encoder yet -
                        // route through rcx scratch.
                        let scratch = if d == Reg64::Rcx { Reg64::Rdx } else { Reg64::Rcx };
                        self.enc.mov_r64_imm64(scratch, *n as u64);
                        self.enc.test_r64_r64(d, scratch);
                        return Ok(());
                    }
                    _ => unreachable!(),
                }
            }
            AsmOperand::Sym(name) => {
                let scratch = if d == Reg64::Rcx { Reg64::Rdx } else { Reg64::Rcx };
                self.emit_load_sym_into(scratch, name)?;
                scratch
            }
            AsmOperand::Mem(mem) => {
                let scratch = if d == Reg64::Rcx { Reg64::Rdx } else { Reg64::Rcx };
                self.emit_load_mem(scratch, mem)?;
                scratch
            }
        };
        match mnem {
            "add"  => self.enc.add_r64_r64(d, s_reg),
            "sub"  => self.enc.sub_r64_r64(d, s_reg),
            "xor"  => self.enc.xor_r64_r64(d, s_reg),
            "and"  => self.enc.and_r64_r64(d, s_reg),
            "or"   => self.enc.or_r64_r64(d, s_reg),
            "cmp"  => self.enc.cmp_r64_r64(d, s_reg),
            "test" => self.enc.test_r64_r64(d, s_reg),
            _ => unreachable!(),
        }
        Ok(())
    }


    /// Look up name and emit mov dst, <value of name>.
    fn emit_load_sym_into(&mut self, dst: Reg64, name: &str) -> Result<(), String> {
        if let Some(&off) = self.locals.get(name) {
            self.enc.mov_r64_rbp_disp(dst, off);
            return Ok(());
        }
        if let Some(label) = self.global_label(name) {
            self.enc.mov_r64_data(dst, &label);
            return Ok(());
        }
        if self.fn_ret_types.contains_key(name) && !self.extern_fns.contains(name) {
            // mov reg, %fn - accepted as a synonym for lea reg, %fn
            // since loading a function's "value" only makes sense as
            // its address.
            self.enc.lea_r64_code(dst, name);
            return Ok(());
        }
        Err(format!("asm: `%{name}` - not a local, global, or function in scope"))
    }

    /// Store src into the location named by name. Locals get a
    /// frame-slot store; globals get a rip-relative store; function
    /// names are an error (you can't assign to code).
    fn emit_store_sym_from(&mut self, name: &str, src: Reg64) -> Result<(), String> {
        if let Some(&off) = self.locals.get(name) {
            self.enc.mov_rbp_disp_r64(off, src);
            return Ok(());
        }
        if let Some(label) = self.global_label(name) {
            self.enc.mov_data_r64(&label, src);
            return Ok(());
        }
        if self.fn_ret_types.contains_key(name) {
            return Err(format!("asm: cannot assign to function `{name}`"));
        }
        Err(format!("asm: `%{name}` - not a local or global in scope"))
    }

    /// mov dst, [mem] - qword load. Narrower widths via db for now.
    fn emit_load_mem(&mut self, dst: Reg64, mem: &AsmMem) -> Result<(), String> {
        let seg = mem.seg;
        let resolved = self.mem_addressing(mem)?;
        // RIP-relative loads ignore segment overrides.
        if seg.is_some() && matches!(resolved, ResolvedMem::RipData(_)) {
            return Err(
                "asm: segment override on a `%global` address is meaningless \
                 (RIP-relative loads ignore segments). Drop the `gs:` / `fs:` prefix.".into()
            );
        }
        match resolved {
            ResolvedMem::RbpDisp(disp) => {
                if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                self.enc.mov_r64_rbp_disp(dst, disp);
            }
            ResolvedMem::BaseDisp { base, disp } => {
                if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                self.enc.mov_r64_r64disp(dst, base, disp);
            }
            ResolvedMem::SegAbs { disp } => {
                let s = seg.expect("SegAbs implies seg override");
                self.enc.emit_seg_prefix(s);
                self.enc.mov_r64_disp32(dst, disp);
            }
            ResolvedMem::BaseIdx { base, idx, scale, disp } => {
                // Encoder only has no-disp SIB; for disp != 0 we lea then load.
                if disp == 0 {
                    match scale {
                        8 => {
                            if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                            self.enc.mov_r64_base_idx(dst, base, idx);
                        }
                        _ => return Err(format!(
                            "asm: indexed load with scale {scale} not yet supported (use 8 for qword)"
                        )),
                    }
                } else {
                    if seg.is_some() {
                        return Err(
                            "asm: indexed memory with a non-zero displacement plus a \
                             segment override is not supported - load the address into \
                             a register first.".into()
                        );
                    }
                    self.enc.lea_r64_base_idx_scale(dst, base, idx, scale);
                    if disp != 0 { self.enc.add_r64_imm32(dst, disp); }
                    self.enc.mov_r64_r64disp(dst, dst, 0);
                }
            }
            ResolvedMem::RipData(label) => {
                self.enc.mov_r64_data(dst, &label);
            }
        }
        Ok(())
    }

    /// mov [mem], src - qword store. Mirror of emit_load_mem.
    fn emit_store_mem(&mut self, mem: &AsmMem, src: Reg64) -> Result<(), String> {
        let seg = mem.seg;
        let resolved = self.mem_addressing(mem)?;
        if seg.is_some() && matches!(resolved, ResolvedMem::RipData(_)) {
            return Err(
                "asm: segment override on a `%global` address is meaningless \
                 (RIP-relative stores ignore segments). Drop the `gs:` / `fs:` prefix.".into()
            );
        }
        match resolved {
            ResolvedMem::RbpDisp(disp) => {
                if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                self.enc.mov_rbp_disp_r64(disp, src);
            }
            ResolvedMem::BaseDisp { base, disp } => {
                if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                self.enc.mov_r64disp_r64(base, disp, src);
            }
            ResolvedMem::SegAbs { disp } => {
                let s = seg.expect("SegAbs implies seg override");
                self.enc.emit_seg_prefix(s);
                self.enc.mov_disp32_r64(disp, src);
            }
            ResolvedMem::BaseIdx { base, idx, scale, disp } => {
                if disp == 0 && scale == 8 {
                    if let Some(s) = seg { self.enc.emit_seg_prefix(s); }
                    self.enc.mov_qword_base_idx_r64(base, idx, src);
                } else {
                    return Err(format!(
                        "asm: indexed store with scale {scale}/disp {disp} \
                         not yet supported (use [reg+reg*8] without disp)"
                    ));
                }
            }
            ResolvedMem::RipData(label) => {
                self.enc.mov_data_r64(&label, src);
            }
        }
        Ok(())
    }

    /// lea dst, [mem] - effective-address computation.
    /// Segment overrides are nonsense on lea and rejected.
    fn emit_lea_mem(&mut self, dst: Reg64, mem: &AsmMem) -> Result<(), String> {
        if mem.seg.is_some() {
            return Err(
                "asm: `lea` does not accept a segment-override prefix - effective \
                 addresses are computed without consulting any segment.".into()
            );
        }
        match self.mem_addressing(mem)? {
            ResolvedMem::RbpDisp(disp) => {
                self.enc.lea_r64_r64disp(dst, Reg64::Rbp, disp);
            }
            ResolvedMem::BaseDisp { base, disp } => {
                self.enc.lea_r64_r64disp(dst, base, disp);
            }
            ResolvedMem::BaseIdx { base, idx, scale, disp } => {
                self.enc.lea_r64_base_idx_scale(dst, base, idx, scale);
                if disp != 0 { self.enc.add_r64_imm32(dst, disp); }
            }
            ResolvedMem::RipData(label) => {
                self.enc.lea_r64_data(dst, &label);
            }
            ResolvedMem::SegAbs { .. } => {
                // Unreachable past the seg guard above; defensive only.
                return Err(
                    "asm: `lea` does not accept disp-only memory operands".into()
                );
            }
        }
        Ok(())
    }

    /// Translate a parsed AsmMem into one of the addressing
    /// shapes the encoder knows how to emit. Resolves %name
    /// bases to the right concrete form.
    fn mem_addressing(&self, mem: &AsmMem) -> Result<ResolvedMem, String> {
        match (&mem.base, &mem.index) {
            // [reg] / [reg + disp]
            (Some(AsmMemBase::Reg(base)), None) => {
                if *base == Reg64::Rbp {
                    Ok(ResolvedMem::RbpDisp(mem.disp))
                } else {
                    Ok(ResolvedMem::BaseDisp { base: *base, disp: mem.disp })
                }
            }
            // [reg + idx*scale + disp]
            (Some(AsmMemBase::Reg(base)), Some((idx, scale))) => {
                Ok(ResolvedMem::BaseIdx { base: *base, idx: *idx, scale: *scale, disp: mem.disp })
            }
            // [%name + disp] - must be a local or global, NOT a function.
            (Some(AsmMemBase::Sym(name)), None) => {
                if let Some(&off) = self.locals.get(name) {
                    Ok(ResolvedMem::RbpDisp(off.wrapping_add(mem.disp)))
                } else if let Some(label) = self.global_label(name) {
                    if mem.disp != 0 {
                        return Err(format!(
                            "asm: `[%{name} + {}]` - non-zero disp on a global isn't supported yet",
                            mem.disp
                        ));
                    }
                    Ok(ResolvedMem::RipData(label))
                } else {
                    Err(format!("asm: `[%{name}]` - `{name}` is not a local or global"))
                }
            }
            (Some(AsmMemBase::Sym(_)), Some(_)) => {
                Err("asm: `[%name + reg*scale]` - combining %sym with an index isn't supported. \
                     `lea` the address into a register first.".into())
            }
            (None, Some(_)) => {
                Err("asm: `[idx*scale]` without a base register isn't supported".into())
            }
            (None, None) => {
                // Disp-only is only meaningful with a seg override.
                if mem.seg.is_none() {
                    return Err("asm: empty `[]` memory operand".into());
                }
                Ok(ResolvedMem::SegAbs { disp: mem.disp })
            }
        }
    }

    /// Find the data-section label for a top-level static, by name.
    /// Returns None if no static named name exists.
    fn global_label(&self, name: &str) -> Option<String> {
        let idx = *self.globals_idx.get(name)?;
        Some(self.globals[idx].label.clone())
    }

    fn lookup_hook(&self, target: &str) -> Option<String> {
        let hook_fn = self.hooks.map.get(target)?;
        if self.current_fn_hook.no_hook_all { return None; }
        if self.current_fn_hook.no_hook.contains(target) { return None; }
        if self.current_fn_hook.is_hook_for.as_deref() == Some(target) {
            return None;
        }
        Some(hook_fn.clone())
    }

    fn gen_call(&mut self, ns: &str, fname: &str, args: &[Expr]) -> Result<(), String> {
        if ns == "mem" {
            return self.gen_mem_call(fname, args);
        }
        if ns == "gc" {
            return Err(format!(
                "intrinsic `gc.{fname}` was renamed - use `mem.{fname}` \
                 (gc.alloc  to  mem.alloc). The memory primitives now live \
                 under `mem.*` (alloc, set, copy, zero, cmp)."
            ));
        }
        if ns == "shared" {
            return self.gen_shared_call(fname, args);
        }
        if ns == "str" {
            return self.gen_str_call(fname, args);
        }

        let struct_ret_ty = if ns.is_empty() {
            self.fn_ret_types.get(fname)
                .filter(|t| self.struct_layouts.contains_key(t.as_str()))
                .cloned()
        } else {
            None
        };
        let mut hidden_buf: Option<(String, i32)> = None;
        let synth_args;
        let args_for_lowering: &[Expr] = if let Some(ref ret_ty) = struct_ret_ty {
            let size = self.struct_layouts[ret_ty].size;
            let name = format!("__call_ret_{}", self.label_counter);
            self.label_counter += 1;
            let off = self.alloc_local_sized(&name, size);
            hidden_buf = Some((name.clone(), off));
            // The hidden first arg is the address of the just-allocated
            // slot. Express it as a &__call_ret_N AST node so it flows
            // through the standard gen_call_args path unchanged.
            let mut v: Vec<Expr> = Vec::with_capacity(args.len() + 1);
            v.push(Expr::Unary {
                op: "&".into(),
                operand: Box::new(Expr::Var(name)),
            });
            // Mark the synthetic local in scope so &name resolves.
            self.local_types.insert(
                hidden_buf.as_ref().unwrap().0.clone(),
                ret_ty.clone(),
            );
            v.extend_from_slice(args);
            synth_args = v;
            &synth_args
        } else {
            args
        };

        // Generic call lowering. Returns the number of bytes pre-allocated
        // on the stack that need to be freed after the call returns.
        let cleanup = self.gen_call_args(args_for_lowering)?;

        // Emit the call instruction itself. Path is identical for ≤4-arg
        // and >4-arg flavours; only arg lowering differs.
        if ns.is_empty() {
            if let Some(&off) = self.locals.get(fname) {
                self.enc.mov_r64_rbp_disp(Reg64::Rax, off);
                self.enc.call_r64(Reg64::Rax);
            } else if let Some(&idx) = self.globals_idx.get(fname) {
                let label = self.globals[idx].label.clone();
                self.enc.mov_r64_data(Reg64::Rax, &label);
                self.enc.call_r64(Reg64::Rax);
            } else if self.extern_fns.contains(fname) {
                match self.kind {
                    BuildKind::Standard => {
                        return Err(format!(
                            "`{fname}` is declared `extern` (typically a Beacon \
                             API symbol). It can only be called when compiled \
                             with `--type=bof` (or `--type=coff`). For standard \
                             shellcode, use the Win32 namespace syntax (e.g. \
                             `Kernel32.SomeFunction(...)`)."
                        ));
                    }
                    BuildKind::Bof | BuildKind::Coff => {
                        if let Some(hook_fn) = self.lookup_hook(fname) {
                            self.enc.call_label(&hook_fn);
                        } else {
                            let imp = format!("__imp_{fname}");
                            self.enc.call_extern(&imp);
                        }
                    }
                }
            } else {
                self.enc.call_label(fname);
            }
        } else if INTRINSIC_NAMESPACES.contains(&ns) {
            // Reached here only if an intrinsic namespace exposed an unknown
            // function name. Surface a precise error so users don't think
            // they're calling into a DLL named e.g. "mem".
            return Err(format!("unknown intrinsic: {ns}.{fname}"));
        } else if self.kind.is_object() {
            let lib_upper = ns.trim_end_matches(".dll").to_ascii_uppercase();
            let target_sym = format!("{lib_upper}${fname}");
            // Hook redirect - same machinery as for externs, but
            // keyed on the LIB$Func form (matches what the user
            // writes in [Hook]).
            if let Some(hook_fn) = self.lookup_hook(&target_sym) {
                self.enc.call_label(&hook_fn);
            } else if self.opsec.hashed_imports && !is_beacon_api(fname) {
                let dll = normalize_dll_name(ns);
                let slot = resolver::slot_label(&dll, fname);
                if !self.imports.iter().any(|i| i.slot == slot) {
                    self.imports.push(Import {
                        dll: dll.clone(),
                        func: fname.to_string(),
                        slot: slot.clone(),
                    });
                    self.enc.add_bss(&slot, 8);
                }
                self.enc.call_indirect_data(&slot);
            } else {
                let sym = format!("__imp_{target_sym}");
                self.enc.call_extern(&sym);
            }
        } else {
            let dll = normalize_dll_name(ns);
            let slot = resolver::slot_label(&dll, fname);
            if !self.imports.iter().any(|i| i.slot == slot) {
                self.imports.push(Import {
                    dll: dll.clone(),
                    func: fname.to_string(),
                    slot: slot.clone(),
                });
                self.enc.add_bss(&slot, 8);
            }
            if dll == "ntdll.dll" {
                if let Some(stub) = self.overrides.ntcall.clone() {
                    self.enc.mov_r64_data(Reg64::Rax, &slot);
                    self.enc.call_label(&stub);
                } else {
                    self.enc.call_indirect_data(&slot);
                }
            } else {
                self.enc.call_indirect_data(&slot);
            }
        }

        // Stack cleanup for the large-arg path.
        if cleanup > 0 {
            self.enc.add_r64_imm32(Reg64::Rsp, cleanup);
        }

        if let Some((_name, off)) = hidden_buf {
            self.enc.lea_r64_r64disp(Reg64::Rax, Reg64::Rbp, off);
        }
        Ok(())
    }

    fn gen_call_args(&mut self, args: &[Expr]) -> Result<i32, String> {
        let arg_regs = [Reg64::Rcx, Reg64::Rdx, Reg64::R8, Reg64::R9];
        let n = args.len();
        let stack_args = n.saturating_sub(4);
        let reg_args = n.min(4);
        let raw = 32 + stack_args * 8 + reg_args * 8;
        let total = ((raw + 15) / 16) * 16;

        self.enc.sub_r64_imm32(Reg64::Rsp, total as i32);
        let temp_base = 32 + (stack_args as i32) * 8;

        for (i, a) in args.iter().enumerate() {
            self.gen_expr(a)?;
            let offset = if i < 4 {
                temp_base + (i as i32) * 8
            } else {
                32 + ((i - 4) as i32) * 8
            };
            self.enc.mov_r64disp_r64(Reg64::Rsp, offset, Reg64::Rax);
        }

        // Load the in-register args from their temp slots.
        for (i, reg) in arg_regs.iter().take(reg_args).enumerate() {
            let offset = temp_base + (i as i32) * 8;
            self.enc.mov_r64_r64disp(*reg, Reg64::Rsp, offset);
        }
        Ok(total as i32)
    }

    fn type_size(&self, ty: &str) -> usize {
        if is_pointer_type(ty) { return 8; }
        if let Some((elem, n)) = parse_array_type(ty) {
            return self.type_size(elem) * n;
        }
        match ty {
            "bool" | "int" | "str" | "wstr"    => 8,
            "i8"  | "u8"                       => 1,
            "i16" | "u16"                      => 2,
            "i32" | "u32"                      => 4,
            "i64" | "u64"                      => 8,
            "void"                             => 1,
            _ => self.struct_layouts.get(ty).map(|l| l.size).unwrap_or(8),
        }
    }

    fn type_align(&self, ty: &str) -> usize {
        if let Some(l) = self.struct_layouts.get(ty) { return l.align; }
        if let Some((elem, _)) = parse_array_type(ty) {
            return self.type_align(elem);
        }
        let s = self.type_size(ty);
        if s > 8 { 8 } else { s }
    }

    fn is_array_type(ty: &str) -> bool {
        parse_array_type(ty).is_some()
    }

    /// Element type of an array (T[N]  to  T) or pointee of a pointer
    /// (T*  to  T). Returns None if ty is neither - that's an
    /// indexing error at the use site.
    fn element_type(ty: &str) -> Option<String> {
        if let Some((elem, _)) = parse_array_type(ty) {
            return Some(elem.to_string());
        }
        pointee(ty).map(String::from)
    }

    fn size_of_type(&self, ty: &str) -> usize {
        if let Some(layout) = self.struct_layouts.get(ty) { return layout.size; }
        if Self::is_array_type(ty) { return self.type_size(ty); }
        8
    }

    fn emit_static_initializers(&mut self) -> Result<(), String> {
        for i in 0..self.globals.len() {
            let init = self.globals[i].init.clone();
            let label = self.globals[i].label.clone();
            let ty = self.globals[i].ty.clone();
            if let Some(expr) = init {
                if self.struct_layouts.contains_key(&ty) || Self::is_array_type(&ty) {
                    let kind = if Self::is_array_type(&ty) { "array" } else { "struct" };
                    return Err(format!(
                        "static of {kind} type `{ty}` cannot have an initialiser in V1 \
                         (assign each element/field at main entry instead)"
                    ));
                }
                self.gen_expr(&expr)?;
                self.enc.mov_data_r64(&label, Reg64::Rax);
            }
        }
        Ok(())
    }

    fn resolve_field(&self, base: &Expr, field: &str) -> Result<(i32, String, usize), String> {
        let ty = self.struct_type_of(base)?;
        let key = ty.trim_end_matches('*');
        let layout = self.struct_layouts.get(key)
            .ok_or_else(|| format!("type `{ty}` is not a struct"))?;
        let f = layout.fields.get(field)
            .ok_or_else(|| format!("struct `{ty}` has no field `{field}`"))?;
        Ok((f.offset, f.ty.clone(), f.size))
    }

    fn struct_type_of(&self, base: &Expr) -> Result<String, String> {
        match base {
            Expr::Var(name) => {
                if let Some(t) = self.local_types.get(name) { return Ok(t.clone()); }
                let idx = self.globals_idx.get(name)
                    .ok_or_else(|| format!("undefined variable: {name}"))?;
                Ok(self.globals[*idx].ty.clone())
            }
            Expr::Field { base: inner_base, field } => {
                let (_, inner_ty, _) = self.resolve_field(inner_base, field)?;
                Ok(inner_ty)
            }
            Expr::Cast { ty, .. } => Ok(ty.clone()),
            Expr::Unary { op, operand } if op == "*" => {
                // *p's type is the pointee of p's type.
                let t = self.expr_type(operand);
                Ok(pointee(&t).map(String::from).unwrap_or(t))
            }
            _ => Err(
                "field access requires a struct global, struct local, struct cast, \
                 deref of a struct pointer, or a nested field thereof".into()
            ),
        }
    }

    fn expr_type(&self, e: &Expr) -> String {
        match e {
            Expr::Int(_)  => "int".into(),
            Expr::Bool(_) => "bool".into(),
            Expr::Str(_)  => "str".into(),
            Expr::Var(name) => {
                if let Some(t) = self.local_types.get(name) { return t.clone(); }
                if let Some(&idx) = self.globals_idx.get(name) {
                    return self.globals[idx].ty.clone();
                }
                "int".into()
            }
            Expr::Cast { ty, .. } => ty.clone(),
            Expr::Field { base, field } => self
                .resolve_field(base, field)
                .map(|(_, t, _)| t)
                .unwrap_or_else(|_| "int".into()),
            Expr::Unary { op, operand } if op == "*" => {
                let t = self.expr_type(operand);
                pointee(&t).map(String::from).unwrap_or(t)
            }
            Expr::Unary { op, operand } if op == "&" => {
                format!("{}*", self.expr_type(operand))
            }
            Expr::Index { base, .. } => {
                // base[i] has the element type of base (T*  to  T, T[N]  to  T).
                // Falls back to int if we can't infer, mirroring deref.
                let t = self.expr_type(base);
                Self::element_type(&t).unwrap_or_else(|| "int".into())
            }
            Expr::SizeOf { .. } => "u64".into(),
            Expr::StructLit { ty, .. } => ty.clone(),
            _ => "int".into(),
        }
    }

    fn emit_load_width(&mut self, pointee_ty: &str, base: Reg64) {
        match self.type_size(pointee_ty) {
            1 => self.enc.movzx_r64_byte_r64disp(Reg64::Rax, base, 0),
            2 => self.enc.movzx_r64_word_r64disp(Reg64::Rax, base, 0),
            4 => self.enc.mov_r32_r64disp(Reg64::Rax, base, 0),
            _ => self.enc.mov_r64_r64disp(Reg64::Rax, base, 0),
        }
    }

    /// Mirror of [emit_load_width] for stores. Writes the low N bytes of
    /// rax to [base + 0], where N comes from type_size.
    fn emit_store_width(&mut self, pointee_ty: &str, base: Reg64) {
        match self.type_size(pointee_ty) {
            1 => self.enc.mov_byte_r64disp_r8(base, 0, Reg64::Rax),
            2 => self.enc.mov_word_r64disp_r16(base, 0, Reg64::Rax),
            4 => self.enc.mov_dword_r64disp_r32(base, 0, Reg64::Rax),
            _ => self.enc.mov_r64disp_r64(base, 0, Reg64::Rax),
        }
    }

    fn gen_addr(&mut self, base: &Expr) -> Result<(), String> {
        match base {
            Expr::Var(name) => {
                if let Some(&off) = self.locals.get(name) {
                    let ty = self.local_types.get(name).cloned().unwrap_or_default();
                    if self.struct_layouts.contains_key(&ty) {
                        self.enc.lea_r64_r64disp(Reg64::Rax, Reg64::Rbp, off);
                        return Ok(());
                    }
                    if is_pointer_type(&ty) {
                        self.enc.mov_r64_rbp_disp(Reg64::Rax, off);
                        return Ok(());
                    }
                    return Err(format!(
                        "cannot use non-pointer scalar local `{name}` (type `{ty}`) \
                         as a struct base"
                    ));
                }
                if let Some(&idx) = self.globals_idx.get(name) {
                    let g = &self.globals[idx];
                    if self.struct_layouts.contains_key(&g.ty) {
                        self.enc.lea_r64_data(Reg64::Rax, &g.label);
                        return Ok(());
                    }
                    if is_pointer_type(&g.ty) {
                        self.enc.mov_r64_data(Reg64::Rax, &g.label);
                        return Ok(());
                    }
                    return Err(format!(
                        "cannot use non-pointer scalar global `{name}` (type `{}`) \
                         as a struct base",
                        g.ty
                    ));
                }
                Err(format!("undefined variable: {name}"))
            }
            Expr::Field { base: inner_base, field } => {
                let (off, _, _) = self.resolve_field(inner_base, field)?;
                self.gen_addr(inner_base)?;
                if off != 0 {
                    self.enc.add_r64_imm32(Reg64::Rax, off);
                }
                Ok(())
            }
            Expr::Cast { ty, expr } if self.struct_layouts.contains_key(ty.trim_end_matches('*')) => {
                self.gen_expr(expr)
            }
            Expr::Unary { op, operand } if op == "*" => {
                // (*p).field - p's value is already the struct base.
                self.gen_expr(operand)
            }
            _ => Err(
                "address-of supported only on globals, struct/pointer locals, \
                 struct casts, deref'd pointers, or fields thereof".into()
            ),
        }
    }

    fn gen_addr_of(&mut self, operand: &Expr) -> Result<(), String> {
        match operand {
            Expr::Var(name) => {
                if let Some(&off) = self.locals.get(name) {
                    self.enc.lea_r64_r64disp(Reg64::Rax, Reg64::Rbp, off);
                    return Ok(());
                }
                if let Some(&idx) = self.globals_idx.get(name) {
                    let label = self.globals[idx].label.clone();
                    self.enc.lea_r64_data(Reg64::Rax, &label);
                    return Ok(());
                }
                Err(format!("cannot take address of `{name}` - no such variable"))
            }
            Expr::Field { base, field } => {
                let (off, _, _) = self.resolve_field(base, field)?;
                self.gen_addr(base)?;
                if off != 0 {
                    self.enc.add_r64_imm32(Reg64::Rax, off);
                }
                Ok(())
            }
            Expr::Unary { op, operand: inner } if op == "*" => {
                // &*p == p - the deref cancels the address-of.
                self.gen_expr(inner)
            }
            _ => Err("`&` requires a variable, field, or deref expression".into()),
        }
    }

    fn gen_str_call(&mut self, fname: &str, args: &[Expr]) -> Result<(), String> {
        match fname {
            "format" => self.gen_str_format(args),
            _ => Err(format!("unknown intrinsic: str.{fname}")),
        }
    }

    fn gen_str_format(&mut self, args: &[Expr]) -> Result<(), String> {
        let template = match args.first() {
            Some(Expr::Str(s)) => s.clone(),
            _ => return Err(
                "str.format: first argument must be a string literal template".into()
            ),
        };
        let user_args = &args[1..];

        let printf_fmt = self.translate_format_template(&template, user_args)?;

        let n = self.label_counter;
        self.label_counter += 1;
        let fmt_label = format!("__fmt_tpl_{n}");
        let buf_label = format!("__fmt_buf_{n}");
        self.enc.add_string(&fmt_label, &printf_fmt);
        self.enc.add_bss(&buf_label, FMT_BUF_SIZE);

        // wsprintfA's signature is (buf, fmt, ...). Use the standard
        // arg-lowering path with two placeholder leading args; overwrite
        // rcx/rdx with the real addresses after gen_call_args is done.
        let mut call_args: Vec<Expr> = vec![Expr::Int(0), Expr::Int(0)];
        call_args.extend_from_slice(user_args);
        let cleanup = self.gen_call_args(&call_args)?;
        self.enc.lea_r64_data(Reg64::Rcx, &buf_label);
        self.enc.lea_r64_data(Reg64::Rdx, &fmt_label);

        if self.kind.is_object() {
            if self.opsec.hashed_imports {
                // Same routing as the BOF-mode Win32 call path:
                // drop the __imp_USER32$wsprintfA external and
                // resolve via the standard PEB-walking resolver.
                let dll = "user32.dll".to_string();
                let func = "wsprintfA".to_string();
                let slot = resolver::slot_label(&dll, &func);
                if !self.imports.iter().any(|i| i.slot == slot) {
                    self.imports.push(Import {
                        dll: dll.clone(),
                        func: func.clone(),
                        slot: slot.clone(),
                    });
                    self.enc.add_bss(&slot, 8);
                }
                self.enc.call_indirect_data(&slot);
            } else {
                self.enc.call_extern("__imp_USER32$wsprintfA");
            }
        } else {
            let dll = "user32.dll".to_string();
            let func = "wsprintfA".to_string();
            let slot = resolver::slot_label(&dll, &func);
            if !self.imports.iter().any(|i| i.slot == slot) {
                self.imports.push(Import {
                    dll: dll.clone(),
                    func: func.clone(),
                    slot: slot.clone(),
                });
                self.enc.add_bss(&slot, 8);
            }
            self.enc.call_indirect_data(&slot);
        }
        if cleanup > 0 {
            self.enc.add_r64_imm32(Reg64::Rsp, cleanup);
        }

        // wsprintfA returns the number of chars written in rax; the
        // caller doesn't want that - they want the buffer pointer.
        self.enc.lea_r64_data(Reg64::Rax, &buf_label);
        Ok(())
    }

    fn translate_format_template(
        &self,
        template: &str,
        user_args: &[Expr],
    ) -> Result<String, String> {
        let mut out = String::new();
        let mut iter = template.chars().peekable();
        let mut arg_idx = 0usize;
        while let Some(c) = iter.next() {
            match c {
                '{' if iter.peek() == Some(&'{') => { iter.next(); out.push('{'); }
                '}' if iter.peek() == Some(&'}') => { iter.next(); out.push('}'); }
                '{' => {
                    let mut spec = String::new();
                    let mut closed = false;
                    while let Some(&c) = iter.peek() {
                        if c == '}' { iter.next(); closed = true; break; }
                        spec.push(c);
                        iter.next();
                    }
                    if !closed {
                        return Err(
                            "str.format: unterminated `{` in template (use `{{` for a literal brace)".into()
                        );
                    }
                    if arg_idx >= user_args.len() {
                        return Err(format!(
                            "str.format: template references argument {} but only {} were given",
                            arg_idx, user_args.len()
                        ));
                    }
                    let ty = self.expr_type(&user_args[arg_idx]);
                    out.push_str(&printf_spec_for(&spec, &ty)?);
                    arg_idx += 1;
                }
                '}' => return Err(
                    "str.format: stray `}` in template - use `}}` to escape a literal `}`".into()
                ),
                // wsprintfA treats % as the start of a format specifier;
                // double any literal % so it renders verbatim.
                '%' => out.push_str("%%"),
                c => out.push(c),
            }
        }
        if arg_idx != user_args.len() {
            return Err(format!(
                "str.format: template has {arg_idx} placeholders but {} arguments were provided",
                user_args.len()
            ));
        }
        Ok(out)
    }

    fn gen_mem_call(&mut self, fname: &str, args: &[Expr]) -> Result<(), String> {
        if fname == "alloc" {
            if args.len() != 1 { return Err("mem.alloc takes exactly 1 arg".into()); }
            self.gen_expr(&args[0])?;
            if self.kind.is_object() {
                self.gen_bof_heap_alloc()?;
            } else if matches!(self.gc_mode, GcMode::Manual) {
                self.gen_standard_heap_alloc()?;
            } else {
                self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);
                macros::emit_gc_alloc_call(&mut self.enc);
            }
            return Ok(());
        }
        if fname == "free" {
            if args.len() != 1 { return Err("mem.free takes exactly 1 arg".into()); }
            let manual_world = self.kind.is_object()
                || matches!(self.gc_mode, GcMode::Manual);
            if !manual_world {
                return Err(format!(
                    "mem.free is only valid in BOF mode or with `--gc=manual` \
                     (current --gc=auto/on uses the embedded GC which doesn't \
                     need explicit frees). Either drop the call or rebuild \
                     with `--gc=manual`."
                ));
            }
            self.gen_expr(&args[0])?;
            self.gen_heap_free()?;
            return Ok(());
        }
        // mem.collect - explicit GC trigger. Useful for tests and for
        // operators that want a deterministic pause point (e.g. before
        // sleep mask). Returns 0; pulls in the GC runtime same as alloc.
        if fname == "collect" {
            if !args.is_empty() { return Err("mem.collect takes no args".into()); }
            if self.kind.is_object() {
                self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
            } else {
                self.enc.call_label("__gc_collect");
                self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
            }
            return Ok(());
        }

        let expected: usize = match fname {
            "zero" => 2,
            "set" | "copy" | "cmp" => 3,
            _ => return Err(format!("unknown intrinsic: mem.{fname}")),
        };
        if args.len() != expected {
            return Err(format!("mem.{fname} takes exactly {expected} args"));
        }
        for a in args {
            self.gen_expr(a)?;
            self.enc.push_r64(Reg64::Rax);
            self.enc.sub_r64_imm32(Reg64::Rsp, 8);
        }
        let arg_regs = [Reg64::Rcx, Reg64::Rdx, Reg64::R8, Reg64::R9];
        for i in (0..args.len()).rev() {
            self.enc.add_r64_imm32(Reg64::Rsp, 8);
            self.enc.pop_r64(arg_regs[i]);
        }

        match fname {
            "set" => {
                // mem.set -> dst
                self.enc.push_r64(Reg64::Rdi);              // save non-volatile
                self.enc.mov_r64_r64(Reg64::R9,  Reg64::Rcx); // preserve dst for return
                self.enc.mov_r64_r64(Reg64::Rdi, Reg64::Rcx);
                self.enc.mov_r64_r64(Reg64::Rax, Reg64::Rdx); // al = byte
                self.enc.mov_r64_r64(Reg64::Rcx, Reg64::R8);  // rcx = n
                self.enc.cld();
                self.enc.rep_stosb();
                self.enc.pop_r64(Reg64::Rdi);
                self.enc.mov_r64_r64(Reg64::Rax, Reg64::R9);
            }
            "zero" => {
                // mem.zero -> dst
                self.enc.push_r64(Reg64::Rdi);
                self.enc.mov_r64_r64(Reg64::R9,  Reg64::Rcx);
                self.enc.mov_r64_r64(Reg64::Rdi, Reg64::Rcx);
                self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rdx);
                self.enc.xor_r64_r64(Reg64::Rax, Reg64::Rax);
                self.enc.cld();
                self.enc.rep_stosb();
                self.enc.pop_r64(Reg64::Rdi);
                self.enc.mov_r64_r64(Reg64::Rax, Reg64::R9);
            }
            "copy" => {
                // mem.copy -> dst
                self.enc.push_r64(Reg64::Rdi);
                self.enc.push_r64(Reg64::Rsi);
                self.enc.mov_r64_r64(Reg64::R9,  Reg64::Rcx); // preserve dst for return
                self.enc.mov_r64_r64(Reg64::Rdi, Reg64::Rcx);
                self.enc.mov_r64_r64(Reg64::Rsi, Reg64::Rdx);
                self.enc.mov_r64_r64(Reg64::Rcx, Reg64::R8);
                self.enc.cld();
                self.enc.rep_movsb();
                self.enc.pop_r64(Reg64::Rsi);
                self.enc.pop_r64(Reg64::Rdi);
                self.enc.mov_r64_r64(Reg64::Rax, Reg64::R9);
            }
            "cmp" => {
                // mem.cmp -> 0 if equal else 1
                self.enc.push_r64(Reg64::Rdi);
                self.enc.push_r64(Reg64::Rsi);
                self.enc.mov_r64_r64(Reg64::Rsi, Reg64::Rcx);
                self.enc.mov_r64_r64(Reg64::Rdi, Reg64::Rdx);
                self.enc.mov_r64_r64(Reg64::Rcx, Reg64::R8);
                self.enc.test_r64_r64(Reg64::Rcx, Reg64::Rcx);
                self.enc.cld();
                self.enc.repe_cmpsb();
                // CRITICAL: do NOT clobber ZF before reading it with setnz.
                // pop_r64 leaves flags alone, but xor / mov_r64_imm do not.
                // Read ZF first into al, THEN zero-extend.
                self.enc.pop_r64(Reg64::Rsi);
                self.enc.pop_r64(Reg64::Rdi);
                // setnz al = 0F 95 C0 - al = 0 if equal (ZF=1), 1 if mismatch
                self.enc.emit_raw(0x0F);
                self.enc.emit_raw(0x95);
                self.enc.emit_raw(0xC0);
                // movzx eax, al = 0F B6 C0 - implicit zero-extension to rax.
                // The 32-bit form is 3 bytes (no REX) vs the 4-byte 64-bit
                // form 48 0F B6 C0; identical result.
                self.enc.emit_raw(0x0F);
                self.enc.emit_raw(0xB6);
                self.enc.emit_raw(0xC0);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn gen_bof_heap_alloc(&mut self) -> Result<(), String> {
        // Build via the unified Win32 import helper so this path
        // works under both BOF mode (external __imp_*) and
        // standard mode with --gc=manual (resolver-filled slot).
        let get_heap = self.ensure_win32_import("kernel32.dll", "GetProcessHeap");
        let heap_alloc = self.ensure_win32_import("kernel32.dll", "HeapAlloc");

        self.enc.push_r64(Reg64::R12);
        self.enc.mov_r64_r64(Reg64::R12, Reg64::Rax);

        self.enc.sub_r64_imm32(Reg64::Rsp, 0x28);

        // rax = GetProcessHeap - zero-arg, returns HANDLE in rax.
        self.emit_win32_call(&get_heap);

        self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);
        self.enc.mov_r64_imm64(Reg64::Rdx, 0x8);
        self.enc.mov_r64_r64(Reg64::R8,  Reg64::R12);

        self.emit_win32_call(&heap_alloc);

        // Tear down. rsp += 0x28 reverses the shadow-space sub; pop r12
        // restores the caller's saved value AND realigns rsp.
        self.enc.add_r64_imm32(Reg64::Rsp, 0x28);
        self.enc.pop_r64(Reg64::R12);

        // rax = allocated pointer (or NULL on OOM). Match the GC's
        // behaviour: caller checks rax == 0 for failure.
        Ok(())
    }

    fn gen_standard_heap_alloc(&mut self) -> Result<(), String> {
        // The unified helper picks the right path. In standard mode
        // it always returns Slot since there's no Beacon
        // loader to fill __imp_* externals.
        self.gen_bof_heap_alloc()
    }

    fn gen_heap_free(&mut self) -> Result<(), String> {
        let get_heap = self.ensure_win32_import("kernel32.dll", "GetProcessHeap");
        let heap_free = self.ensure_win32_import("kernel32.dll", "HeapFree");

        // Save the pointer (rax) into r12 across GetProcessHeap.
        self.enc.push_r64(Reg64::R12);
        self.enc.mov_r64_r64(Reg64::R12, Reg64::Rax);

        // 16-aligned rsp at every sub-call site (push knocked rsp to
        // 8-mod-16; 0x28 brings it back to 0-mod-16).
        self.enc.sub_r64_imm32(Reg64::Rsp, 0x28);

        // rax = GetProcessHeap
        self.emit_win32_call(&get_heap);

        // HeapFree
        self.enc.mov_r64_r64(Reg64::Rcx, Reg64::Rax);
        self.enc.mov_r64_imm64(Reg64::Rdx, 0);
        self.enc.mov_r64_r64(Reg64::R8,  Reg64::R12);

        self.emit_win32_call(&heap_free);

        self.enc.add_r64_imm32(Reg64::Rsp, 0x28);
        self.enc.pop_r64(Reg64::R12);

        // HeapFree returns BOOL (0 = failed, non-zero = success). We
        // leave it in rax so callers that care can check.
        Ok(())
    }

    fn gen_shared_call(&mut self, fname: &str, args: &[Expr]) -> Result<(), String> {
        for a in args {
            self.gen_expr(a)?;
            self.enc.push_r64(Reg64::Rax);
            self.enc.sub_r64_imm32(Reg64::Rsp, 8);
        }
        let arg_regs = [Reg64::Rcx, Reg64::Rdx, Reg64::R8, Reg64::R9];
        for i in (0..args.len()).rev() {
            self.enc.add_r64_imm32(Reg64::Rsp, 8);
            self.enc.pop_r64(arg_regs[i]);
        }
        match fname {
            "get" => self.enc.call_label(shared::FN_GET),
            "put" => self.enc.call_label(shared::FN_PUT),
            _ => return Err(format!("unknown intrinsic: shared.{fname}")),
        }
        Ok(())
    }
}

fn literal_int_value(e: &Expr) -> Option<i64> {
    match e {
        Expr::Int(n) => Some(*n),
        Expr::Unary { op, operand } if op == "-" => {
            if let Expr::Int(n) = operand.as_ref() { Some(n.wrapping_neg()) }
            else { None }
        }
        _ => None,
    }
}

fn narrow_int_literal(ty: &str, n: i64) -> Option<i64> {
    match ty {
        "u8"  => Some((n as u8)  as i64),
        "u16" => Some((n as u16) as i64),
        "u32" => Some((n as u32) as i64),
        "i8"  => Some((n as i8)  as i64),
        "i16" => Some((n as i16) as i64),
        "i32" => Some((n as i32) as i64),
        // u64/i64/int are full-width; no narrowing needed. Skip the fold so
        // the regular gen_expr path runs.
        _ => None,
    }
}

fn normalize_dll_name(ns: &str) -> String {
    let lower = ns.to_ascii_lowercase();
    if lower.ends_with(".dll") { lower } else { format!("{lower}.dll") }
}

fn is_beacon_api(fname: &str) -> bool {
    fname.starts_with("Beacon")
}


fn program_uses<F: Fn(&Expr) -> bool>(prog: &Program, pred: F) -> bool {
    if prog.functions.iter().any(|f| block_any_expr(&f.body, &pred)) {
        return true;
    }
    prog.statics.iter().any(|s| {
        s.init.as_ref().map_or(false, |e| expr_any_subexpr(e, &pred))
    })
}

fn block_any_expr<F: Fn(&Expr) -> bool>(stmts: &[Stmt], pred: &F) -> bool {
    stmts.iter().any(|s| stmt_any_expr(s, pred))
}

fn stmt_any_expr<F: Fn(&Expr) -> bool>(s: &Stmt, pred: &F) -> bool {
    match s {
        Stmt::Var { value, .. }      => value.as_ref().map_or(false, |e| expr_any_subexpr(e, pred)),
        Stmt::Expr { value: e, .. }  => expr_any_subexpr(e, pred),
        Stmt::Ret { value: Some(e), .. } => expr_any_subexpr(e, pred),
        Stmt::Ret { value: None, .. }    => false,
        Stmt::If { cond, then_body, else_body } => {
            expr_any_subexpr(cond, pred)
                || block_any_expr(then_body, pred)
                || block_any_expr(else_body, pred)
        }
        Stmt::While { cond, body }   => expr_any_subexpr(cond, pred) || block_any_expr(body, pred),
        Stmt::For { init, cond, step, body } => {
            init.as_ref().map_or(false, |i| stmt_any_expr(i, pred))
                || cond.as_ref().map_or(false, |c| expr_any_subexpr(c, pred))
                || step.as_ref().map_or(false, |s| stmt_any_expr(s, pred))
                || block_any_expr(body, pred)
        }
        Stmt::Try { body, handler, .. } => {
            block_any_expr(body, pred) || block_any_expr(handler, pred)
        }
        Stmt::Raise { value, .. }    => expr_any_subexpr(value, pred),
        Stmt::Break | Stmt::Continue => false,
        Stmt::Asm(_)                 => false,
    }
}

fn expr_any_subexpr<F: Fn(&Expr) -> bool>(e: &Expr, pred: &F) -> bool {
    if pred(e) { return true; }
    match e {
        Expr::Call { args, .. }       => args.iter().any(|a| expr_any_subexpr(a, pred)),
        Expr::Binary { lhs, rhs, .. } => expr_any_subexpr(lhs, pred) || expr_any_subexpr(rhs, pred),
        Expr::Unary { operand, .. }   => expr_any_subexpr(operand, pred),
        Expr::Assign { value, .. }    => expr_any_subexpr(value, pred),
        Expr::Field { base, .. }      => expr_any_subexpr(base, pred),
        Expr::FieldAssign { base, value, .. } => {
            expr_any_subexpr(base, pred) || expr_any_subexpr(value, pred)
        }
        Expr::DerefAssign { ptr, value } => {
            expr_any_subexpr(ptr, pred) || expr_any_subexpr(value, pred)
        }
        Expr::Index { base, index } => {
            expr_any_subexpr(base, pred) || expr_any_subexpr(index, pred)
        }
        Expr::IndexAssign { base, index, value } => {
            expr_any_subexpr(base, pred)
                || expr_any_subexpr(index, pred)
                || expr_any_subexpr(value, pred)
        }
        Expr::Cast { expr, .. }       => expr_any_subexpr(expr, pred),
        Expr::SizeOf { .. }           => false,
        Expr::StructLit { fields, .. } => {
            fields.iter().any(|(_, e)| expr_any_subexpr(e, pred))
        }
        Expr::Int(_) | Expr::Str(_) | Expr::Bool(_) | Expr::Var(_) => false,
    }
}

// Per-subsystem predicates. They examine an Expr in isolation; the walker
// above takes care of recursion.

fn is_win32_call(e: &Expr) -> bool {
    if let Expr::Call { ns, fname, .. } = e {
        if !ns.is_empty() && !INTRINSIC_NAMESPACES.contains(&ns.as_str()) {
            return true;
        }
        // str.format lowers to a User32.wsprintfA call, so it
        // counts as a Win32 trigger for the resolver pre-scan.
        if ns == "str" && fname == "format" {
            return true;
        }
    }
    false
}

fn is_intrinsic(e: &Expr, want_ns: &str, want_fn: &str) -> bool {
    matches!(e, Expr::Call { ns, fname, .. } if ns == want_ns && fname == want_fn)
}

fn expr_first_span(e: &Expr) -> Option<Span> {
    match e {
        Expr::Call { span, .. } | Expr::StructLit { span, .. } => Some(*span),
        Expr::Assign { value, .. } => expr_first_span(value),
        Expr::FieldAssign { base, value, .. } => {
            expr_first_span(base).or_else(|| expr_first_span(value))
        }
        Expr::DerefAssign { ptr, value } => {
            expr_first_span(ptr).or_else(|| expr_first_span(value))
        }
        Expr::IndexAssign { base, index, value } => {
            expr_first_span(base)
                .or_else(|| expr_first_span(index))
                .or_else(|| expr_first_span(value))
        }
        Expr::Unary { operand, .. } => expr_first_span(operand),
        Expr::Binary { lhs, rhs, .. } => {
            expr_first_span(lhs).or_else(|| expr_first_span(rhs))
        }
        Expr::Field { base, .. } => expr_first_span(base),
        Expr::Cast { expr, .. } => expr_first_span(expr),
        Expr::Index { base, index } => {
            expr_first_span(base).or_else(|| expr_first_span(index))
        }
        Expr::Int(_) | Expr::Str(_) | Expr::Bool(_)
        | Expr::Var(_) | Expr::SizeOf { .. } => None,
    }
}

fn stmts_first_span(stmts: &[Stmt]) -> Option<Span> {
    stmts.iter().find_map(stmt_first_span)
}

fn stmt_first_span(s: &Stmt) -> Option<Span> {
    match s {
        Stmt::Var { span, .. } | Stmt::Ret { span, .. }
        | Stmt::Raise { span, .. } => Some(*span),
        Stmt::Expr { span, value } => {
            if !span.is_unknown() { Some(*span) } else { expr_first_span(value) }
        }
        Stmt::If { cond, then_body, else_body } => {
            expr_first_span(cond)
                .or_else(|| stmts_first_span(then_body))
                .or_else(|| stmts_first_span(else_body))
        }
        Stmt::While { cond, body } => {
            expr_first_span(cond).or_else(|| stmts_first_span(body))
        }
        Stmt::For { init, cond, body, step } => {
            init.as_deref().and_then(stmt_first_span)
                .or_else(|| cond.as_ref().and_then(expr_first_span))
                .or_else(|| stmts_first_span(body))
                .or_else(|| step.as_deref().and_then(stmt_first_span))
        }
        Stmt::Try { body, handler, .. } => {
            stmts_first_span(body).or_else(|| stmts_first_span(handler))
        }
        Stmt::Asm(lines) => lines.first().map(|l| Span::new(l.line, l.col)),
        Stmt::Break | Stmt::Continue => None,
    }
}

fn stmt_breadcrumb(s: &Stmt) -> (Span, &'static str) {
    let kind = match s {
        Stmt::Var { .. }        => "var",
        Stmt::Ret { .. }        => "ret",
        Stmt::Raise { .. }      => "raise",
        Stmt::Expr { value: Expr::Call { .. }, .. } => "call",
        Stmt::Expr { .. }       => "expr",
        Stmt::If { .. }         => "if",
        Stmt::While { .. }      => "while",
        Stmt::For { .. }        => "for",
        Stmt::Break             => "break",
        Stmt::Continue          => "continue",
        Stmt::Try { .. }        => "try",
        Stmt::Asm(_)            => "asm",
    };
    (stmt_first_span(s).unwrap_or_default(), kind)
}

fn is_shared_call(e: &Expr) -> bool {
    matches!(e, Expr::Call { ns, .. } if ns == "shared")
}

pub enum Win32CallSite {
    Extern(String),  // `__imp_KERNEL32$AddVectoredExceptionHandler`
    Slot(String),    // resolver::slot_label() output
}

/// Does any function in the program contain a try { ... } catch { ... }?
/// Driven the same way as program_uses but on the statement variants.
fn program_uses_try(prog: &Program) -> bool {
    prog.functions.iter().any(|f| block_contains_try(&f.body))
}

fn block_contains_try(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_contains_try)
}

fn stmt_contains_try(s: &Stmt) -> bool {
    match s {
        Stmt::Try { .. } => true,
        Stmt::If { then_body, else_body, .. } => {
            block_contains_try(then_body) || block_contains_try(else_body)
        }
        Stmt::While { body, .. } => block_contains_try(body),
        Stmt::For { init, body, step, .. } => {
            init.as_ref().map_or(false, |i| stmt_contains_try(i))
                || block_contains_try(body)
                || step.as_ref().map_or(false, |s| stmt_contains_try(s))
        }
        _ => false,
    }
}
