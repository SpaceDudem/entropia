// SPDX-License-Identifier: Apache-2.0
//! beacon.rs - in-harness implementations of the Beacon API.
//!
//! Every function declared in [stdlib/bof.etpy](../../stdlib/bof.etpy)
//! has a stub here so a BOF that calls it can run end-to-end through
//! `bof-runner` instead of bombing on "unresolved external."
//!
//! Stubs aim for **behavioural fidelity** with real Beacon where
//! cheap, and **clear instrumentation** where the real semantics are
//! impractical to replicate locally (process injection, syscall
//! gates, etc.). Each stub category documents which side it leans
//! toward.
//!
//! Calling convention: every exported stub is `unsafe extern "system"`
//! so the BOF can call it through `__imp_<Name>` with no thunking on
//! Win64 (rcx/rdx/r8/r9, 32-byte shadow). Pointers are raw - BOF code
//! is trusted in the harness.
//!
//! Concurrency: the harness runs `go` synchronously on the main
//! thread; no cross-thread state. The `BeaconAddValue` KV store and
//! the `BeaconGate` state use a `Mutex` for safety in case a future
//! version of the harness adds threading.

// The library root gates this module on `cfg(windows)` already;
// the inner attribute is unnecessary here.
#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;

// ============================================================================
// Shared state. Process-global to mirror "Beacon owns the heap" -
// state survives across BOF calls within one harness invocation.
// ============================================================================

/// `BeaconAddValue` / `GetValue` / `RemoveValue` storage. Keys are
/// owned `String`s (BOFs hand us a `char*` we copy on insert); values
/// are raw `usize` (the BOF's choice of payload - pointer, integer,
/// whatever). Lookups return 0 (null) for misses.
static KV: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

fn kv_with<R>(f: impl FnOnce(&mut HashMap<String, usize>) -> R) -> R {
    let mut guard = KV.lock().unwrap();
    if guard.is_none() { *guard = Some(HashMap::new()); }
    f(guard.as_mut().unwrap())
}

unsafe fn cstr_to_string(p: *const u8) -> Option<String> {
    if p.is_null() { return None; }
    let mut n = 0usize;
    while *p.add(n) != 0 && n < 4096 { n += 1; }
    let bytes = std::slice::from_raw_parts(p, n);
    Some(String::from_utf8_lossy(bytes).into_owned())
}

// ============================================================================
// Output: BeaconPrintf, BeaconOutput.
//
// Real Beacon ships output back to the operator's console. Locally
// we route output through an installable hook so:
//
//   * Standalone `bof-runner`  to  default sink writes `[BOF] <text>`
//     to stdout. Identical to the original behaviour.
//
//   * `entc-debug` (DAP mode)  to  installs a custom hook that emits
//     DAP `output` events to VS Code's Debug Console. Without this
//     route, the BOF's `print!` writes would corrupt the DAP wire
//     protocol (entc-debug's stdout IS the DAP channel).
//
// `set_output_hook` / `clear_output_hook` are the public hook
// API. The hook is held in a Mutex so callers from the BOF thread
// don't race with the DAP server thread installing/replacing it.
//
// EntropyKit source can't pass varargs today (you'd use `str.format`
// to build the final string first), so the stub treats `fmt` as a
// pre-formatted literal and emits it raw.
// ============================================================================

/// Output category for the hook callback. `Printf` is the `[BOF]`
/// stream; `Output` is the `[BOF output]` stream (real Beacon sends
/// these to different operator channels - log vs. data).
#[derive(Debug, Clone, Copy)]
pub enum OutputCategory { Printf, Output }

type OutputHook = Box<dyn Fn(OutputCategory, &str) + Send + Sync>;

/// One installable global output hook. When `None`, BeaconPrintf /
/// BeaconOutput fall back to stdout writes (bof-runner default).
/// When `Some`, every output flows through the closure instead -
/// entc-debug installs one that fans out to DAP events.
static OUTPUT_HOOK: Mutex<Option<OutputHook>> = Mutex::new(None);

/// Install a custom output hook. The closure receives a category
/// and a `&str` for every BeaconPrintf / BeaconOutput call. Pass
/// `None` to revert to stdout default.
///
/// Thread-safety: the BOF thread (which calls BeaconPrintf) and
/// the DAP server thread (which installs the hook) hit the same
/// Mutex; contention is minimal because the hook is set once at
/// launch and never replaced mid-session.
pub fn set_output_hook<F>(f: F)
where F: Fn(OutputCategory, &str) + Send + Sync + 'static
{
    *OUTPUT_HOOK.lock().unwrap() = Some(Box::new(f));
}

/// Remove the hook. After this, BeaconPrintf / BeaconOutput resume
/// writing to stdout. `bof-runner` doesn't bother (the harness
/// exits after one run); `entc-debug` calls this on session
/// teardown so a subsequent session doesn't see stale state.
#[allow(dead_code)]
pub fn clear_output_hook() {
    *OUTPUT_HOOK.lock().unwrap() = None;
}

/// Emit one chunk through the active hook (or the default stdout
/// sink). Called from both Beacon API stubs and exposed to the
/// harness so test infrastructure can route diagnostic output
/// through the same pipe.
fn emit_output(cat: OutputCategory, text: &str) {
    if let Some(ref hook) = *OUTPUT_HOOK.lock().unwrap() {
        hook(cat, text);
        return;
    }
    // Default sink - what bof-runner shows.
    match cat {
        OutputCategory::Printf => {
            print!("[BOF] {text}");
            let _ = std::io::stdout().flush();
        }
        OutputCategory::Output => {
            println!("[BOF output] {text}");
        }
    }
}

pub unsafe extern "system" fn BeaconPrintf(_kind: i32, fmt: *const u8) {
    if fmt.is_null() { return; }
    let mut n = 0usize;
    while *fmt.add(n) != 0 && n < 64 * 1024 { n += 1; }
    let bytes = std::slice::from_raw_parts(fmt, n);
    let s = String::from_utf8_lossy(bytes);
    emit_output(OutputCategory::Printf, &s);
}

pub unsafe extern "system" fn BeaconOutput(_kind: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 { return; }
    let slice = std::slice::from_raw_parts(data, len as usize);
    let s = String::from_utf8_lossy(slice);
    emit_output(OutputCategory::Output, &s);
}

// ============================================================================
// Data parsing: BeaconDataParse / Int / Short / Length / Extract.
//
// The C struct (and our `datap` in stdlib/bof.etpy):
//   { char* original; char* buffer; int length; int size; }
// 24 bytes on x64. We index by raw byte offsets so the layout stays
// in sync with the source-level declaration without a Rust mirror.
//
// Format match: Aggressor's `bof_pack` packs variable-length items
// as `[u32 length LE][bytes]`, scalars (`i`, `s`) as BIG-endian.
// Real Beacon does `ntohl()` on the int read, so our stub does too.
// The harness CLI's `--zarg`/`--iarg`/`--sarg` flags pack on the
// same shape so end-to-end tests pass through symmetrically.
// ============================================================================

const OFF_ORIGINAL: usize = 0;
const OFF_BUFFER:   usize = 8;
const OFF_LENGTH:   usize = 16;
const OFF_SIZE:     usize = 20;

unsafe fn dp_buffer(p: *mut u8) -> *mut u8 {
    *(p.add(OFF_BUFFER) as *mut *mut u8)
}
unsafe fn dp_set_buffer(p: *mut u8, v: *mut u8) {
    *(p.add(OFF_BUFFER) as *mut *mut u8) = v;
}
unsafe fn dp_length(p: *mut u8) -> i32 { *(p.add(OFF_LENGTH) as *mut i32) }
unsafe fn dp_set_length(p: *mut u8, v: i32) { *(p.add(OFF_LENGTH) as *mut i32) = v; }

pub unsafe extern "system" fn BeaconDataParse(parser: *mut u8, buffer: *mut u8, size: i32) {
    if parser.is_null() { return; }
    *(parser.add(OFF_ORIGINAL) as *mut *mut u8) = buffer;
    *(parser.add(OFF_BUFFER)   as *mut *mut u8) = buffer;
    *(parser.add(OFF_LENGTH)   as *mut i32)     = size;
    *(parser.add(OFF_SIZE)     as *mut i32)     = size;
}

pub unsafe extern "system" fn BeaconDataInt(parser: *mut u8) -> i32 {
    if parser.is_null() { return 0; }
    let len = dp_length(parser);
    if len < 4 { return 0; }
    let buf = dp_buffer(parser);
    let mut bytes = [0u8; 4];
    std::ptr::copy_nonoverlapping(buf, bytes.as_mut_ptr(), 4);
    dp_set_buffer(parser, buf.add(4));
    dp_set_length(parser, len - 4);
    // Beacon uses network byte order for ints - matches `bof_pack "i"`.
    i32::from_be_bytes(bytes)
}

pub unsafe extern "system" fn BeaconDataShort(parser: *mut u8) -> i16 {
    if parser.is_null() { return 0; }
    let len = dp_length(parser);
    if len < 2 { return 0; }
    let buf = dp_buffer(parser);
    let mut bytes = [0u8; 2];
    std::ptr::copy_nonoverlapping(buf, bytes.as_mut_ptr(), 2);
    dp_set_buffer(parser, buf.add(2));
    dp_set_length(parser, len - 2);
    i16::from_be_bytes(bytes)
}

pub unsafe extern "system" fn BeaconDataLength(parser: *mut u8) -> i32 {
    if parser.is_null() { return 0; }
    dp_length(parser)
}

pub unsafe extern "system" fn BeaconDataExtract(parser: *mut u8, size: *mut i32) -> *mut u8 {
    // Variable-length item: `[u32 length LE][bytes of that length]`.
    // The returned pointer is INTO the original args buffer - caller
    // does not free.
    if parser.is_null() { return std::ptr::null_mut(); }
    let len = dp_length(parser);
    if len < 4 { return std::ptr::null_mut(); }
    let buf = dp_buffer(parser);
    let mut hdr = [0u8; 4];
    std::ptr::copy_nonoverlapping(buf, hdr.as_mut_ptr(), 4);
    let item_len = u32::from_le_bytes(hdr) as i32;
    if len - 4 < item_len {
        return std::ptr::null_mut();
    }
    let item_start = buf.add(4);
    dp_set_buffer(parser, item_start.add(item_len as usize));
    dp_set_length(parser, len - 4 - item_len);
    if !size.is_null() { *size = item_len; }
    item_start
}

// ============================================================================
// Format API: BeaconFormat* - build a buffer in chunks, emit at once.
//
// Each `formatp` owns a heap-allocated `Vec<u8>` indirected through
// the struct's `original` pointer. `Alloc` puts the Vec on the heap
// and stashes the pointer + length; `Free` releases it. We track the
// allocations through `FORMAT_BUFS` so we can deallocate properly
// even if a BOF leaks its `formatp` (real Beacon would just let the
// process exit reclaim it).
// ============================================================================

const FP_OFF_ORIGINAL: usize = 0;
const FP_OFF_BUFFER:   usize = 8;
const FP_OFF_LENGTH:   usize = 16;
const FP_OFF_SIZE:     usize = 20;

static FORMAT_BUFS: Mutex<Option<HashMap<usize, (usize, usize)>>> = Mutex::new(None);
// Maps formatp-pointer  to  (original_ptr_as_usize, capacity). Used so
// `BeaconFormatFree` can convert the original pointer back into a
// `Vec<u8>` for deallocation without leaking.

fn track_format_alloc(fp: usize, original: usize, capacity: usize) {
    let mut g = FORMAT_BUFS.lock().unwrap();
    if g.is_none() { *g = Some(HashMap::new()); }
    g.as_mut().unwrap().insert(fp, (original, capacity));
}
fn forget_format_alloc(fp: usize) -> Option<(usize, usize)> {
    let mut g = FORMAT_BUFS.lock().unwrap();
    g.as_mut().and_then(|m| m.remove(&fp))
}

pub unsafe extern "system" fn BeaconFormatAlloc(format: *mut u8, maxsz: i32) {
    if format.is_null() || maxsz <= 0 { return; }
    let cap = maxsz as usize;
    let mut v: Vec<u8> = Vec::with_capacity(cap);
    let p = v.as_mut_ptr();
    std::mem::forget(v);   // keep the allocation alive; FORMAT_BUFS owns it
    *(format.add(FP_OFF_ORIGINAL) as *mut *mut u8) = p;
    *(format.add(FP_OFF_BUFFER)   as *mut *mut u8) = p;
    *(format.add(FP_OFF_LENGTH)   as *mut i32)     = 0;
    *(format.add(FP_OFF_SIZE)     as *mut i32)     = maxsz;
    track_format_alloc(format as usize, p as usize, cap);
}

pub unsafe extern "system" fn BeaconFormatReset(format: *mut u8) {
    if format.is_null() { return; }
    let original = *(format.add(FP_OFF_ORIGINAL) as *mut *mut u8);
    *(format.add(FP_OFF_BUFFER) as *mut *mut u8) = original;
    *(format.add(FP_OFF_LENGTH) as *mut i32)     = 0;
}

pub unsafe extern "system" fn BeaconFormatFree(format: *mut u8) {
    if format.is_null() { return; }
    if let Some((ptr, cap)) = forget_format_alloc(format as usize) {
        // Reconstruct + drop the Vec to actually deallocate.
        let _v: Vec<u8> = Vec::from_raw_parts(ptr as *mut u8, 0, cap);
    }
    *(format.add(FP_OFF_ORIGINAL) as *mut *mut u8) = std::ptr::null_mut();
    *(format.add(FP_OFF_BUFFER)   as *mut *mut u8) = std::ptr::null_mut();
    *(format.add(FP_OFF_LENGTH)   as *mut i32)     = 0;
    *(format.add(FP_OFF_SIZE)     as *mut i32)     = 0;
}

unsafe fn format_append_bytes(format: *mut u8, data: *const u8, n: usize) {
    if format.is_null() || data.is_null() || n == 0 { return; }
    let cur = *(format.add(FP_OFF_BUFFER) as *mut *mut u8);
    let len = *(format.add(FP_OFF_LENGTH) as *mut i32) as usize;
    let cap = *(format.add(FP_OFF_SIZE)   as *mut i32) as usize;
    let writable = cap.saturating_sub(len);
    let to_copy = n.min(writable);
    if to_copy > 0 {
        std::ptr::copy_nonoverlapping(data, cur, to_copy);
        *(format.add(FP_OFF_BUFFER) as *mut *mut u8) = cur.add(to_copy);
        *(format.add(FP_OFF_LENGTH) as *mut i32)     = (len + to_copy) as i32;
    }
}

pub unsafe extern "system" fn BeaconFormatAppend(format: *mut u8, text: *const u8, len: i32) {
    if len <= 0 { return; }
    format_append_bytes(format, text, len as usize);
}

pub unsafe extern "system" fn BeaconFormatPrintf(format: *mut u8, fmt: *const u8) {
    // EntropyKit source-level varargs don't exist; the BOF passes a
    // pre-formatted string. Treat `fmt` as a literal C string and
    // append its bytes (no NUL).
    if fmt.is_null() { return; }
    let mut n = 0usize;
    while *fmt.add(n) != 0 && n < 64 * 1024 { n += 1; }
    format_append_bytes(format, fmt, n);
}

pub unsafe extern "system" fn BeaconFormatToString(format: *mut u8, size: *mut i32) -> *mut u8 {
    if format.is_null() { return std::ptr::null_mut(); }
    let original = *(format.add(FP_OFF_ORIGINAL) as *mut *mut u8);
    let len      = *(format.add(FP_OFF_LENGTH)   as *mut i32);
    if !size.is_null() { *size = len; }
    original
}

pub unsafe extern "system" fn BeaconFormatInt(format: *mut u8, value: i32) {
    // Big-endian to match Beacon's wire convention (`BeaconDataInt`
    // does `ntohl`). Lets a BOF round-trip an int through Format /
    // Data with no byte-order surprise.
    let bytes = value.to_be_bytes();
    format_append_bytes(format, bytes.as_ptr(), 4);
}

// ============================================================================
// Token: BeaconUseToken, BeaconRevertToken, BeaconIsAdmin.
//
// Real Beacon swaps the thread's token via `SetThreadToken`. The
// harness just tracks "did the BOF ask to use a token?" so tests
// can assert on it; no actual impersonation happens locally.
// ============================================================================

static CURRENT_TOKEN: Mutex<usize> = Mutex::new(0);

pub unsafe extern "system" fn BeaconUseToken(token: *mut u8) -> i32 {
    *CURRENT_TOKEN.lock().unwrap() = token as usize;
    eprintln!("[stub] BeaconUseToken(0x{:x})", token as usize);
    1   // success
}

pub unsafe extern "system" fn BeaconRevertToken() {
    *CURRENT_TOKEN.lock().unwrap() = 0;
    eprintln!("[stub] BeaconRevertToken()");
}

pub unsafe extern "system" fn BeaconIsAdmin() -> i32 {
    eprintln!("[stub] BeaconIsAdmin() -> false");
    0   // not admin in the harness; flip to 1 to simulate elevated runs
}

// ============================================================================
// Spawn / inject - log + no-op. Replicating real injection in a test
// harness is both pointless and dangerous; the operator gets clear
// stderr output describing what their BOF would have done.
// ============================================================================

pub unsafe extern "system" fn BeaconGetSpawnTo(x86: i32, buffer: *mut u8, length: i32) {
    let default = if x86 != 0 {
        b"%windir%\\syswow64\\rundll32.exe\0".as_ref()
    } else {
        b"%windir%\\sysnative\\rundll32.exe\0".as_ref()
    };
    if buffer.is_null() || length <= 0 { return; }
    let n = (length as usize).min(default.len());
    std::ptr::copy_nonoverlapping(default.as_ptr(), buffer, n);
    eprintln!("[stub] BeaconGetSpawnTo(x86={}) -> {}",
              x86 != 0,
              String::from_utf8_lossy(&default[..n.saturating_sub(1)]));
}

pub unsafe extern "system" fn BeaconInjectProcess(
    process_handle: *mut u8, pid: i32,
    _payload: *const u8, p_length: i32, p_offset: i32,
    _arg:     *const u8, a_length: i32,
) {
    eprintln!(
        "[stub] BeaconInjectProcess(handle=0x{:x}, pid={}, payload_len={}, payload_off={}, arg_len={})",
        process_handle as usize, pid, p_length, p_offset, a_length,
    );
}

pub unsafe extern "system" fn BeaconInjectTemporaryProcess(
    process_info: *mut u8,
    _payload: *const u8, p_length: i32, p_offset: i32,
    _arg:     *const u8, a_length: i32,
) {
    eprintln!(
        "[stub] BeaconInjectTemporaryProcess(pi=0x{:x}, payload_len={}, payload_off={}, arg_len={})",
        process_info as usize, p_length, p_offset, a_length,
    );
}

pub unsafe extern "system" fn BeaconCleanupProcess(process_info: *mut u8) {
    eprintln!("[stub] BeaconCleanupProcess(pi=0x{:x})", process_info as usize);
}

pub unsafe extern "system" fn BeaconSpawnTemporaryProcess(
    x86: i32, ignore_token: i32,
    _si: *mut u8, _pi: *mut u8,
) -> i32 {
    eprintln!("[stub] BeaconSpawnTemporaryProcess(x86={}, ignore_token={}) -> false",
              x86 != 0, ignore_token != 0);
    0
}

// ============================================================================
// Utility: toWideChar.
//
// ASCII  to  UTF-16. NUL-terminates the destination if there's room.
// Returns 1 on success, 0 on bad input. Real Beacon uses Win32's
// `MultiByteToWideChar`; for ASCII-only input the byte-by-byte
// extension matches it exactly.
// ============================================================================

pub unsafe extern "system" fn toWideChar(src: *const u8, dst: *mut u16, max: i32) -> i32 {
    if src.is_null() || dst.is_null() || max <= 0 { return 0; }
    let mut i = 0usize;
    let max = max as usize;
    while i + 1 < max {
        let b = *src.add(i);
        if b == 0 { break; }
        *dst.add(i) = b as u16;
        i += 1;
    }
    *dst.add(i) = 0;
    1
}

// ============================================================================
// Session KV store (CS 4.9+).
// ============================================================================

pub unsafe extern "system" fn BeaconAddValue(key: *const u8, ptr: *mut u8) -> i32 {
    let Some(k) = cstr_to_string(key) else { return 0; };
    kv_with(|m| { m.insert(k, ptr as usize); });
    1
}

pub unsafe extern "system" fn BeaconGetValue(key: *const u8) -> *mut u8 {
    let Some(k) = cstr_to_string(key) else { return std::ptr::null_mut(); };
    kv_with(|m| m.get(&k).copied().unwrap_or(0)) as *mut u8
}

pub unsafe extern "system" fn BeaconRemoveValue(key: *const u8) -> i32 {
    let Some(k) = cstr_to_string(key) else { return 0; };
    kv_with(|m| if m.remove(&k).is_some() { 1 } else { 0 })
}

// ============================================================================
// BeaconInformation (CS 4.9+) - fill an opaque BEACON_INFO block.
//
// The harness writes a fixed-shape blob: 4 bytes BOF mode marker,
// 4 bytes harness pid, 8 bytes sleep_ms, rest zeroed. The user code
// reads specific offsets via casts (until we ship a typed wrapper).
// ============================================================================

pub unsafe extern "system" fn BeaconInformation(info: *mut u8) -> i32 {
    if info.is_null() { return 0; }
    // Zero the whole 256-byte block first.
    std::ptr::write_bytes(info, 0, 256);
    // Slot 0..4: signature 'EKBF' (EntropyKit BOF) so callers can
    // tell they're running inside the local harness.
    *(info as *mut u32) = u32::from_le_bytes(*b"EKBF");
    // Slot 4..8: pid.
    *(info.add(4) as *mut u32) = std::process::id();
    // Slot 8..16: a fake sleep of 0 (the harness doesn't loop).
    *(info.add(8) as *mut u64) = 0;
    1
}

// ============================================================================
// Error reporting (CS 4.10+).
// ============================================================================

pub unsafe extern "system" fn BeaconIsErrorMessage(kind: i32, fmt: *const u8) {
    if fmt.is_null() { return; }
    let mut n = 0usize;
    while *fmt.add(n) != 0 && n < 64 * 1024 { n += 1; }
    let bytes = std::slice::from_raw_parts(fmt, n);
    let s = String::from_utf8_lossy(bytes);
    eprintln!("[BOF error type={kind}] {s}");
}

// ============================================================================
// Custom user data (CS 4.10+).
// ============================================================================

static CUSTOM_USER_DATA: Mutex<usize> = Mutex::new(0);

/// Test hook for the harness to seed user data before running the
/// BOF. Not exported to BOFs - they call `BeaconGetCustomUserData`
/// instead.
pub fn set_custom_user_data(p: usize) {
    *CUSTOM_USER_DATA.lock().unwrap() = p;
}

pub unsafe extern "system" fn BeaconGetCustomUserData() -> *mut u8 {
    *CUSTOM_USER_DATA.lock().unwrap() as *mut u8
}

// ============================================================================
// Data store APIs (CS 4.10+) - memory-safety primitives. Stubbed as
// no-ops with logging; the operator gets visibility into what the
// BOF is doing without crashing on missing symbols.
// ============================================================================

pub unsafe extern "system" fn BeaconDataStoreGetItem(index: i32) -> *mut u8 {
    eprintln!("[stub] BeaconDataStoreGetItem({index}) -> null");
    std::ptr::null_mut()
}

pub unsafe extern "system" fn BeaconDataStoreProtectItem(index: i32) {
    eprintln!("[stub] BeaconDataStoreProtectItem({index})");
}

pub unsafe extern "system" fn BeaconDataStoreUnprotectItem(index: i32) {
    eprintln!("[stub] BeaconDataStoreUnprotectItem({index})");
}

// ============================================================================
// Beacon gate APIs (CS 4.10+) - syscall obfuscation. Stubbed.
// ============================================================================

pub unsafe extern "system" fn BeaconGate(vftable_p: *mut u8, indices_p: *mut u8) -> i32 {
    eprintln!("[stub] BeaconGate(vftable=0x{:x}, indices=0x{:x}) -> false",
              vftable_p as usize, indices_p as usize);
    0
}

pub unsafe extern "system" fn BeaconGateReturnValue() -> *mut u8 {
    std::ptr::null_mut()
}

pub unsafe extern "system" fn BeaconDisableBeaconGate() -> i32 {
    eprintln!("[stub] BeaconDisableBeaconGate()");
    1
}

pub unsafe extern "system" fn BeaconEnableBeaconGate() -> i32 {
    eprintln!("[stub] BeaconEnableBeaconGate()");
    1
}

// ============================================================================
// Custom commands (CS 4.10+).
// ============================================================================

static COMMANDS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

fn commands_with<R>(f: impl FnOnce(&mut HashMap<String, usize>) -> R) -> R {
    let mut g = COMMANDS.lock().unwrap();
    if g.is_none() { *g = Some(HashMap::new()); }
    f(g.as_mut().unwrap())
}

pub unsafe extern "system" fn BeaconAddCommand(command: *const u8, function: *mut u8) -> i32 {
    let Some(k) = cstr_to_string(command) else { return 0; };
    commands_with(|m| { m.insert(k, function as usize); });
    1
}

pub unsafe extern "system" fn BeaconRemoveCommand(command: *const u8) -> i32 {
    let Some(k) = cstr_to_string(command) else { return 0; };
    commands_with(|m| if m.remove(&k).is_some() { 1 } else { 0 })
}

pub unsafe extern "system" fn BeaconGetCommand(command: *const u8) -> *mut u8 {
    let Some(k) = cstr_to_string(command) else { return std::ptr::null_mut(); };
    commands_with(|m| m.get(&k).copied().unwrap_or(0)) as *mut u8
}

// ============================================================================
// Dispatch table: name  to  function pointer.
//
// One entry per Beacon API the harness implements. The runner's
// `__imp_<Name>` slot resolver consults this table; unknown names
// fall through to "unresolved external" which fails fast.
// ============================================================================

pub fn resolve(name: &str) -> Option<*const u8> {
    let f: *const u8 = match name {
        // Output
        "BeaconPrintf"                  => BeaconPrintf                  as *const u8,
        "BeaconOutput"                  => BeaconOutput                  as *const u8,

        // Data parsing
        "BeaconDataParse"               => BeaconDataParse               as *const u8,
        "BeaconDataInt"                 => BeaconDataInt                 as *const u8,
        "BeaconDataShort"               => BeaconDataShort               as *const u8,
        "BeaconDataLength"              => BeaconDataLength              as *const u8,
        "BeaconDataExtract"             => BeaconDataExtract             as *const u8,

        // Format
        "BeaconFormatAlloc"             => BeaconFormatAlloc             as *const u8,
        "BeaconFormatReset"             => BeaconFormatReset             as *const u8,
        "BeaconFormatFree"              => BeaconFormatFree              as *const u8,
        "BeaconFormatAppend"            => BeaconFormatAppend            as *const u8,
        "BeaconFormatPrintf"            => BeaconFormatPrintf            as *const u8,
        "BeaconFormatToString"          => BeaconFormatToString          as *const u8,
        "BeaconFormatInt"               => BeaconFormatInt               as *const u8,

        // Token
        "BeaconUseToken"                => BeaconUseToken                as *const u8,
        "BeaconRevertToken"             => BeaconRevertToken             as *const u8,
        "BeaconIsAdmin"                 => BeaconIsAdmin                 as *const u8,

        // Spawn / inject
        "BeaconGetSpawnTo"              => BeaconGetSpawnTo              as *const u8,
        "BeaconInjectProcess"           => BeaconInjectProcess           as *const u8,
        "BeaconInjectTemporaryProcess"  => BeaconInjectTemporaryProcess  as *const u8,
        "BeaconCleanupProcess"          => BeaconCleanupProcess          as *const u8,
        "BeaconSpawnTemporaryProcess"   => BeaconSpawnTemporaryProcess   as *const u8,

        // Utility
        "toWideChar"                    => toWideChar                    as *const u8,

        // KV store
        "BeaconAddValue"                => BeaconAddValue                as *const u8,
        "BeaconGetValue"                => BeaconGetValue                as *const u8,
        "BeaconRemoveValue"             => BeaconRemoveValue             as *const u8,

        // Beacon info / errors / custom data
        "BeaconInformation"             => BeaconInformation             as *const u8,
        "BeaconIsErrorMessage"          => BeaconIsErrorMessage          as *const u8,
        "BeaconGetCustomUserData"       => BeaconGetCustomUserData       as *const u8,

        // Data store
        "BeaconDataStoreGetItem"        => BeaconDataStoreGetItem        as *const u8,
        "BeaconDataStoreProtectItem"    => BeaconDataStoreProtectItem    as *const u8,
        "BeaconDataStoreUnprotectItem"  => BeaconDataStoreUnprotectItem  as *const u8,

        // Beacon gate
        "BeaconGate"                    => BeaconGate                    as *const u8,
        "BeaconGateReturnValue"         => BeaconGateReturnValue         as *const u8,
        "BeaconDisableBeaconGate"       => BeaconDisableBeaconGate       as *const u8,
        "BeaconEnableBeaconGate"        => BeaconEnableBeaconGate        as *const u8,

        // Custom commands
        "BeaconAddCommand"              => BeaconAddCommand              as *const u8,
        "BeaconRemoveCommand"           => BeaconRemoveCommand           as *const u8,
        "BeaconGetCommand"              => BeaconGetCommand              as *const u8,

        _ => return None,
    };
    Some(f)
}
