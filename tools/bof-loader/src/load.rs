// SPDX-License-Identifier: Apache-2.0
//! End-to-end COFF load.
//!
//! Given the bytes of a `.obj`, produce a [`LoadedBof`] that the
//! caller can execute (`bof-runner`) or instrument with `int 3` for
//! source-level debugging (`entc-debug`).
//!
//! The load pipeline:
//!
//!   1. Parse the COFF headers / symbol table / string table.
//!   2. VirtualAlloc each section's raw bytes into RWX memory.
//!      `.bss` (raw_size > 0 but no raw bytes) gets a zero-filled
//!      VirtualAlloc'd region. RWX everywhere matches what we use
//!      for shellcode - pragmatic for a test loader; a production
//!      Beacon-equivalent would split RX/R/RW per characteristic.
//!   3. Walk every symbol:
//!        - Undefined external (`__imp_<NAME>`): resolve via the
//!          Beacon-API dispatch table, falling back to
//!          `GetModuleHandle`/`LoadLibrary` + `GetProcAddress` for
//!          `LIBRARY$Function` form. Store the resolved pointer in
//!          a per-symbol slot inside a `PAGE_READWRITE` slot table.
//!        - Defined section symbol: record runtime address (section
//!          base + symbol's value).
//!      Resolve `go` along the way - its offset is needed by the
//!      caller to invoke the entry point.
//!   4. Apply every section's relocations using the unified
//!      `sym_addr` table.

use std::ptr;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};

use crate::beacon;
use crate::coff::{ParsedCoff, IMAGE_REL_AMD64_ADDR64, IMAGE_REL_AMD64_REL32};

/// Result of loading a `.obj` into memory.
///
/// All fields refer to live VirtualAlloc'd regions. The caller keeps
/// the `LoadedBof` value alive for as long as it wants to call into
/// the BOF - dropping it doesn't release the regions (we deliberately
/// leak them; the harness exits after one run, and the debugger
/// process exits after a session, so explicit teardown isn't worth
/// the complexity).
pub struct LoadedBof {
    /// Runtime base address of the `.text` section. Add `go_offset`
    /// for the entry function's address.
    pub text_base: usize,
    pub text_size: usize,
    /// Offset of `go` within `.text`. `text_base + go_offset` is the
    /// address to transmute and call as `extern "system" fn(*const u8, i32)`.
    pub go_offset: u32,
    /// Per-section runtime bases (1-indexed; element 0 is unused so
    /// COFF's 1-based section numbers map directly).
    pub section_bases: Vec<usize>,
    /// Address of the `__imp_*` slot table. Indexed by symbol-table
    /// index - `slot_addr(idx) = imp_slots + idx * 8`. Each slot
    /// holds the resolved function pointer for that external symbol.
    pub imp_slots: usize,
}

pub fn load(bytes: &[u8]) -> Result<LoadedBof, String> {
    let coff = ParsedCoff::parse(bytes)?;

    // ---- Map every section's raw bytes into RWX memory --------------------
    let mut section_bases: Vec<usize> = vec![0; coff.n_sections as usize + 1];
    let mut text_base: usize = 0;
    let mut text_size: usize = 0;

    for i in 0..coff.n_sections {
        let sec = coff.section(i);
        let size = sec.raw_size as usize;
        if size == 0 { continue; }
        let p = unsafe {
            VirtualAlloc(ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        } as usize;
        if p == 0 {
            return Err(format!("VirtualAlloc({size}) failed for section `{}`", sec.name));
        }
        if !sec.raw.is_empty() {
            unsafe { ptr::copy_nonoverlapping(sec.raw.as_ptr(), p as *mut u8, size); }
        } else {
            // .bss-style: zero-fill the region.
            unsafe { ptr::write_bytes(p as *mut u8, 0, size); }
        }
        section_bases[i as usize + 1] = p;
        if sec.name == ".text" {
            text_base = p;
            text_size = size;
        }
    }

    // ---- Build a unified symbol-address table -----------------------------
    let n_syms = coff.n_symbols as usize;
    let imp_slots = unsafe {
        VirtualAlloc(ptr::null(), n_syms.max(1) * 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    } as usize;
    if imp_slots == 0 {
        return Err("VirtualAlloc for imp_slots failed".into());
    }

    let mut sym_addr: Vec<usize> = vec![0; n_syms];
    let mut go_offset: Option<u32> = None;

    for idx in 0..coff.n_symbols {
        let name = coff.symbol_name(idx);
        let section = coff.symbol_section(idx);
        let value = coff.symbol_value(idx);

        if name == "go" {
            go_offset = Some(value);
        }

        if section == 0 {
            // Undefined external - resolve via Beacon API table or
            // LoadLibrary/GetProcAddress.
            let slot_addr = imp_slots + (idx as usize) * 8;
            let Some(rest) = name.strip_prefix("__imp_") else {
                return Err(format!(
                    "undefined symbol `{name}` is not in `__imp_<...>` form - \
                     unresolvable by the loader"
                ));
            };
            let resolved: usize = if let Some(p) = beacon::resolve(rest) {
                p as usize
            } else if let Some((lib, fun)) = split_dollar(rest) {
                resolve_win32(lib, fun)?
            } else {
                return Err(format!(
                    "unresolved external `{name}` - not a known Beacon API \
                     and not a `LIBRARY$Function` form"
                ));
            };
            unsafe { *(slot_addr as *mut usize) = resolved; }
            sym_addr[idx as usize] = slot_addr;
        } else if (section as usize) <= coff.n_sections as usize {
            // Defined in one of our mapped sections.
            sym_addr[idx as usize] = section_bases[section as usize] + value as usize;
        }
        // Negative section numbers (absolute, debug) - leave 0; no
        // relocation should reference these.
    }

    let Some(go_offset) = go_offset else {
        return Err("BOF has no `go` symbol".into());
    };

    // ---- Apply each section's relocations --------------------------------
    for i in 0..coff.n_sections {
        let sec = coff.section(i);
        if sec.relocs.is_empty() { continue; }
        let sec_base = section_bases[i as usize + 1];
        if sec_base == 0 {
            return Err(format!(
                "section `{}` has relocations but wasn't mapped - refusing to patch",
                sec.name
            ));
        }
        let mut off = 0;
        while off + 10 <= sec.relocs.len() {
            let at  = u32::from_le_bytes(sec.relocs[off..off+4].try_into().unwrap());
            let sym = u32::from_le_bytes(sec.relocs[off+4..off+8].try_into().unwrap());
            let ty  = u16::from_le_bytes(sec.relocs[off+8..off+10].try_into().unwrap());
            off += 10;

            let patch_site = sec_base + at as usize;
            let sym_target = sym_addr[sym as usize];

            match ty {
                IMAGE_REL_AMD64_REL32 => {
                    // The patch site already carries any compiler-side
                    // addend (in particular, the in-section offset for
                    // cross-section data references). Final disp32 is:
                    //   sym_target + existing_addend - (patch_site + 4)
                    let existing_addend = unsafe {
                        let mut buf = [0u8; 4];
                        ptr::copy_nonoverlapping(patch_site as *const u8, buf.as_mut_ptr(), 4);
                        i32::from_le_bytes(buf) as i64
                    };
                    let next_ip = (patch_site + 4) as i64;
                    let rel = sym_target as i64 + existing_addend - next_ip;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(format!(
                            "REL32 to symbol #{sym} (`{}`) is out of range \
                             (target=0x{sym_target:x}, addend=0x{existing_addend:x}, \
                             site=0x{patch_site:x})",
                            coff.symbol_name(sym)
                        ));
                    }
                    let bytes = (rel as i32).to_le_bytes();
                    unsafe {
                        ptr::copy_nonoverlapping(bytes.as_ptr(), patch_site as *mut u8, 4);
                    }
                }
                IMAGE_REL_AMD64_ADDR64 => {
                    let bytes = (sym_target as u64).to_le_bytes();
                    unsafe {
                        ptr::copy_nonoverlapping(bytes.as_ptr(), patch_site as *mut u8, 8);
                    }
                }
                other => {
                    return Err(format!(
                        "unsupported relocation type 0x{other:04x} at \
                         section #{i} offset 0x{at:x} (loader handles \
                         REL32 + ADDR64 only)"
                    ));
                }
            }
        }
    }

    Ok(LoadedBof {
        text_base,
        text_size,
        go_offset,
        section_bases,
        imp_slots,
    })
}

/// `__imp_USER32$MessageBoxA`  to  `("USER32", "MessageBoxA")`.
fn split_dollar(rest: &str) -> Option<(&str, &str)> {
    let dollar = rest.find('$')?;
    Some((&rest[..dollar], &rest[dollar+1..]))
}

fn resolve_win32(lib: &str, fun: &str) -> Result<usize, String> {
    // GetModuleHandle first (already-loaded libraries); fall back to
    // LoadLibrary so calling into a DLL not currently in the process
    // maps it on demand. Matches what Beacon's loader does and what
    // the Tradecraft Garden literature recommends for the missing-
    // User32 case (`PIC Parterre`).
    let lib_z = format!("{lib}\0");
    let lib_z_bytes = lib_z.as_bytes();
    let mut h: HMODULE = unsafe { GetModuleHandleA(lib_z_bytes.as_ptr()) };
    if h.is_null() {
        h = unsafe { LoadLibraryA(lib_z_bytes.as_ptr()) };
    }
    if h.is_null() {
        return Err(format!("LoadLibraryA({lib}) failed"));
    }
    let fun_z = format!("{fun}\0");
    let p = unsafe { GetProcAddress(h, fun_z.as_bytes().as_ptr()) };
    match p {
        Some(f) => Ok(f as usize),
        None    => Err(format!("GetProcAddress({lib}!{fun}) failed")),
    }
}
