// SPDX-License-Identifier: Apache-2.0
//! bof-loader - shared in-process COFF loader for EntropyKit BOFs.
//!
//! Used by:
//!   - `bof-runner` (CLI harness for fast iteration)
//!   - `entc-debug` (VS Code DAP server, BOF mode)
//!
//! Both consumers need the same logic - parse a `.obj`, allocate
//! sections, resolve `__imp_*` slots (Beacon stubs + Win32 imports),
//! apply REL32 / ADDR64 relocations, expose the loaded artifact for
//! the caller to either execute (`bof-runner`) or instrument with
//! `int 3` planting (`entc-debug`).
//!
//! Public surface:
//!
//!   - [`coff::ParsedCoff`] - parser for COFF object files.
//!   - [`beacon`] - Beacon API stub dispatch table.
//!   - [`args::parse_packed_args`] - bof_pack-format CLI args packer.
//!   - [`load::load`] - end-to-end load: parse  to  map  to  resolve  to  relocate.
//!     Returns a [`load::LoadedBof`] with section bases, `go` offset,
//!     and the imp-slot region (kept live for the caller's lifetime).
//!
//! Windows-only - the loader needs `VirtualAlloc` + `LoadLibrary` +
//! `GetProcAddress`. On non-Windows, the crate builds but every load
//! call returns an "Windows-only" error so the consumers stay
//! cross-platform-buildable.

#![allow(clippy::missing_safety_doc)]

pub mod coff;

#[cfg(windows)]
pub mod beacon;

pub mod args;

#[cfg(windows)]
pub mod load;

#[cfg(not(windows))]
pub mod load {
    pub struct LoadedBof;
    pub fn load(_bytes: &[u8]) -> Result<LoadedBof, String> {
        Err("bof-loader is Windows-only - it calls Win32 APIs to map RWX pages \
             and resolve __imp_* symbols.".into())
    }
}
