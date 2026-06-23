// SPDX-License-Identifier: Apache-2.0
//! bof-runner - CLI shell over the [`bof_loader`] library.
//!
//! Parses argv, packs typed `bof_pack` args, loads the `.obj` into
//! memory, and calls `go(args, len)`. The heavy lifting (COFF
//! parsing, section mapping, symbol resolution, REL32 / ADDR64
//! relocations, Beacon API stubs) is placed in `tools/bof-loader/` so
//! the VS Code debugger (`entc-debug`) reuses every line of it.
//!
//! Usage:
//!     bof-runner <path.obj> [args...]
//!
//! Argument forms (may repeat; order matters):
//!
//!     --args "raw bytes"   raw UTF-8 buffer + trailing NUL.
//!     --zarg "string"      `bof_pack "z"` - length-prefixed zstring.
//!     --iarg N             `bof_pack "i"` - big-endian 4-byte int.
//!     --sarg N             `bof_pack "s"` - big-endian 2-byte short.
//!     --barg @path         `bof_pack "b"` - length-prefixed binary blob.

use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 || argv[1].starts_with('-') {
        eprintln!(
            "usage: bof-runner <path.obj> [--args RAW] [--zarg STR] \
             [--iarg N] [--sarg N] [--barg @FILE]"
        );
        return ExitCode::from(2);
    }
    let path = &argv[1];

    let packed = match bof_loader::args::parse_packed_args(&argv[2..]) {
        Ok(b) => b,
        Err(e) => { eprintln!("bof-runner: {e}"); return ExitCode::from(2); }
    };

    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => { eprintln!("read {path}: {e}"); return ExitCode::from(1); }
    };

    match run(&bytes, &packed) {
        Ok(()) => ExitCode::from(0),
        Err(e) => { eprintln!("bof-runner: {e}"); ExitCode::from(1) }
    }
}

#[cfg(not(windows))]
fn run(_bytes: &[u8], _args: &[u8]) -> Result<(), String> {
    Err("bof-runner is Windows-only - it calls Win32 APIs to map RWX pages \
         and resolve LIBRARY$Function imports. Build + run on Windows.".into())
}

#[cfg(windows)]
fn run(bytes: &[u8], args_buf: &[u8]) -> Result<(), String> {
    let loaded = bof_loader::load::load(bytes)?;

    // Append a trailing NUL so a BOF that treats `args` as a C string
    // (the simple `MessageBoxA(0, args, ...)` pattern) doesn't read
    // past the end. The reported `len` excludes the NUL - matches
    // Beacon's convention where `len` is the data length only.
    let mut args_buf_z: Vec<u8> = args_buf.to_vec();
    args_buf_z.push(0);
    let payload_len = (args_buf_z.len() - 1) as i32;

    let go_addr = loaded.text_base + loaded.go_offset as usize;
    let go_fn: unsafe extern "system" fn(*const u8, i32) =
        unsafe { std::mem::transmute(go_addr) };
    unsafe { go_fn(args_buf_z.as_ptr(), payload_len); }
    Ok(())
}
