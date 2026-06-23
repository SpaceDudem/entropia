// SPDX-License-Identifier: Apache-2.0
//! entc-debug - Debug Adapter Protocol server + in-process tracer for
//! EntropyKit shellcode.
//!
//! Wires VS Code's "Run  to  Start Debugging" (F5) to a custom launcher:
//! we VirtualAlloc a `.bin`, plant software breakpoints (`int 3`) at
//! every source-line offset in the matching `.dbg` map, then call into
//! the shellcode. A Vectored Exception Handler catches each break,
//! parks the tracer thread, and signals the DAP server thread which
//! sends VS Code a `stopped` event with the source location - that's
//! the bit that makes the execution arrow move through the `.etpy`.
//!
//! Architecture:
//!
//!   stdin -> DAP server thread -> mpsc command channel -> tracer thread
//!   stdout <- DAP server thread <- mpsc event channel   <- VEH handler
//!
//! Both threads are placed in the same process. The shellcode runs in the
//! tracer thread; its in-process VEH catches `int 3`, pushes a Stopped
//! event to the server, then blocks on a Win32 event handle until the
//! server replies with a Continue / StepOver command.
//!
//! Run modes (selected by argv[1]):
//!   - no args / `dap`             : DAP server on stdio (what VS Code uses)
//!   - `trace <bin>`               : run a bin once and print each stop to
//!                                   stdout as NDJSON; useful for headless
//!                                   smoke tests outside VS Code.

use std::fs;
use std::io::{self, Write};
use std::sync::mpsc;
use std::thread;

mod dap;
mod tracer;
mod sourcemap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("dap");
    match mode {
        "dap" => run_dap(),
        "trace" => {
            let bin = args.get(2).cloned().unwrap_or_else(|| {
                eprintln!("usage: entc-debug trace <foo.bin>");
                std::process::exit(2);
            });
            run_headless_trace(&bin);
        }
        other => {
            eprintln!("unknown mode `{other}` - try `dap` (default) or `trace <bin>`");
            std::process::exit(2);
        }
    }
}

fn run_dap() {
    dap::serve();
}

/// Headless smoke test: load + trace once, print each source-line stop
/// as NDJSON to stdout, then exit. Useful for `cargo run -- trace foo.bin`
/// without VS Code in the loop.
fn run_headless_trace(bin_path: &str) {
    let dbg_path = bin_path
        .strip_suffix(".bin")
        .map(|s| format!("{s}.dbg"))
        .unwrap_or_else(|| format!("{bin_path}.dbg"));
    let map = sourcemap::SourceMap::load(&dbg_path).unwrap_or_else(|e| {
        eprintln!("entc-debug: load {dbg_path}: {e}");
        std::process::exit(1);
    });
    let bin = fs::read(bin_path).unwrap_or_else(|e| {
        eprintln!("entc-debug: read {bin_path}: {e}");
        std::process::exit(1);
    });

    let (ev_tx, ev_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel();

    // Headless: plant a stop at every source-mapped offset so the
    // NDJSON walks past every statement. The VS Code path is more
    // selective (it only plants what the user / stopOnEntry chose).
    let initial_bps: Vec<usize> = map.entries.iter().map(|e| e.offset).collect();

    // Spawn the tracer. It runs the shellcode + VEH; we pump events
    // back here and just auto-acknowledge every stop with Continue.
    let session = tracer::TracerSession::new();
    let map_clone = map.clone();
    let bin_clone = bin.clone();
    let tracer_handle = thread::spawn(move || {
        tracer::run(&bin_clone, map_clone, initial_bps, session, ev_tx, cmd_rx)
    });

    let stdout = io::stdout();
    let mut out = stdout.lock();
    while let Ok(ev) = ev_rx.recv() {
        let line = serde_json::to_string(&ev).unwrap();
        writeln!(out, "{line}").ok();
        match ev {
            tracer::Event::Stopped { .. } => {
                cmd_tx.send(tracer::Cmd::Continue).ok();
            }
            tracer::Event::Exited { .. } | tracer::Event::Output { .. } => {}
        }
    }
    let _ = tracer_handle.join();
}
