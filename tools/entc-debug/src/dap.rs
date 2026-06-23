// SPDX-License-Identifier: Apache-2.0
//! dap.rs - Debug Adapter Protocol server speaking on stdio.
//!
//! Implements the F5 flow:
//!
//!   initialize  to  launch  to  setBreakpoints*  to  configurationDone
//!                                              ↓
//!                              tracer thread starts, runs until first int 3
//!                                              ↓
//!                   stopped event + register snapshot + (line, col)
//!                                              ↓
//!         continue / next / stepInstruction / setBreakpoints  to  resume  to  ...
//!                                              ↓
//!                                exited / terminated  to  disconnect
//!
//! Beyond the basic stepping loop, this adapter also exposes:
//!
//!   - the "Registers" + "Stack" variables scopes (RAX..R15, RIP,
//!     RFLAGS; sixteen qwords above RSP) - answers `scopes` and
//!     `variables`.
//!   - `disassemble`: feeds VS Code's Disassembly View. Reads bytes
//!     out of the live shellcode region and decodes them with
//!     iced-x86. Instruction stepping pairs naturally with this view.
//!   - `readMemory`: lets users punch any address into the Hex Editor
//!     /Memory view. Validated through VirtualQuery so a typo doesn't
//!     crash the adapter.
//!
//! Out of scope (returns empty / stub): writeMemory, evaluate,
//! conditional breakpoints, multiple threads.
//!
//! Protocol shape (per DAP spec):
//!
//!     Content-Length: <n>\r\n
//!     \r\n
//!     <n bytes of JSON>

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{json, Value};

use crate::sourcemap::SourceMap;
use crate::tracer::{self, Cmd, Event, StopReason, TracerSession};

// ============================================================================
// Wire framing.
// ============================================================================

fn read_message<R: Read>(rdr: &mut R) -> io::Result<Option<Value>> {
    let mut content_length: Option<usize> = None;
    let mut buf = Vec::<u8>::new();
    loop {
        let mut b = [0u8; 1];
        match rdr.read_exact(&mut b) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n") {
            let line = &buf[..buf.len() - 2];
            if line.is_empty() { break; }
            if let Some(rest) = strip_header_prefix(line, b"Content-Length:") {
                if let Ok(s) = std::str::from_utf8(rest) {
                    content_length = s.trim().parse().ok();
                }
            }
            buf.clear();
        }
    }
    let len = content_length.unwrap_or(0);
    let mut body = vec![0u8; len];
    rdr.read_exact(&mut body)?;
    let v: Value = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(v))
}

fn strip_header_prefix<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if line.len() < prefix.len() { return None; }
    if line[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

// ============================================================================
// Shared writer.
// ============================================================================

struct DapWriter {
    out: Mutex<io::Stdout>,
    seq: AtomicI64,
}

impl DapWriter {
    fn new() -> Self {
        Self { out: Mutex::new(io::stdout()), seq: AtomicI64::new(1) }
    }
    fn next_seq(&self) -> i64 { self.seq.fetch_add(1, Ordering::Relaxed) }

    fn write_frame(&self, body: &[u8]) {
        if let Ok(mut out) = self.out.lock() {
            let _ = write!(out, "Content-Length: {}\r\n\r\n", body.len());
            let _ = out.write_all(body);
            let _ = out.flush();
        }
    }
    fn reply_ok(&self, req: &Value, body: Value) {
        let msg = json!({
            "type":        "response",
            "seq":         self.next_seq(),
            "request_seq": req["seq"],
            "success":     true,
            "command":     req["command"],
            "body":        body,
        });
        self.write_frame(&serde_json::to_vec(&msg).unwrap());
    }
    fn reply_err(&self, req: &Value, message: &str) {
        let msg = json!({
            "type":        "response",
            "seq":         self.next_seq(),
            "request_seq": req["seq"],
            "success":     false,
            "command":     req["command"],
            "message":     message,
        });
        self.write_frame(&serde_json::to_vec(&msg).unwrap());
    }
    fn event(&self, name: &str, body: Value) {
        let msg = json!({
            "type":  "event",
            "seq":   self.next_seq(),
            "event": name,
            "body":  body,
        });
        self.write_frame(&serde_json::to_vec(&msg).unwrap());
    }
}

// ============================================================================
// Variable reference IDs.
//
// VS Code identifies expandable variable lists by integer reference.
// We reserve a small static set; nothing here is dynamic enough to
// need a registry.
// ============================================================================

const VARREF_REGISTERS: i64 = 1;
const VARREF_STACK:     i64 = 2;
const VARREF_LOCALS:    i64 = 3;

// ============================================================================
// Server state.
// ============================================================================

struct PendingLaunch {
    bin_path:      String,
    stop_on_entry: bool,
    /// What kind of artifact `bin_path` points at:
    ///   - `Shellcode` - flat `.bin` produced by `--type=standard`.
    ///     Tracer VirtualAllocs RWX + copies + calls offset 0 as
    ///     `extern "C" fn() -> i64`.
    ///   - `Bof { args }` - `.obj` produced by `--type=bof|coff`.
    ///     Loaded via [`bof_loader::load`] (parses COFF, maps
    ///     sections, resolves `__imp_*`, applies relocations).
    ///     Tracer plants int 3 at debug offsets in `.text` and
    ///     calls `go(args, len)` as `extern "system"`.
    artifact: ArtifactKind,
}

enum ArtifactKind {
    Shellcode,
    Bof { args: Vec<u8> },
}

/// Per-breakpoint metadata that affects how a stop is handled:
///
///   - `condition`  - DAP "expression that must be true for the bp to
///                    fire". We evaluate it on each hit; false  to  auto-resume.
///   - `log_message` - DAP "logpoint". On hit, format the template and
///                    emit an Output event, then auto-resume; never
///                    stops. Template `{expr}` placeholders are
///                    evaluated against the registers + locals.
#[derive(Debug, Clone, Default)]
struct BpMeta {
    condition:   Option<String>,
    log_message: Option<String>,
}

/// State shared between the request-handling loop and the tracer-event
/// forwarder thread. The forwarder needs to:
///   (a) read the source map to resolve `line`  to  variable scope,
///   (b) read the tracer session to evaluate expressions against live
///       register state,
///   (c) look up per-breakpoint metadata to decide whether the hit
///       should fire / be skipped / be turned into a log,
///   (d) send `Cmd::Continue` back to the tracer when skipping.
/// All four arrive at different times relative to when the forwarder
/// is spawned, so we route them through Mutex<Option<...>> rather
/// than capturing at spawn time.
struct SharedDap {
    map:       Mutex<Option<SourceMap>>,
    session:   Mutex<Option<Arc<TracerSession>>>,
    cmd_tx:    Mutex<Option<mpsc::Sender<Cmd>>>,
    bp_meta:   Mutex<HashMap<usize, BpMeta>>,
    last_stop: Mutex<Option<(u32, u32)>>,
}

impl SharedDap {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            map:       Mutex::new(None),
            session:   Mutex::new(None),
            cmd_tx:    Mutex::new(None),
            bp_meta:   Mutex::new(HashMap::new()),
            last_stop: Mutex::new(None),
        })
    }
    fn map_clone(&self)     -> Option<SourceMap> { self.map.lock().unwrap().clone() }
    fn session_clone(&self) -> Option<Arc<TracerSession>> { self.session.lock().unwrap().clone() }
    fn current_line(&self)  -> u32 { self.last_stop.lock().unwrap().map(|(l,_)| l).unwrap_or(0) }
}

struct Server {
    pending_launch: Option<PendingLaunch>,
    user_bps:       Vec<usize>,
    tracer_join:    Option<thread::JoinHandle<()>>,
    shared:         Arc<SharedDap>,
}

impl Server {
    fn new(shared: Arc<SharedDap>) -> Self {
        Self {
            pending_launch: None,
            user_bps:       Vec::new(),
            tracer_join:    None,
            shared,
        }
    }
}

// ============================================================================
// Main loop.
// ============================================================================

pub fn serve() {
    let stdin = io::stdin();
    let mut rdr = stdin.lock();
    let writer = Arc::new(DapWriter::new());
    let shared = SharedDap::new();
    let mut srv = Server::new(shared.clone());

    let (ev_tx_main, ev_rx_main) = mpsc::channel::<Event>();
    let writer_clone = writer.clone();
    let shared_clone = shared.clone();
    let _ = thread::spawn(move || {
        for ev in ev_rx_main.iter() {
            match ev {
                Event::Stopped { line, col, reason, description, offset, .. } => {
                    *shared_clone.last_stop.lock().unwrap() = Some((line, col));

                    // Per-breakpoint metadata: a logpoint hit emits an
                    // Output event and auto-resumes (never shows the
                    // stop in the UI). A false condition auto-resumes
                    // silently. Both paths bypass the stopped event.
                    if matches!(reason, StopReason::Breakpoint) {
                        let meta = shared_clone.bp_meta.lock().unwrap()
                            .get(&offset).cloned().unwrap_or_default();
                        if let Some(template) = meta.log_message.as_deref() {
                            let rendered = render_log_message(template, &shared_clone, line);
                            writer_clone.event("output", json!({
                                "category": "console",
                                "output":   format!("{rendered}\n"),
                                "line":     line,
                            }));
                            send_continue(&shared_clone);
                            continue;
                        }
                        if let Some(cond) = meta.condition.as_deref() {
                            if !evaluate_truthy(cond, &shared_clone, line) {
                                send_continue(&shared_clone);
                                continue;
                            }
                        }
                    }

                    let reason_str = match reason {
                        StopReason::Entry      => "entry",
                        StopReason::Breakpoint => "breakpoint",
                        StopReason::Step       => "step",
                        StopReason::Pause      => "pause",
                        StopReason::Exception  => "exception",
                    };
                    let mut body = json!({
                        "reason":            reason_str,
                        "threadId":          1,
                        "allThreadsStopped": true,
                        "preserveFocusHint": false,
                    });
                    if let Some(text) = description {
                        body["text"] = json!(text);
                        body["description"] = json!("debuggee fault");
                    }
                    writer_clone.event("stopped", body);
                }
                Event::Output { text } => {
                    writer_clone.event("output", json!({
                        "category": "console",
                        "output":   format!("{text}\n"),
                    }));
                }
                Event::Exited { code } => {
                    writer_clone.event("exited",     json!({ "exitCode": code }));
                    writer_clone.event("terminated", json!({}));
                }
            }
        }
    });
    let tracer_ev_tx = ev_tx_main;

    fn send_continue(shared: &SharedDap) {
        if let Some(tx) = shared.cmd_tx.lock().unwrap().as_ref() {
            let _ = tx.send(Cmd::Continue);
        }
    }

    loop {
        let req = match read_message(&mut rdr) {
            Ok(Some(v)) => v,
            Ok(None) => return,
            Err(e) => { eprintln!("dap: read error: {e}"); return; }
        };
        let cmd = req["command"].as_str().unwrap_or("").to_string();
        match cmd.as_str() {
            "initialize" => {
                writer.reply_ok(&req, json!({
                    "supportsConfigurationDoneRequest":   true,
                    "supportsTerminateRequest":           true,
                    "supportsRestartRequest":             true,
                    "supportsBreakpointLocationsRequest": true,
                    "supportsSteppingGranularity":        true,
                    "supportsDisassembleRequest":         true,
                    "supportsReadMemoryRequest":          true,
                    "supportsConditionalBreakpoints":     true,
                    "supportsLogPoints":                  true,
                    "supportsEvaluateForHovers":          true,
                    "supportsStepBack":                   false,
                    "supportsExceptionInfoRequest":       false,
                }));
                writer.event("initialized", json!({}));
            }

            "launch" | "attach" => {
                let args = &req["arguments"];
                let program = args["program"].as_str()
                    .or_else(|| args["bin"].as_str())
                    .map(String::from);
                let Some(program) = program else {
                    writer.reply_err(&req,
                        "launch: `program` is required (path to a .etpy source, .bin, .x64.o, .obj, or .coff)");
                    continue;
                };
                let stop_on_entry = args["stopOnEntry"].as_bool().unwrap_or(true);

                // ---- Resolve source + artifact + mode -----------------
                //
                // `program` accepts three shapes; all three converge on
                // the same (source, artifact_path, mode) triple below:
                //
                //   1. `.etpy`             - source mode. Sniff the file
                //                            for `fn go(` vs `fn main(`,
                //                            pick the build kind, ALWAYS
                //                            rebuild (so the .obj/.bin
                //                            on disk matches what the
                //                            user sees in the editor),
                //                            then debug the result.
                //                            This is the recommended F5
                //                            flow - fully self-describing.
                //
                //   2. `.obj` / `.coff`    - BOF artifact path. The
                //                            sibling `.etpy` is the
                //                            source; rebuild iff
                //                            `build: true`.
                //
                //   3. anything else       - shellcode artifact path
                //                            (`.bin` or custom name).
                //                            Same source-derivation rule.
                //
                // The auto-detect path means the package.json default
                // `program: "${file}"` works without the user having to
                // know which artifact kind their .etpy compiles to.
                let force_build = args["build"].as_bool().unwrap_or(false);
                let explicit_source = args["source"].as_str()
                    .filter(|s| !s.is_empty()).map(String::from);

                let resolved = match resolve_launch_target(
                    &program, explicit_source.as_deref(), force_build,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        writer.reply_err(&req, &format!("launch: {e}"));
                        continue;
                    }
                };
                let ResolvedTarget { source, bin_path, build_kind, should_build } = resolved;

                // ---- Compile when requested OR when source-mode -------
                //
                // `.etpy` source mode forces a build every launch - the
                // `.obj`/`.bin`/`.dbg` on disk may be stale, mismatched,
                // or absent entirely. Avoiding the rebuild would mean
                // F5 silently running last-week's binary.
                if should_build {
                    let Some(ref source_path) = source else {
                        writer.reply_err(&req,
                            "build requested but no `.etpy` source found. \
                             Either pass `program: \"path/to/source.etpy\"` or \
                             add `source: \"path/to/source.etpy\"` to launch.json.");
                        continue;
                    };
                    let entc = args["entc"].as_str()
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .or_else(|| find_entc(source_path));
                    let Some(entc) = entc else {
                        writer.reply_err(&req,
                            "build needed but no entc compiler found. Set `entc` in \
                             launch.json to the absolute path of entc.exe, or run \
                             `cargo build -p entropykit` so target/{release,debug}/entc.exe \
                             exists in a parent directory of your source.");
                        continue;
                    };
                    let build_type: Option<&str> = match build_kind {
                        BuildMode::Bof      => Some("bof"),
                        BuildMode::Coff     => Some("coff"),
                        BuildMode::Standard => None,
                    };
                    writer.event("output", json!({
                        "category": "console",
                        "output":   format!(
                            "[entc-debug] launching {source_path} as {} (artifact: {bin_path})\n",
                            match build_kind {
                                BuildMode::Bof      => "BOF",
                                BuildMode::Coff     => "COFF",
                                BuildMode::Standard => "shellcode",
                            }
                        ),
                    }));
                    match run_entc_compile(&entc, source_path, build_type) {
                        Ok(diag) => {
                            if !diag.is_empty() {
                                writer.event("output", json!({
                                    "category": "console",
                                    "output":   diag,
                                }));
                            }
                        }
                        Err(BuildErr { exit_code, stderr }) => {
                            // Stream compile diagnostics into the
                            // Debug Console as stderr so VS Code's
                            // problem-matcher styling kicks in.
                            writer.event("output", json!({
                                "category": "stderr",
                                "output":   stderr,
                            }));
                            writer.reply_err(&req, &format!(
                                "entc compile failed (exit {exit_code}). See Debug Console for details."));
                            continue;
                        }
                    }
                }

                // ---- Final artifact existence check -------------------
                //
                // If we got here without building, the artifact must
                // already exist; otherwise the next `fs::read` deep in
                // the tracer would fail with an opaque message. Catch
                // it now with a precise hint.
                if !Path::new(&bin_path).exists() {
                    writer.reply_err(&req, &format!(
                        "artifact `{bin_path}` doesn't exist. \
                         {} \
                         If the source compiles to a different path, set `program` \
                         to that path explicitly.",
                        if source.is_some() {
                            "Set `build: true` in launch.json to compile it from source."
                        } else {
                            "Pass a `.etpy` source as `program` (recommended) so the \
                             debugger auto-builds, or compile it manually with `entc compile`."
                        }
                    ));
                    continue;
                }

                // ---- Source map sidecar -------------------------------
                let dbg_path = match args["dbg"].as_str() {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => default_dbg_for(&bin_path),
                };

                // ---- Pack BOF args (BOF mode only) --------------------
                let is_bof = matches!(build_kind, BuildMode::Bof | BuildMode::Coff);
                let artifact = if is_bof {
                    let arg_tokens: Vec<String> = args["args"].as_array()
                        .map(|arr| arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect())
                        .unwrap_or_default();
                    match bof_loader::args::parse_packed_args(&arg_tokens) {
                        Ok(packed) => ArtifactKind::Bof { args: packed },
                        Err(e) => {
                            writer.reply_err(&req, &format!("`args`: {e}"));
                            continue;
                        }
                    }
                } else {
                    ArtifactKind::Shellcode
                };

                match SourceMap::load(&dbg_path) {
                    Ok(map) => {
                        *srv.shared.map.lock().unwrap() = Some(map);
                        srv.pending_launch = Some(PendingLaunch {
                            bin_path, stop_on_entry, artifact,
                        });
                        writer.reply_ok(&req, json!({}));
                    }
                    Err(e) => writer.reply_err(&req, &format!(
                        "load source map `{dbg_path}`: {e}. \
                         Did the build emit a .dbg sidecar? \
                         Set `build: true` in launch.json to force `entc compile --debug`."
                    )),
                }
            }

            "setBreakpoints" => {
                let source_path = req["arguments"]["source"]["path"]
                    .as_str().unwrap_or("").to_string();
                let bp_args: Vec<Value> = req["arguments"]["breakpoints"]
                    .as_array().cloned().unwrap_or_default();

                // Translate each requested bp INDIVIDUALLY, preserving
                // the (bp_args, requested_lines, translation) alignment
                // so the metadata indexing below stays correct even
                // when some lines fall between .dbg entries.
                let map_clone = srv.shared.map_clone();
                let translations: Vec<Option<(usize, u32)>> = bp_args.iter().map(|b| {
                    let line = b["line"].as_u64().map(|n| n as u32)?;
                    let map  = map_clone.as_ref()?;
                    translate_one_bp(map, &source_path, line)
                }).collect();

                // Build (offsets, response rows, meta map) in lockstep.
                let mut offsets: Vec<usize> = Vec::new();
                let mut bp_rows: Vec<Value> = Vec::with_capacity(bp_args.len());
                let mut meta = srv.shared.bp_meta.lock().unwrap();
                meta.clear();
                for (i, t) in translations.iter().enumerate() {
                    let raw = &bp_args[i];
                    let req_line = raw["line"].as_u64().unwrap_or(0) as u32;
                    match t {
                        Some((off, mapped_line)) => {
                            offsets.push(*off);
                            // DAP lets the response report a different
                            // line from the request - VS Code snaps
                            // the gutter marker to where the bp
                            // actually landed.
                            bp_rows.push(json!({
                                "verified": true,
                                "line":     mapped_line,
                            }));
                            let condition   = raw["condition"].as_str()
                                .filter(|s| !s.is_empty()).map(String::from);
                            let log_message = raw["logMessage"].as_str()
                                .filter(|s| !s.is_empty()).map(String::from);
                            if condition.is_some() || log_message.is_some() {
                                meta.insert(*off, BpMeta { condition, log_message });
                            }
                        }
                        None => {
                            bp_rows.push(json!({
                                "verified": false,
                                "line":     req_line,
                                "message":  "no .dbg entry at or after this line",
                            }));
                        }
                    }
                }
                drop(meta);

                srv.user_bps = offsets.clone();

                // Apply the new set. If the tracer is already running,
                // plant directly into RWX memory so changes take effect
                // BEFORE the next stop. This is what makes "add a
                // breakpoint while the program is running" actually
                // work - previously we routed through Cmd::SetBreakpoints
                // on a channel that the tracer only drains when parked,
                // so a new bp would only fire if some OTHER bp already
                // existed to park on. apply_breakpoints_live is a no-op
                // when the tracer hasn't started yet, in which case the
                // bps will get planted from `initial` in configurationDone.
                tracer::apply_breakpoints_live(&offsets);

                writer.reply_ok(&req, json!({ "breakpoints": bp_rows }));
            }

            "setExceptionBreakpoints" => {
                writer.reply_ok(&req, json!({}));
            }

            "configurationDone" => {
                writer.reply_ok(&req, json!({}));
                if let Some(pl) = srv.pending_launch.take() {
                    let mut initial = srv.user_bps.clone();
                    let map_for_start = srv.shared.map_clone().expect("map loaded at launch");
                    if pl.stop_on_entry {
                        if let Some(first) = map_for_start.entries.first() {
                            if !initial.contains(&first.offset) {
                                initial.push(first.offset);
                            }
                        }
                    }
                    let session = TracerSession::new();
                    let result = match &pl.artifact {
                        ArtifactKind::Shellcode => start_tracer(
                            &pl.bin_path, map_for_start, initial,
                            session.clone(), tracer_ev_tx.clone(),
                        ),
                        ArtifactKind::Bof { args } => start_tracer_bof(
                            &pl.bin_path, map_for_start, initial,
                            session.clone(), tracer_ev_tx.clone(),
                            args.clone(),
                        ),
                    };
                    match result {
                        Ok((cmd_tx, join)) => {
                            *srv.shared.cmd_tx.lock().unwrap()  = Some(cmd_tx);
                            *srv.shared.session.lock().unwrap() = Some(session);
                            srv.tracer_join = Some(join);
                            writer.event("thread", json!({
                                "reason":   "started",
                                "threadId": 1,
                            }));
                        }
                        Err(e) => {
                            writer.event("output", json!({
                                "category": "stderr",
                                "output":   format!("entc-debug: {e}\n"),
                            }));
                            writer.event("terminated", json!({}));
                        }
                    }
                }
            }

            "threads" => {
                writer.reply_ok(&req, json!({
                    "threads": [{ "id": 1, "name": "shellcode" }]
                }));
            }

            "stackTrace" => {
                let map = srv.shared.map_clone();
                let last = *srv.shared.last_stop.lock().unwrap();
                let body = match (map, last) {
                    (Some(map), Some((line, col))) => {
                        let abs = map.source_path.to_string_lossy().to_string();
                        let name = map.source_path.file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let rip = current_rip(&srv.shared.session_clone()).unwrap_or(0);
                        json!({
                            "stackFrames": [{
                                "id":     1,
                                "name":   "shellcode",
                                "line":   line,
                                "column": col,
                                "instructionPointerReference": format!("0x{rip:x}"),
                                "source": { "path": abs, "name": name }
                            }],
                            "totalFrames": 1
                        })
                    }
                    _ => json!({ "stackFrames": [], "totalFrames": 0 }),
                };
                writer.reply_ok(&req, body);
            }

            "scopes" => {
                // Order matters - VS Code expands the first scope by
                // default. Locals first so users see their named vars
                // before having to drill into Registers.
                writer.reply_ok(&req, json!({
                    "scopes": [
                        {
                            "name":               "Locals",
                            "presentationHint":   "locals",
                            "variablesReference": VARREF_LOCALS,
                            "expensive":          false,
                        },
                        {
                            "name":               "Registers",
                            "presentationHint":   "registers",
                            "variablesReference": VARREF_REGISTERS,
                            "expensive":          false,
                        },
                        {
                            "name":               "Stack",
                            "variablesReference": VARREF_STACK,
                            "expensive":          false,
                        }
                    ]
                }));
            }

            "variables" => {
                let var_ref = req["arguments"]["variablesReference"].as_i64().unwrap_or(0);
                let session = srv.shared.session_clone();
                let map     = srv.shared.map_clone();
                let line    = srv.shared.current_line();
                let vars = match var_ref {
                    VARREF_REGISTERS => build_registers(&session),
                    VARREF_STACK     => build_stack(&session),
                    VARREF_LOCALS    => build_locals(&session, &map, line),
                    _                => Vec::new(),
                };
                writer.reply_ok(&req, json!({ "variables": vars }));
            }

            "disassemble" => {
                let session = srv.shared.session_clone();
                let body = handle_disassemble(&req, &session, &srv.shared.map_clone());
                writer.reply_ok(&req, body);
            }

            "readMemory" => {
                let session = srv.shared.session_clone();
                let (body, ok) = handle_read_memory(&req, &session);
                if ok {
                    writer.reply_ok(&req, body);
                } else {
                    writer.reply_err(&req, "readMemory: invalid memoryReference");
                }
            }

            "evaluate" => {
                let expr = req["arguments"]["expression"].as_str().unwrap_or("").to_string();
                let line = srv.shared.current_line();
                match evaluate(&expr, &srv.shared, line) {
                    Ok(v) => writer.reply_ok(&req, json!({
                        "result":              format_eval_value(&v),
                        "variablesReference":  0,
                        "memoryReference":     match &v {
                            EvalValue::Int(n) => format!("0x{n:x}"),
                            _                 => String::new(),
                        },
                    })),
                    Err(e) => writer.reply_err(&req, &e),
                }
            }

            "continue" => {
                if let Some(tx) = srv.shared.cmd_tx.lock().unwrap().as_ref() {
                    let _ = tx.send(Cmd::Continue);
                }
                writer.reply_ok(&req, json!({ "allThreadsContinued": true }));
            }
            "next" | "stepIn" | "stepOut" => {
                let gran = req["arguments"]["granularity"].as_str().unwrap_or("statement");
                let cmd = if gran == "instruction" { Cmd::StepInstruction } else { Cmd::Next };
                if let Some(tx) = srv.shared.cmd_tx.lock().unwrap().as_ref() {
                    let _ = tx.send(cmd);
                }
                writer.reply_ok(&req, json!({}));
            }
            "pause" => {
                let session = srv.shared.session_clone();
                let ok = match (session, &srv.tracer_join) {
                    (Some(s), Some(j)) => arm_pause(&s, j),
                    _ => false,
                };
                if !ok {
                    writer.event("output", json!({
                        "category": "console",
                        "output":   "[entc-debug] pause: nothing to suspend\n",
                    }));
                }
                writer.reply_ok(&req, json!({}));
            }

            "restart" => {
                // VS Code's UI "Restart" button. We acknowledge the
                // request and exit - the editor then invokes the
                // adapter again from scratch, which is cleaner than
                // teardown-and-respawn inside one process given the
                // global VEH state and one-tracer-at-a-time invariant.
                writer.reply_ok(&req, json!({}));
                writer.event("terminated", json!({ "restart": true }));
                std::process::exit(0);
            }

            "disconnect" | "terminate" => {
                // Acknowledge first so VS Code's UI unblocks, then
                // exit the whole process. We deliberately do NOT
                // try to "let the shellcode finish" - the previous
                // behaviour (restore-and-continue) was why the
                // MessageBox still popped up after the user clicked
                // stop. Killing the adapter process tears down the
                // tracer thread + shellcode + any blocking syscall
                // (MessageBox, Sleep, RPC, ...) atomically.
                writer.reply_ok(&req, json!({}));
                writer.event("terminated", json!({}));
                writer.event("exited",     json!({ "exitCode": 0 }));
                std::process::exit(0);
            }

            _ => { writer.reply_ok(&req, json!({})); }
        }
    }
}

// ============================================================================
// Helpers.
// ============================================================================

fn default_dbg_for(bin: &str) -> String {
    // Multi-segment extensions first so `foo.x64.o` resolves to `foo.dbg`,
    // not `foo.x64.dbg`.
    for ext in [".x64.o", ".x86.o", ".bin", ".obj", ".coff"] {
        if let Some(stem) = bin.strip_suffix(ext) {
            return format!("{stem}.dbg");
        }
    }
    format!("{bin}.dbg")
}

fn start_tracer(
    bin_path: &str,
    map: SourceMap,
    initial_bps: Vec<usize>,
    session: Arc<TracerSession>,
    ev_tx: mpsc::Sender<Event>,
) -> Result<(mpsc::Sender<Cmd>, thread::JoinHandle<()>), String> {
    let bin = fs::read(bin_path)
        .map_err(|e| format!("read {bin_path}: {e}"))?;
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let bin_clone = bin.clone();
    let map_clone = map.clone();
    let session_clone = session.clone();
    let join = thread::spawn(move || {
        tracer::run(&bin_clone, map_clone, initial_bps,
                    session_clone, ev_tx, cmd_rx);
    });
    let _ = session; // moved into spawn; explicit name keeps the read clear.
    Ok((cmd_tx, join))
}

/// BOF flavour of `start_tracer`. Loads the `.obj` via `bof_loader`
/// (parsing, mapping, symbol resolution, relocations) and hands the
/// already-loaded artifact to `tracer::run_bof`. The tracer then
/// plants `int 3` at the debug-info offsets within `.text` and calls
/// `go(args, len)` with Win64 calling convention.
fn start_tracer_bof(
    obj_path: &str,
    map: SourceMap,
    initial_bps: Vec<usize>,
    session: Arc<TracerSession>,
    ev_tx: mpsc::Sender<Event>,
    args: Vec<u8>,
) -> Result<(mpsc::Sender<Cmd>, thread::JoinHandle<()>), String> {
    let coff_bytes = fs::read(obj_path)
        .map_err(|e| format!("read {obj_path}: {e}"))?;
    // Load NOW (on the DAP server thread) rather than inside the
    // tracer thread, so any COFF parse / relocation error surfaces
    // through the existing `Err` path and the user gets a clean
    // launch failure instead of "debugger died."
    let loaded = bof_loader::load::load(&coff_bytes)?;
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let map_clone = map.clone();
    let session_clone = session.clone();
    let join = thread::spawn(move || {
        tracer::run_bof(loaded, args, map_clone, initial_bps,
                        session_clone, ev_tx, cmd_rx);
    });
    let _ = session;
    Ok((cmd_tx, join))
}

/// Translate one breakpoint request to a planted-offset + the actual
/// source line we mapped it to (which may differ from the requested
/// line if the user clicked between .dbg entries).
///
/// Strategy:
///   1. Confirm the source file matches (canonical-path or
///      basename fallback).
///   2. Exact line match  to  use that entry.
///   3. Otherwise, snap FORWARD to the first entry whose line is
///      strictly greater. This matches what most debuggers do for
///      "you clicked the gutter on a line of whitespace / comment".
///   4. If nothing past this line is mapped, give up - there's no
///      executable code we could trap on.
fn translate_one_bp(map: &SourceMap, source_path: &str, line: u32) -> Option<(usize, u32)> {
    let want = std::fs::canonicalize(source_path).ok();
    let have = std::fs::canonicalize(&map.source_path).ok();
    let same_source = match (&want, &have) {
        (Some(a), Some(b)) => a == b,
        _ => map.source_path.file_name() == Path::new(source_path).file_name(),
    };
    if !same_source { return None; }

    if let Some(e) = map.entries.iter().find(|e| e.line == line) {
        return Some((e.offset, e.line));
    }
    // Snap forward to the entry with the SMALLEST line strictly
    // greater than the requested one - NOT the first entry in
    // offset order with `line > requested`. `entries` is sorted by
    // offset, so a naïve `find(|e| e.line > requested)` can pick
    // an entry from a different function whose offset happens to
    // come earlier in the file. Comparing on `e.line` gives us the
    // "next executable line BELOW where you clicked" the user
    // expects.
    map.entries.iter()
        .filter(|e| e.line > line)
        .min_by_key(|e| e.line)
        .map(|e| (e.offset, e.line))
}

fn current_rip(session: &Option<Arc<TracerSession>>) -> Option<u64> {
    session.as_ref().and_then(|s| s.regs()).map(|r| r.rip)
}

// ---------------------------------------------------------------- variables

/// One row in the Registers scope. The `memoryReference` field is set
/// to the value formatted as hex so the user can right-click  to  "View
/// Binary Data" / open the Memory view at the address held by that
/// register.
fn reg(name: &str, value: u64) -> Value {
    json!({
        "name":            name,
        "value":           format!("0x{value:016x}  ({value})"),
        "type":            "u64",
        "variablesReference": 0,
        "memoryReference": format!("0x{value:x}"),
    })
}

fn build_registers(session: &Option<Arc<TracerSession>>) -> Vec<Value> {
    let r = match session.as_ref().and_then(|s| s.regs()) {
        Some(r) => r,
        None    => return vec![],
    };
    let f = r.rflags;
    // RFLAGS bit positions (Intel SDM Vol 1 §3.4.3).
    let bit = |pos: u32, name: &str| -> Value {
        json!({
            "name":  name,
            "value": if (f >> pos) & 1 == 1 { "1" } else { "0" },
            "type":  "flag",
            "variablesReference": 0,
        })
    };
    vec![
        reg("RIP",    r.rip),
        reg("RFLAGS", r.rflags),
        // Single-bit flag rows. Cheap, and once you've debugged a
        // conditional jump that didn't go where you expected, having
        // ZF/CF/SF inline saves you bit-twiddling RFLAGS in your head.
        bit(0,  "CF"), bit(2,  "PF"), bit(4,  "AF"), bit(6,  "ZF"),
        bit(7,  "SF"), bit(10, "DF"), bit(11, "OF"),
        reg("RAX",    r.rax), reg("RBX", r.rbx), reg("RCX", r.rcx), reg("RDX", r.rdx),
        reg("RSI",    r.rsi), reg("RDI", r.rdi),
        reg("RBP",    r.rbp), reg("RSP", r.rsp),
        reg("R8",     r.r8),  reg("R9",  r.r9),  reg("R10", r.r10), reg("R11", r.r11),
        reg("R12",    r.r12), reg("R13", r.r13), reg("R14", r.r14), reg("R15", r.r15),
    ]
}

/// The "Locals" scope: named variables in scope at the current line,
/// resolved through the .dbg's variables section. For each variable
/// we compute its current address from the registers + textual loc
/// expression (`rbp-0x8`, `rax`, ...), then read the underlying
/// qword. Types currently rendered hex/dec like other variables;
/// future work could format `int`/`bool`/`str` differently.
fn build_locals(
    session: &Option<Arc<TracerSession>>,
    map: &Option<SourceMap>,
    line: u32,
) -> Vec<Value> {
    let (regs, map) = match (session.as_ref().and_then(|s| s.regs()), map.as_ref()) {
        (Some(r), Some(m)) => (r, m),
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    // When the stop has no source mapping (line == 0 - e.g. after a
    // pause that landed mid-statement, or an instruction-step between
    // .dbg entries), don't hide every local. The user is still
    // somewhere inside a function; show ALL declared locals so they
    // can see register-derived values rather than an empty panel.
    let scoped: Vec<_> = if line == 0 {
        map.vars.iter().collect()
    } else {
        map.vars_in_scope(line)
    };
    for v in scoped {
        let addr = match resolve_var_address(&v.loc, &regs) {
            Some(a) => a,
            None    => {
                out.push(json!({
                    "name":  v.name,
                    "value": format!("<location \"{}\" not understood>", v.loc),
                    "type":  v.ty,
                    "variablesReference": 0,
                }));
                continue;
            }
        };
        // The location may itself BE a register (no memory read needed):
        // `loc` like `rax` should report rax's value directly.
        if let Some(direct) = direct_register_value(&v.loc, &regs) {
            out.push(json!({
                "name":  v.name,
                "value": format_typed_value(direct, &v.ty),
                "type":  v.ty,
                "variablesReference": 0,
                "memoryReference": format!("0x{:x}", direct),
            }));
            continue;
        }
        let mut buf = [0u8; 8];
        let n = unsafe { try_read_bytes(addr, &mut buf) };
        let value_str = if n == 8 {
            format_typed_value(u64::from_le_bytes(buf), &v.ty)
        } else {
            "<unreadable>".to_string()
        };
        out.push(json!({
            "name":  v.name,
            "value": value_str,
            "type":  v.ty,
            "variablesReference": 0,
            "memoryReference": format!("0x{:x}", addr),
        }));
    }
    out
}

/// Parse a location expression into the absolute address of the
/// variable's storage. Supported shapes:
///   - `rbp-0x8`, `rbp+0x10`, `rsp-0x4` (general `reg±hex`)
///   - `rip+0x...` (rip-relative - globals)
/// Returns None for register-only locations (caller should use
/// `direct_register_value`) and for malformed expressions.
fn resolve_var_address(loc: &str, regs: &crate::tracer::RegSnapshot) -> Option<usize> {
    let s = loc.trim().to_ascii_lowercase();
    // Split on the FIRST + or - (after the register name).
    let split = s.find(|c| c == '+' || c == '-')?;
    let (reg, rest) = s.split_at(split);
    let sign: i64 = if rest.starts_with('-') { -1 } else { 1 };
    let raw = &rest[1..];
    let raw = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    let mag = i64::from_str_radix(raw, 16).ok()?;
    let base = register_by_name(reg.trim(), regs)?;
    Some((base as i64 + sign * mag) as usize)
}

fn direct_register_value(loc: &str, regs: &crate::tracer::RegSnapshot) -> Option<u64> {
    let s = loc.trim().to_ascii_lowercase();
    if s.contains('+') || s.contains('-') { return None; }
    register_by_name(&s, regs)
}

fn register_by_name(name: &str, r: &crate::tracer::RegSnapshot) -> Option<u64> {
    match name {
        "rax" => Some(r.rax), "rbx" => Some(r.rbx), "rcx" => Some(r.rcx), "rdx" => Some(r.rdx),
        "rsi" => Some(r.rsi), "rdi" => Some(r.rdi), "rbp" => Some(r.rbp), "rsp" => Some(r.rsp),
        "r8"  => Some(r.r8),  "r9"  => Some(r.r9),  "r10" => Some(r.r10), "r11" => Some(r.r11),
        "r12" => Some(r.r12), "r13" => Some(r.r13), "r14" => Some(r.r14), "r15" => Some(r.r15),
        "rip" => Some(r.rip), "rflags" => Some(r.rflags),
        _ => None,
    }
}

/// Render a u64 according to a (very loose) source type. `int`/`u32`/
/// etc. land as `0xhex (decimal)`. `bool` collapses to true/false.
/// `str` is shown as the pointer (we'd need to read the heap to
/// dereference, which we'll add when strings become real).
fn format_typed_value(v: u64, ty: &str) -> String {
    match ty {
        "bool" => if v != 0 { "true".into() } else { "false".into() },
        "i32" | "int" => {
            let signed = v as i64 as i32;
            format!("{signed}  (0x{:x})", v & 0xffff_ffff)
        }
        "u32" => format!("{}  (0x{:x})", v as u32, v & 0xffff_ffff),
        "i64" => format!("{}  (0x{:x})", v as i64, v),
        _     => format!("0x{:016x}  ({})", v, v as i64),
    }
}

/// The "Stack" scope: sixteen qwords starting at RSP. Each row reads
/// the qword inline and exposes its address as a memoryReference so
/// the user can drill in further.
fn build_stack(session: &Option<Arc<TracerSession>>) -> Vec<Value> {
    let r = match session.as_ref().and_then(|s| s.regs()) {
        Some(r) => r,
        None    => return vec![],
    };
    let mut out = Vec::with_capacity(16);
    for i in 0..16u64 {
        let addr = r.rsp + i * 8;
        let mut buf = [0u8; 8];
        let read = unsafe { try_read_bytes(addr as usize, &mut buf) };
        let value_str = if read == 8 {
            let qword = u64::from_le_bytes(buf);
            format!("0x{qword:016x}  ({qword})")
        } else {
            "<unreadable>".to_string()
        };
        out.push(json!({
            "name":            format!("[rsp+0x{:02x}]", i * 8),
            "value":           value_str,
            "type":            "qword",
            "variablesReference": 0,
            "memoryReference": format!("0x{:x}", addr),
        }));
    }
    out
}

// ---------------------------------------------------------------- disasm

fn handle_disassemble(
    req: &Value,
    session: &Option<Arc<TracerSession>>,
    map: &Option<SourceMap>,
) -> Value {
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

    let args = &req["arguments"];
    let mem_ref = args["memoryReference"].as_str().unwrap_or("0");
    let byte_offset  = args["offset"].as_i64().unwrap_or(0);
    let instr_offset = args["instructionOffset"].as_i64().unwrap_or(0);
    let count        = args["instructionCount"].as_i64().unwrap_or(32).max(1) as usize;
    let resolve_syms = args["resolveSymbols"].as_bool().unwrap_or(false);
    let _ = resolve_syms;

    let base_addr = parse_hex_address(mem_ref).unwrap_or(0);
    let start_addr = (base_addr as i64).wrapping_add(byte_offset) as u64;

    // We can only safely disassemble bytes we OWN - the shellcode
    // region. If the requested range straddles the shellcode boundary,
    // we trim it and report invalid instructions for the rest so VS
    // Code's Disassembly View still aligns.
    let (region_base, region_size) = match session.as_ref() {
        Some(s) => (s.base() as u64, s.size() as u64),
        None    => (0, 0),
    };

    // Decode forward from start_addr; if instruction_offset is
    // non-zero we walk backward/forward in instructions using a
    // simple heuristic (re-decode from an aligned anchor).
    let bytes = if start_addr >= region_base && start_addr < region_base + region_size {
        let lo = (start_addr - region_base) as usize;
        let mut hi = lo + 16 * count + 16;
        if hi > region_size as usize { hi = region_size as usize; }
        let mut v = vec![0u8; hi - lo];
        unsafe {
            std::ptr::copy_nonoverlapping(
                (region_base as usize + lo) as *const u8,
                v.as_mut_ptr(),
                hi - lo,
            );
        }
        // Overlay the original byte for any planted breakpoint inside
        // this slice - otherwise the user sees `cc int3` instead of
        // the instruction they set the breakpoint on.
        if let Some(s) = session.as_ref() {
            for (off, orig) in s.planted.lock().unwrap().iter() {
                if *off >= lo && *off < hi {
                    v[*off - lo] = *orig;
                }
            }
        }
        v
    } else {
        // Outside our shellcode: try a guarded process-memory read.
        let mut v = vec![0u8; 16 * count];
        let n = unsafe { try_read_bytes(start_addr as usize, &mut v) };
        v.truncate(n);
        v
    };

    let mut decoder = Decoder::with_ip(64, &bytes, start_addr, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_first_operand_char_index(8);
    let mut instr = Instruction::default();
    let mut out_text = String::new();
    let mut decoded: Vec<Value> = Vec::with_capacity(count);

    // Skip forward `instr_offset` instructions if positive; for
    // negative we can't safely walk backward without a fuller cache,
    // so we just clamp to zero (Disassembly View still works - it'll
    // show the requested address as the topmost line).
    let mut skip = instr_offset.max(0);
    while skip > 0 && decoder.can_decode() {
        decoder.decode_out(&mut instr);
        skip -= 1;
    }

    while decoder.can_decode() && decoded.len() < count {
        decoder.decode_out(&mut instr);
        out_text.clear();
        formatter.format(&instr, &mut out_text);

        // Slice the raw bytes of this instruction.
        let start_off = (instr.ip() - start_addr) as usize;
        let end_off   = start_off + instr.len();
        let raw = bytes.get(start_off..end_off)
            .map(|b| b.iter()
                 .map(|x| format!("{:02x}", x))
                 .collect::<Vec<_>>()
                 .join(" "))
            .unwrap_or_default();

        // Source mapping - attach (line, col, source) per row when we
        // can. VS Code's Disassembly View then interleaves the source
        // text between asm rows. Only the FIRST instruction at each
        // source-line offset gets the location attached; rows that
        // fall between source statements stay unannotated, which is
        // what produces the inline-source layout.
        let mut row = json!({
            "address":          format!("0x{:x}", instr.ip()),
            "instructionBytes": raw,
            "instruction":      out_text.clone(),
        });
        if let Some(map) = map.as_ref() {
            if instr.ip() >= region_base && instr.ip() < region_base + region_size {
                let off = (instr.ip() - region_base) as usize;
                if let Some(entry) = map.at(off) {
                    let abs  = map.source_path.to_string_lossy().to_string();
                    let name = map.source_path.file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    row["line"]   = json!(entry.line);
                    row["column"] = json!(entry.col);
                    row["location"] = json!({ "path": abs, "name": name });
                }
            }
        }
        decoded.push(row);
    }

    // Pad with synthetic "??" rows if we got fewer instructions than
    // requested; the Disassembly View expects exactly `count` rows.
    while decoded.len() < count {
        let addr = start_addr.wrapping_add((decoded.len() * 1) as u64);
        decoded.push(json!({
            "address":          format!("0x{:x}", addr),
            "instructionBytes": "",
            "instruction":      "??",
        }));
    }

    json!({ "instructions": decoded })
}

fn parse_hex_address(s: &str) -> Option<u64> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u64::from_str_radix(t, 16).ok()
}

// ---------------------------------------------------------------- readMemory

fn handle_read_memory(req: &Value, session: &Option<Arc<TracerSession>>) -> (Value, bool) {
    let args = &req["arguments"];
    let mem_ref = args["memoryReference"].as_str().unwrap_or("");
    let offset  = args["offset"].as_i64().unwrap_or(0);
    let count   = args["count"].as_i64().unwrap_or(0).max(0) as usize;
    let base    = match parse_hex_address(mem_ref) {
        Some(a) => a,
        None    => return (json!({}), false),
    };
    let addr = (base as i64).wrapping_add(offset) as usize;

    let mut buf = vec![0u8; count];
    let read = unsafe { try_read_bytes(addr, &mut buf) };

    // Overlay planted-bp originals when the read window intersects
    // the shellcode region - matches the disassemble behaviour so the
    // Hex Editor doesn't display our `0xCC` traps.
    if let Some(s) = session.as_ref() {
        let region_base = s.base();
        let region_end  = region_base + s.size();
        if region_base != 0 && addr < region_end && addr + read > region_base {
            for (off, orig) in s.planted.lock().unwrap().iter() {
                let bp_addr = region_base + *off;
                if bp_addr >= addr && bp_addr < addr + read {
                    buf[bp_addr - addr] = *orig;
                }
            }
        }
    }

    let data_b64 = base64_encode(&buf[..read]);
    let body = json!({
        "address":         format!("0x{:x}", addr),
        "data":            data_b64,
        "unreadableBytes": (count - read) as i64,
    });
    (body, true)
}

// ---------------------------------------------------------------- evaluate
//
// A tiny expression evaluator powering three DAP features:
//
//   * `evaluate`            (Watch / hover / Debug Console)
//   * breakpoint condition  ("only stop when this is true")
//   * logpoint placeholders ("{expr} resolves on hit")
//
// Grammar (precedence low  to  high):
//
//   cmp     := add (( "==" | "!=" | "<" | ">" | "<=" | ">=" ) add)?
//   add     := unary (("+" | "-") unary)*
//   unary   := "-"? primary
//   primary := integer | name | "[" cmp "]" | "(" cmp ")"
//
// `name` resolves first as a local-in-scope (via SourceMap.vars), then
// as a register. `[expr]` reads 8 bytes at `expr` and treats them as a
// little-endian u64.
//
// Returns are tagged: integer results vs. byte slices (future:
// strings). For now everything collapses to i64 - sufficient for
// `i == 3`, `rax > 0`, `[rbp-8] != 0`, `i+1`.

#[derive(Debug, Clone)]
enum EvalValue { Int(i64), Bytes(Vec<u8>) }

fn evaluate(expr: &str, shared: &SharedDap, line: u32) -> Result<EvalValue, String> {
    let regs = match shared.session_clone().and_then(|s| s.regs()) {
        Some(r) => r,
        None    => return Err("no register state - debuggee not stopped".into()),
    };
    let map  = shared.map_clone();
    let mut p = Parser { src: expr.as_bytes(), pos: 0, regs: &regs, map: map.as_ref(), line };
    let v = p.parse_cmp()?;
    p.skip_ws();
    if p.pos < p.src.len() {
        return Err(format!("trailing input near `{}`", &expr[p.pos..]));
    }
    Ok(v)
}

fn evaluate_truthy(expr: &str, shared: &SharedDap, line: u32) -> bool {
    match evaluate(expr, shared, line) {
        Ok(EvalValue::Int(n))   => n != 0,
        Ok(EvalValue::Bytes(b)) => !b.is_empty() && b.iter().any(|&x| x != 0),
        Err(_) => true, // be permissive - bad condition shouldn't silently skip
    }
}

fn format_eval_value(v: &EvalValue) -> String {
    match v {
        EvalValue::Int(n)   => format!("0x{:x}  ({})", *n as u64, n),
        EvalValue::Bytes(b) => format!("{} bytes", b.len()),
    }
}

/// Render a DAP logpoint template. Curly braces are placeholders:
/// `i={i} rax={rax}` substitutes each `{expr}` with the evaluated
/// value. Doubled braces `{{` / `}}` are literal.
fn render_log_message(template: &str, shared: &SharedDap, line: u32) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '{' && bytes.get(i + 1).copied() == Some(b'{') {
            out.push('{'); i += 2; continue;
        }
        if c == '}' && bytes.get(i + 1).copied() == Some(b'}') {
            out.push('}'); i += 2; continue;
        }
        if c == '{' {
            // Find matching `}`.
            let start = i + 1;
            let end = match bytes[start..].iter().position(|&b| b == b'}') {
                Some(p) => start + p,
                None    => { out.push(c); i += 1; continue; }
            };
            let expr = &template[start..end];
            let rendered = match evaluate(expr, shared, line) {
                Ok(v)  => format_eval_value(&v),
                Err(e) => format!("<err: {e}>"),
            };
            out.push_str(&rendered);
            i = end + 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

struct Parser<'a> {
    src:  &'a [u8],
    pos:  usize,
    regs: &'a crate::tracer::RegSnapshot,
    map:  Option<&'a SourceMap>,
    line: u32,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && (self.src[self.pos] as char).is_whitespace() {
            self.pos += 1;
        }
    }
    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.src.get(self.pos).copied()
    }
    fn eat(&mut self, s: &[u8]) -> bool {
        self.skip_ws();
        if self.src[self.pos..].starts_with(s) { self.pos += s.len(); true } else { false }
    }

    fn parse_cmp(&mut self) -> Result<EvalValue, String> {
        let l = self.parse_add()?;
        let op = if      self.eat(b"==") { Some("==") }
                 else if self.eat(b"!=") { Some("!=") }
                 else if self.eat(b"<=") { Some("<=") }
                 else if self.eat(b">=") { Some(">=") }
                 else if self.eat(b"<")  { Some("<")  }
                 else if self.eat(b">")  { Some(">")  }
                 else { None };
        if let Some(op) = op {
            let r = self.parse_add()?;
            let li = as_int(&l)?; let ri = as_int(&r)?;
            let b = match op {
                "==" => li == ri, "!=" => li != ri,
                "<"  => li <  ri, ">"  => li >  ri,
                "<=" => li <= ri, ">=" => li >= ri,
                _ => unreachable!(),
            };
            return Ok(EvalValue::Int(if b { 1 } else { 0 }));
        }
        Ok(l)
    }
    fn parse_add(&mut self) -> Result<EvalValue, String> {
        let mut l = self.parse_unary()?;
        loop {
            if self.eat(b"+") {
                let r = self.parse_unary()?;
                l = EvalValue::Int(as_int(&l)?.wrapping_add(as_int(&r)?));
            } else if self.eat(b"-") {
                let r = self.parse_unary()?;
                l = EvalValue::Int(as_int(&l)?.wrapping_sub(as_int(&r)?));
            } else { break; }
        }
        Ok(l)
    }
    fn parse_unary(&mut self) -> Result<EvalValue, String> {
        if self.eat(b"-") {
            let v = self.parse_primary()?;
            return Ok(EvalValue::Int(-as_int(&v)?));
        }
        self.parse_primary()
    }
    fn parse_primary(&mut self) -> Result<EvalValue, String> {
        self.skip_ws();
        let b = match self.src.get(self.pos) {
            Some(&b) => b,
            None     => return Err("unexpected end of expression".into()),
        };
        if b == b'(' {
            self.pos += 1;
            let v = self.parse_cmp()?;
            if !self.eat(b")") { return Err("expected `)`".into()); }
            return Ok(v);
        }
        if b == b'[' {
            self.pos += 1;
            let v = self.parse_cmp()?;
            if !self.eat(b"]") { return Err("expected `]`".into()); }
            let addr = as_int(&v)? as usize;
            let mut buf = [0u8; 8];
            let n = unsafe { try_read_bytes(addr, &mut buf) };
            if n != 8 { return Err(format!("read 8 bytes at 0x{addr:x}: only got {n}")); }
            return Ok(EvalValue::Int(i64::from_le_bytes(buf)));
        }
        if b.is_ascii_digit() {
            return self.parse_number();
        }
        if b.is_ascii_alphabetic() || b == b'_' {
            return self.parse_name();
        }
        Err(format!("unexpected character `{}`", b as char))
    }
    fn parse_number(&mut self) -> Result<EvalValue, String> {
        let start = self.pos;
        // Hex?
        if self.src[self.pos] == b'0' && self.src.get(self.pos + 1).map_or(false, |&c| c == b'x' || c == b'X') {
            self.pos += 2;
            let s = self.pos;
            while self.pos < self.src.len() && (self.src[self.pos] as char).is_ascii_hexdigit() {
                self.pos += 1;
            }
            let txt = std::str::from_utf8(&self.src[s..self.pos]).unwrap();
            return i64::from_str_radix(txt, 16)
                .map(EvalValue::Int)
                .map_err(|e| format!("bad hex literal: {e}"));
        }
        while self.pos < self.src.len() && (self.src[self.pos] as char).is_ascii_digit() {
            self.pos += 1;
        }
        let txt = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
        txt.parse::<i64>().map(EvalValue::Int).map_err(|e| format!("bad number: {e}"))
    }
    fn parse_name(&mut self) -> Result<EvalValue, String> {
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.src[self.pos] as char;
            if !(c.is_ascii_alphanumeric() || c == '_') { break; }
            self.pos += 1;
        }
        let name = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
        // Local first, then register.
        if let Some(map) = self.map {
            for v in map.vars_in_scope(self.line) {
                if v.name == name {
                    let addr = resolve_var_address(&v.loc, self.regs);
                    if let Some(direct) = direct_register_value(&v.loc, self.regs) {
                        return Ok(EvalValue::Int(direct as i64));
                    }
                    if let Some(addr) = addr {
                        let mut buf = [0u8; 8];
                        let n = unsafe { try_read_bytes(addr, &mut buf) };
                        if n != 8 {
                            return Err(format!("read local `{name}` at 0x{addr:x}: got {n} bytes"));
                        }
                        return Ok(EvalValue::Int(i64::from_le_bytes(buf)));
                    }
                }
            }
        }
        if let Some(v) = register_by_name(&name.to_ascii_lowercase(), self.regs) {
            return Ok(EvalValue::Int(v as i64));
        }
        Err(format!("unknown name `{name}`"))
    }
}

fn as_int(v: &EvalValue) -> Result<i64, String> {
    match v {
        EvalValue::Int(n) => Ok(*n),
        _ => Err("expected integer".into()),
    }
}

// ---------------------------------------------------------------- auto-build
//
// `build: true` in launch.json runs `entc compile <source> --debug`
// before loading the .dbg. Resolves three issues:
//
//   * Edit-restart loop: no more stop / compile / F5 dance.
//   * Stale .dbg: the source-map vars section can drift out of sync
//     with the source, which manifests as "Locals shows nothing".
//     Always-rebuild ensures the .dbg matches what's actually running.
//   * Wrong-compile-flags: if a previous run used `--release` without
//     --debug, the .dbg is stale or missing. We force --debug here.

struct BuildErr {
    exit_code: i32,
    stderr:    String,
}

fn run_entc_compile(entc: &str, source: &str, build_type: Option<&str>) -> Result<String, BuildErr> {
    let mut cmd = std::process::Command::new(entc);
    cmd.arg("compile").arg(source).arg("--debug");
    if let Some(t) = build_type {
        cmd.arg(format!("--type={t}"));
    }
    let out = cmd
        .output()
        .map_err(|e| BuildErr {
            exit_code: -1,
            stderr:    format!("failed to spawn `{entc}`: {e}\n"),
        })?;
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(BuildErr {
            exit_code: out.status.code().unwrap_or(-1),
            stderr:    if stderr.is_empty() { stdout } else { stderr + &stdout },
        });
    }
    // entc prints "wrote foo.bin (N bytes)" + .dbg + .entc.js to
    // stderr. Surface it so the user knows what got built.
    Ok(stderr + &stdout)
}

/// Build kind decided at launch time. Mirrors the compiler's
/// `BuildKind` but stays a thin string-ish enum here so the adapter
/// doesn't depend on the compiler crate's types.
#[derive(Debug, Clone, Copy)]
enum BuildMode { Standard, Bof, Coff }

/// Resolved (source, artifact, mode) triple for one launch request.
struct ResolvedTarget {
    /// `.etpy` source path when known. `None` only when the user
    /// pointed `program` at a pre-built artifact and no sibling
    /// `.etpy` exists - at that point a rebuild is impossible and
    /// `should_build` is forced to false.
    source:       Option<String>,
    /// Final path on disk we'll load as the runnable artifact -
    /// `.bin` for shellcode, `.obj`/`.coff` for BOF.
    bin_path:     String,
    /// Inferred build kind. Drives the `--type=` flag during rebuild
    /// AND the `ArtifactKind` selection during execution.
    build_kind:   BuildMode,
    /// True when the adapter should compile before loading. Always
    /// true in source mode (`.etpy` as `program`) so the artifact
    /// matches the source the user can see in the editor; otherwise
    /// follows the `build` field from launch.json.
    should_build: bool,
}

/// Single resolution pass. Handles all three `program` shapes
/// (.etpy source / .obj artifact / .bin artifact) and works out the
/// build mode by sniffing the source when possible.
fn resolve_launch_target(
    program: &str,
    explicit_source: Option<&str>,
    force_build: bool,
) -> Result<ResolvedTarget, String> {
    // Shape 1: `program` is the source itself. Sniff it for `fn go`
    // (BOF) vs `fn main` (shellcode); rebuild EVERY launch so the
    // resulting `.obj`/`.bin` is fresh. This is the F5 sweet spot:
    // VS Code's `${file}` always resolves to the active editor's
    // path, so as long as the user has the .etpy focused, this path
    // is the one chosen.
    if program.ends_with(".etpy") {
        if !Path::new(program).exists() {
            return Err(format!("source `{program}` doesn't exist"));
        }
        let mode = detect_build_mode_from_source(program)
            .map_err(|e| format!("read `{program}`: {e}"))?;
        let bin_path = artifact_path_for(program, mode);
        return Ok(ResolvedTarget {
            source:       Some(program.to_string()),
            bin_path,
            build_kind:   mode,
            should_build: true,    // source mode always rebuilds
        });
    }

    // Shape 2/3: `program` is a pre-built artifact. Honour the path
    // the user gave, but try to surface the matching `.etpy` source
    // (via `explicit_source` first, then the obvious sibling) so we
    // can support `build: true` from launch.json AND so the source
    // map's "this is the file your stack frame is placed in" actually
    // resolves to the right .etpy.
    //
    // If the requested artifact is missing but a sibling .etpy is
    // there, switch the resolution path to source mode - the user
    // is on F5 with no pre-built artifact and clearly wants us to
    // build it. Avoids the historic "F5 reports 'file not found' on
    // a fresh checkout" trap.
    let mode_from_ext = match () {
        _ if program.ends_with(".x64.o") => BuildMode::Bof,
        _ if program.ends_with(".x86.o") => BuildMode::Bof,
        // `.obj` retained for `--type=coff` (generic Windows COFF)
        // and for backward compat with BOFs built before the .x64.o
        // convention change. Treated as BOF here since that was the
        // historical default.
        _ if program.ends_with(".obj")   => BuildMode::Bof,
        _ if program.ends_with(".coff")  => BuildMode::Coff,
        _                                 => BuildMode::Standard,
    };
    let source = explicit_source.map(String::from)
        .or_else(|| etpy_for(program).filter(|p| Path::new(p).exists()));

    if !Path::new(program).exists() {
        // Try to upgrade to source mode if we found a sibling .etpy.
        if let Some(ref src) = source {
            let mode = detect_build_mode_from_source(src)
                .map_err(|e| format!("read `{src}`: {e}"))?;
            let bin_path = artifact_path_for(src, mode);
            return Ok(ResolvedTarget {
                source:       Some(src.clone()),
                bin_path,
                build_kind:   mode,
                should_build: true,
            });
        }
        // Last-ditch: try the standard .bin  to  .x64.o / .obj / .coff
        // auto-swap that earlier versions of the adapter did.
        // Lets `program: "...bin"` keep working when the sibling
        // .x64.o (current convention) or .obj (legacy) exists.
        if let Some(stem) = program.strip_suffix(".bin") {
            for (ext, alt_mode) in [(".x64.o", BuildMode::Bof), (".obj", BuildMode::Bof), (".coff", BuildMode::Coff)] {
                let cand = format!("{stem}{ext}");
                if Path::new(&cand).exists() {
                    return Ok(ResolvedTarget {
                        source,
                        bin_path:     cand,
                        build_kind:   alt_mode,
                        should_build: false,
                    });
                }
            }
        }
        return Err(format!(
            "program `{program}` doesn't exist and no sibling `.etpy` to build from"
        ));
    }

    Ok(ResolvedTarget {
        source,
        bin_path:     program.to_string(),
        build_kind:   mode_from_ext,
        should_build: force_build,
    })
}

/// Read the first ~16 KB of a `.etpy` source and decide which build
/// kind it targets. Looks for the unambiguous entry-point spellings:
/// `fn go(`  =>  BOF, `fn main(`  =>  standard. Falls back to standard so
/// brand-new empty files don't error out.
///
/// Cheap one-shot scan - no parser, no allocations beyond reading
/// the file. `//` line comments aren't stripped but the heuristic is
/// tolerant: a comment line containing literal `fn go(` would
/// misclassify, but that's a corner case the user can always fix by
/// adding `--type=` explicitly.
fn detect_build_mode_from_source(path: &str) -> std::io::Result<BuildMode> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut buf = Vec::with_capacity(16 * 1024);
    // Cap at 64 KB - every real .etpy is much smaller, and capping
    // protects against a huge generated source surprising us.
    let _ = f.take(64 * 1024).read_to_end(&mut buf);
    let src = String::from_utf8_lossy(&buf);
    if src.contains("fn go(") || src.contains("fn go (") {
        return Ok(BuildMode::Bof);
    }
    Ok(BuildMode::Standard)
}

/// Compute the output artifact path `entc compile` will write for
/// a given source + build kind. Mirrors `main.rs::default_output`
/// EXACTLY so the adapter's expectation lines up with what the
/// compiler actually produces - artifacts now land in a `bin/`
/// subdirectory next to the source.
fn artifact_path_for(source: &str, mode: BuildMode) -> String {
    let p = Path::new(source);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("a");
    let bin_dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.join("bin"),
        _ => PathBuf::from("bin"),
    };
    let ext = match mode {
        BuildMode::Standard => "bin",
        // Cobalt Strike's BOF convention is `name.x64.o`.
        // Generic COFF stays `.obj`.
        BuildMode::Bof      => "x64.o",
        BuildMode::Coff     => "obj",
    };
    bin_dir.join(format!("{stem}.{ext}")).to_string_lossy().to_string()
}

/// Derive the .etpy source path next to a built artifact. Returns
/// `None` when the path doesn't end in a recognised artifact
/// extension.
///
/// The compiler now defaults outputs to `<source-dir>/bin/`. So
/// an artifact like `example/bin/foo.x64.o` corresponds to source
/// `example/foo.etpy`. We strip the artifact's filename suffix
/// AND, when the parent directory is named `bin`, hop one level
/// up. Artifacts the operator placed somewhere else still resolve
/// against their own directory - the fallback covers
/// `-o some/path/foo.bin` builds.
fn etpy_for(bin: &str) -> Option<String> {
    let p = Path::new(bin);
    let stem = {
        let name = p.file_name()?.to_string_lossy().to_string();
        let mut s = name.as_str();
        let mut found = false;
        for ext in [".x64.o", ".x86.o", ".bin", ".obj", ".coff"] {
            if let Some(rest) = s.strip_suffix(ext) {
                s = rest;
                found = true;
                break;
            }
        }
        if !found { return None; }
        s.to_string()
    };
    let candidate_with_hop = p.parent().and_then(|dir| {
        // If artifact is placed in `.../bin/foo.x64.o`, the source is
        // `.../foo.etpy`. The hop only fires when the immediate
        // parent dir is literally named `bin` - keeps the resolver
        // predictable.
        if dir.file_name().map(|n| n == "bin").unwrap_or(false) {
            dir.parent().map(|gp| gp.join(format!("{stem}.etpy")))
        } else {
            None
        }
    });
    if let Some(hop) = candidate_with_hop {
        if hop.exists() {
            return Some(hop.to_string_lossy().to_string());
        }
    }
    // Fallback: same directory as the artifact (handles -o paths
    // that bypassed the bin/ convention).
    let same_dir = p.with_file_name(format!("{stem}.etpy"));
    Some(same_dir.to_string_lossy().to_string())
}

/// Walk up the directory tree from `source_path` looking for a
/// `target/release/entc.exe` (preferred) or `target/debug/entc.exe`.
/// Stops at the filesystem root. The walk lets users put the
/// debugger config in any workspace whose Rust target dir is at or
/// above the source file - the common case for monorepos and the
/// EntropyKit workspace layout.
fn find_entc(source_path: &str) -> Option<String> {
    let mut cursor = Path::new(source_path).parent()?.to_path_buf();
    let exe = if cfg!(windows) { "entc.exe" } else { "entc" };
    loop {
        for profile in ["release", "debug"] {
            let cand = cursor.join("target").join(profile).join(exe);
            if cand.exists() {
                return Some(cand.to_string_lossy().to_string());
            }
        }
        match cursor.parent() {
            Some(p) if p != cursor => cursor = p.to_path_buf(),
            _ => return None,
        }
    }
}

// ---------------------------------------------------------------- pause

/// Arm a pause on the tracer thread. We suspend it, set TF on its
/// context, mark `pause_pending` on the session so the VEH reports
/// reason=Pause when it traps, then resume. The CPU executes exactly
/// one more instruction before the SINGLE_STEP trap fires.
///
/// Returns false if any Win32 call fails (in which case the tracer
/// is left running, and we surface a console hint rather than
/// silently swallowing the user's click).
#[cfg(windows)]
fn arm_pause(session: &Arc<TracerSession>, join: &thread::JoinHandle<()>) -> bool {
    use std::os::windows::io::AsRawHandle;
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64,
    };
    use windows_sys::Win32::System::Threading::{ResumeThread, SuspendThread};

    let h = join.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    if h.is_null() { return false; }

    // SuspendThread returns the previous suspend count; -1 (DWORD
    // max) means failure.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX { return false; }

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
    let got = unsafe { GetThreadContext(h, &mut ctx) };
    if got == 0 {
        unsafe { ResumeThread(h); }
        return false;
    }
    ctx.EFlags |= 0x100;
    let set = unsafe { SetThreadContext(h, &ctx) };
    if set == 0 {
        unsafe { ResumeThread(h); }
        return false;
    }

    session.pause_pending.store(true, Ordering::SeqCst);
    unsafe { ResumeThread(h); }
    true
}

#[cfg(not(windows))]
fn arm_pause(_session: &Arc<TracerSession>, _join: &thread::JoinHandle<()>) -> bool {
    false
}

// ---------------------------------------------------------------- safe memory probe

/// Read up to `out.len()` bytes from `addr` in the current process,
/// guarded by VirtualQuery so we don't fault on an unmapped page.
/// Returns the number of bytes successfully read (0 on bad address).
///
/// Used by readMemory, the Stack variables scope, and disasm-outside-
/// shellcode paths. Same-process reads are fine because the tracer
/// shares its address space with the DAP server (they're threads in
/// the same process).
unsafe fn try_read_bytes(addr: usize, out: &mut [u8]) -> usize {
    use windows_sys::Win32::System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION,
        MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD,
    };

    if addr == 0 || out.is_empty() { return 0; }

    let mut copied = 0usize;
    let mut cursor = addr;
    while copied < out.len() {
        let mut info = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        let qsize = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let got = VirtualQuery(cursor as *const _, &mut info, qsize);
        if got == 0 { break; }
        if info.State != MEM_COMMIT { break; }
        if info.Protect & (PAGE_NOACCESS | PAGE_GUARD) != 0 { break; }

        let region_end = info.BaseAddress as usize + info.RegionSize;
        let chunk_end  = region_end.min(addr + out.len());
        let chunk_len  = chunk_end - cursor;
        if chunk_len == 0 { break; }

        std::ptr::copy_nonoverlapping(
            cursor as *const u8,
            out.as_mut_ptr().add(copied),
            chunk_len,
        );
        copied += chunk_len;
        cursor = chunk_end;
    }
    copied
}

// ---------------------------------------------------------------- base64

/// Tiny base64 encoder for readMemory responses. Inlined to avoid a
/// dep on `base64` - the DAP wire format uses standard alphabet with
/// `=` padding, which is two dozen lines.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >>  6) & 0x3f) as usize] as char);
        out.push(ALPHA[((n      ) & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >>  6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}
