// SPDX-License-Identifier: Apache-2.0
//! tracer.rs - in-process software-breakpoint tracer.
//!
//! Loads a shellcode `.bin` into RWX memory, plants `int 3` (0xCC) at
//! every breakpoint offset chosen by the DAP server, registers a
//! vectored exception handler, then calls into the entry. Each `int 3`
//! trap is parked in the VEH, which sends a `Stopped` event to the DAP
//! server, snapshots the CPU registers into a session struct the DAP
//! server can read, and blocks on a control channel until told to
//! Continue, Step, or Stop.
//!
//! Software-bp restoration uses the classic "restore + single-step +
//! re-plant" dance:
//!   1. On int 3, restore the original byte and keep RIP at the
//!      trapped instruction so the original runs on resume.
//!   2. Set the TF flag so the CPU traps after that one instruction.
//!   3. In the SINGLE_STEP handler, re-plant `0xCC` at the original
//!      address. The breakpoint is live again for the next pass.
//!
//! Instruction stepping piggy-backs on the same TF trick: when the
//! DAP server sends `StepInstruction`, we set TF and stop again in the
//! SINGLE_STEP handler.
//!
//! This file is Windows-only - VEH and TF instrumentation don't have
//! portable equivalents. On non-Windows the module compiles to a
//! plain stub so the DAP server still builds for local schema tests
//! but loudly refuses to actually trace.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use serde::Serialize;

use crate::sourcemap::SourceMap;

// ============================================================================
// Public protocol between tracer thread and DAP server.
// ============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Tracer parked at a breakpoint or step. The DAP server forwards
    /// this to VS Code as a `stopped` event - that's what makes the
    /// execution arrow appear on the source line. `line`/`col` are
    /// the source mapping when available; otherwise 0 (e.g. stopping
    /// between source statements during instruction stepping).
    Stopped {
        offset:    usize,
        rip:       u64,
        line:      u32,
        col:       u32,
        reason:    StopReason,
        /// Free-form detail string. Used for exception stops
        /// ("ACCESS_VIOLATION reading 0x...") and (eventually)
        /// logpoint hits.
        description: Option<String>,
    },
    /// Shellcode returned. `code` is `rax` truncated to i32.
    Exited { code: i32 },
    /// Diagnostic text to surface in VS Code's Debug Console.
    Output { text: String },
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason { Entry, Breakpoint, Step, Pause, Exception }

#[derive(Debug, Clone)]
pub enum Cmd {
    /// Resume free-running until the next planted breakpoint.
    Continue,
    /// Step exactly one source-mapped statement. The DAP server arms
    /// every source-line offset as a temporary breakpoint before
    /// sending this, so the next break IS the next source line.
    Next,
    /// Step exactly one machine instruction. TF-based - we restore
    /// the byte we trapped on (if any), set TF, and on the SINGLE_STEP
    /// re-stop the tracer with reason=Step.
    StepInstruction,
    /// Replace the active breakpoint set with this list of offsets.
    /// Sent at the start of every session AND whenever the user
    /// toggles breakpoints in VS Code. Safe to receive while the
    /// tracer is parked - applied in place; the park keeps waiting
    /// for a real resume command.
    SetBreakpoints { offsets: Vec<usize> },
    /// Tear down the session (shellcode is mid-run). Restores every
    /// planted byte and resumes - the shellcode then runs to a clean
    /// exit without re-stopping.
    Stop,
}

// ============================================================================
// Register snapshot shared with the DAP server.
// ============================================================================

/// CPU register snapshot captured at every stop. The DAP server reads
/// it through the shared [`TracerSession`] when answering `variables`
/// requests in the "Registers" scope. Keeping it in a Mutex (rather
/// than passing it through the Stopped event) lets the DAP server
/// also serve `readMemory` requests that index off a current register
/// without the event having to round-trip first.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegSnapshot {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8:  u64, pub r9:  u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
}

/// State the DAP server needs while the tracer is running:
///   - shellcode base/size for memoryReference resolution + disasm
///     range bounds-checks,
///   - the latest register snapshot for the Registers variables scope.
///
/// Created by the DAP server, handed to the tracer, written to from
/// inside the VEH handler.
pub struct TracerSession {
    /// Set once by `tracer::run` immediately after `VirtualAlloc`
    /// succeeds, then read-only for the rest of the session. Zero
    /// means "not yet allocated".
    pub base: AtomicUsize,
    pub size: AtomicUsize,
    /// Latest register snapshot. `None` until the first stop.
    pub regs: Mutex<Option<RegSnapshot>>,
    /// Mirror of the tracer's planted-bp table: `(offset, original_byte)`.
    /// The DAP server overlays these onto disasm / readMemory output
    /// so the user sees the original instructions rather than our
    /// `0xCC` traps. Kept in step with the tracer's internal `bps`
    /// via [`TracerSession::set_planted`].
    pub planted: Mutex<Vec<(usize, u8)>>,
    /// Set by the DAP server's `pause` handler after it has armed
    /// TF on the tracer thread via SuspendThread + SetThreadContext.
    /// The next SINGLE_STEP the VEH receives reports a stop with
    /// reason=Pause instead of the usual step semantics.
    pub pause_pending: std::sync::atomic::AtomicBool,
}

impl TracerSession {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            base: AtomicUsize::new(0),
            size: AtomicUsize::new(0),
            regs: Mutex::new(None),
            planted: Mutex::new(Vec::new()),
            pause_pending: std::sync::atomic::AtomicBool::new(false),
        })
    }
    pub fn base(&self) -> usize { self.base.load(Ordering::Acquire) }
    pub fn size(&self) -> usize { self.size.load(Ordering::Acquire) }
    pub fn regs(&self) -> Option<RegSnapshot> { *self.regs.lock().unwrap() }

    /// Replace the planted-bp mirror. Tracer-side helper - call after
    /// any mutation of the real bps list so the DAP server's reads
    /// stay in sync.
    pub fn set_planted(&self, bps: &[(usize, u8)]) {
        *self.planted.lock().unwrap() = bps.to_vec();
    }
}

// ============================================================================
// Windows-only tracer implementation.
// ============================================================================

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::mem::transmute;
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use windows_sys::Win32::Foundation::{EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
        EXCEPTION_POINTERS, RemoveVectoredExceptionHandler,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    };

    /// Singleton tracer state. The VEH callback has no userdata pointer
    /// (Win32 limitation), so the only path it has to find session
    /// state is a global. We accept one active tracer at a time -
    /// matches the DAP "one debuggee per session" model.
    static mut STATE: Option<TracerState> = None;
    static STATE_INSTALLED: AtomicBool = AtomicBool::new(false);

    struct TracerState {
        base:        usize,
        size:        usize,
        map:         SourceMap,
        ev_tx:       Sender<Event>,
        cmd_rx:      std::sync::Mutex<Receiver<Cmd>>,
        session:     Arc<TracerSession>,
        /// All source-line offsets - armed temporarily when the user
        /// asks for a source-line step so the next break IS the next
        /// source line. Sorted, immutable for the session.
        all_source_offsets: Vec<usize>,
        /// `(offset, original_byte)` for every planted breakpoint.
        bps:         std::sync::Mutex<Vec<(usize, u8)>>,
        /// Offsets planted ONLY for the current source-line step. On
        /// the next stop, these are restored and removed from `bps`.
        step_temp_offsets: std::sync::Mutex<Vec<usize>>,
        /// Single-step "owe": after restoring a planted byte and
        /// running the original instruction, we need to re-plant
        /// `0xCC`. The SINGLE_STEP handler reads this, replants,
        /// clears it.
        replant_at:  AtomicUsize,
        replant_pending: AtomicBool,
        /// Set when the user requested an instruction step. The next
        /// SINGLE_STEP exception (after the TF-armed resume) will
        /// stop the tracer again with reason=Step instead of just
        /// continuing.
        step_instr_pending: AtomicBool,
    }

    /// Entry point. Builds the shellcode in RWX memory, plants the
    /// initial breakpoint set (chosen by the DAP server - typically
    /// user bps + an optional stop-on-entry), installs VEH, calls into
    /// the entry. Blocks the caller until the shellcode returns or a
    /// `Cmd::Stop` aborts.
    pub fn run(
        bin: &[u8],
        map: SourceMap,
        initial_bps: Vec<usize>,
        session: Arc<TracerSession>,
        ev_tx: Sender<Event>,
        cmd_rx: Receiver<Cmd>,
    ) {
        if STATE_INSTALLED.swap(true, Ordering::SeqCst) {
            let _ = ev_tx.send(Event::Output {
                text: "tracer: another session is already active".into(),
            });
            return;
        }

        // RWX so we can both patch (write the 0xCC) and execute.
        let mem = unsafe {
            VirtualAlloc(
                null_mut(),
                bin.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut u8;
        if mem.is_null() {
            let _ = ev_tx.send(Event::Output {
                text: "tracer: VirtualAlloc failed".into(),
            });
            STATE_INSTALLED.store(false, Ordering::SeqCst);
            return;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bin.as_ptr(), mem, bin.len());
        }

        // Publish base/size to the DAP server BEFORE we install VEH -
        // any inbound readMemory request must see the region as live.
        session.base.store(mem as usize, Ordering::Release);
        session.size.store(bin.len(), Ordering::Release);

        // Plant ONLY the requested breakpoints. The DAP server hands
        // us the user's chosen set (translated from source lines)
        // plus optionally the first source line for stopOnEntry.
        let mut bps = Vec::with_capacity(initial_bps.len());
        for &offset in &initial_bps {
            if offset >= bin.len() { continue; }
            let p = unsafe { mem.add(offset) };
            let original = unsafe { *p };
            unsafe { *p = 0xCC; }
            bps.push((offset, original));
        }

        let all_source_offsets: Vec<usize> =
            map.entries.iter().map(|e| e.offset).collect();

        // Sync the initial planted set to the session so the DAP
        // server's first disasm / readMemory request already sees the
        // overlay-able originals.
        session.set_planted(&bps);

        unsafe {
            STATE = Some(TracerState {
                base: mem as usize,
                size: bin.len(),
                map,
                ev_tx,
                cmd_rx: std::sync::Mutex::new(cmd_rx),
                session,
                all_source_offsets,
                bps: std::sync::Mutex::new(bps),
                step_temp_offsets: std::sync::Mutex::new(Vec::new()),
                replant_at: AtomicUsize::new(0),
                replant_pending: AtomicBool::new(false),
                step_instr_pending: AtomicBool::new(false),
            });
        }

        // 1  to  call first. Our handler should win over anything the
        // shellcode might install later.
        let veh = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
        if veh.is_null() {
            tear_down(mem);
            return;
        }

        // We trust our own emitter not to throw - unrecoverable
        // shellcode exceptions take down the adapter process, which
        // VS Code surfaces as "debugger died".
        let entry: extern "C" fn() -> i64 = unsafe { transmute(mem) };
        let exit_code = entry();

        let st = unsafe { STATE.as_ref().unwrap() };
        let _ = st.ev_tx.send(Event::Exited { code: exit_code as i32 });

        // Order matters: remove the VEH BEFORE freeing memory so any
        // stale exception delivery can't dereference our state.
        unsafe { RemoveVectoredExceptionHandler(veh) };
        tear_down(mem);
    }

    fn tear_down(mem: *mut u8) {
        unsafe {
            VirtualFree(mem as *mut c_void, 0, MEM_RELEASE);
            STATE = None;
        }
        STATE_INSTALLED.store(false, Ordering::SeqCst);
    }

    /// Tear-down for BOF mode. The loader VirtualAlloc'd all the
    /// sections itself and intentionally leaks them (the harness
    /// process is short-lived, the debugger session is one-shot).
    /// We just clear the global state + the singleton lock so the
    /// next session can install.
    fn tear_down_bof() {
        unsafe { STATE = None; }
        STATE_INSTALLED.store(false, Ordering::SeqCst);
    }

    /// Entry point - BOF flavour. Mirrors [`run`] but consumes an
    /// already-loaded [`bof_loader::load::LoadedBof`] (sections
    /// mapped, `__imp_*` slots resolved, relocations applied) and
    /// calls `go(args, len)` per Win64 ABI instead of `entry()`.
    ///
    /// Plants `int 3` at every debug-info offset within `.text` the
    /// same way `run` does, registers the same VEH, and uses the same
    /// DAP machinery - the only differences are "where the bytes
    /// came from" and "what calling convention the entry uses."
    pub fn run_bof(
        loaded: bof_loader::load::LoadedBof,
        args: Vec<u8>,
        map: SourceMap,
        initial_bps: Vec<usize>,
        session: Arc<TracerSession>,
        ev_tx: Sender<Event>,
        cmd_rx: Receiver<Cmd>,
    ) {
        if STATE_INSTALLED.swap(true, Ordering::SeqCst) {
            let _ = ev_tx.send(Event::Output {
                text: "tracer: another session is already active".into(),
            });
            return;
        }

        // Route BeaconPrintf / BeaconOutput through DAP `Event::Output`
        // so the BOF's prints surface in VS Code's Debug Console.
        // Without this hook the BOF's `print!` writes would land on
        // entc-debug's own stdout - which IS the DAP wire-protocol
        // channel, corrupting frame headers.
        //
        // The closure captures a clone of `ev_tx`; emits are
        // line-buffered (we send each Beacon call as its own event)
        // so VS Code's console flushes promptly. Categories are
        // collapsed to one text stream - DAP `output` doesn't have a
        // semantic distinction between `printf` and `output` and the
        // operator sees a strict-order log anyway.
        let ev_tx_for_hook = ev_tx.clone();
        bof_loader::beacon::set_output_hook(move |cat, text| {
            let prefix = match cat {
                bof_loader::beacon::OutputCategory::Printf => "[BOF] ",
                bof_loader::beacon::OutputCategory::Output => "[BOF output] ",
            };
            let _ = ev_tx_for_hook.send(Event::Output {
                text: format!("{prefix}{text}"),
            });
        });

        let text_base = loaded.text_base;
        let text_size = loaded.text_size;
        let go_addr   = text_base + loaded.go_offset as usize;

        // Publish .text base/size so the DAP server's disasm /
        // readMemory / Locals scope work the same way they do for
        // standard mode.
        session.base.store(text_base, Ordering::Release);
        session.size.store(text_size, Ordering::Release);

        // Plant int 3 at the requested .text offsets.
        let mut bps = Vec::with_capacity(initial_bps.len());
        for &offset in &initial_bps {
            if offset >= text_size { continue; }
            let p = (text_base + offset) as *mut u8;
            let original = unsafe { *p };
            unsafe { *p = 0xCC; }
            bps.push((offset, original));
        }

        let all_source_offsets: Vec<usize> =
            map.entries.iter().map(|e| e.offset).collect();
        session.set_planted(&bps);

        unsafe {
            STATE = Some(TracerState {
                base: text_base,
                size: text_size,
                map,
                ev_tx,
                cmd_rx: std::sync::Mutex::new(cmd_rx),
                session,
                all_source_offsets,
                bps: std::sync::Mutex::new(bps),
                step_temp_offsets: std::sync::Mutex::new(Vec::new()),
                replant_at: AtomicUsize::new(0),
                replant_pending: AtomicBool::new(false),
                step_instr_pending: AtomicBool::new(false),
            });
        }

        let veh = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
        if veh.is_null() {
            tear_down_bof();
            return;
        }

        // Build a NUL-terminated args buffer so a BOF reading `args`
        // as a C string doesn't walk off the end. The reported `len`
        // excludes the NUL (matches Beacon's convention).
        let mut args_z = args;
        args_z.push(0);
        let payload_len = (args_z.len() - 1) as i32;
        let go_fn: unsafe extern "system" fn(*const u8, i32) =
            unsafe { transmute(go_addr) };
        unsafe { go_fn(args_z.as_ptr(), payload_len); }

        let st = unsafe { STATE.as_ref().unwrap() };
        // BOFs return `void`; report exit code 0 to keep the DAP
        // contract happy.
        let _ = st.ev_tx.send(Event::Exited { code: 0 });

        unsafe { RemoveVectoredExceptionHandler(veh) };
        // Drop the output hook so a subsequent session installs its
        // own. Without this, `ev_tx` from THIS session would stay
        // captured by the global hook - fine for one-shot but a
        // hazard for any future multi-session adapter mode.
        bof_loader::beacon::clear_output_hook();
        tear_down_bof();
    }

    /// Vectored exception handler.
    ///
    /// `EXCEPTION_BREAKPOINT` (`int 3`): planted bp hit.
    ///   1. Snapshot registers, look up the source line, push Stopped.
    ///   2. Park; ignore SetBreakpoints; wait for Continue/Next/StepI/Stop.
    ///   3. On resume: restore the trapped byte, set TF, schedule
    ///      replant. For `Next`, arm every source-line offset; for
    ///      `StepInstruction`, also set `step_instr_pending` so the
    ///      SINGLE_STEP handler re-stops the tracer.
    ///
    /// `EXCEPTION_SINGLE_STEP`: TF fired after one instruction.
    ///   1. Replant the saved bp if owed.
    ///   2. If `step_instr_pending`: snapshot regs again, push Stopped
    ///      with reason=Step, park, then re-enter the resume logic.
    ///
    /// Anything else falls through to the system handler.
    unsafe extern "system" fn veh_handler(ep: *mut EXCEPTION_POINTERS) -> i32 {
        let st = match STATE.as_ref() {
            Some(s) => s,
            None => return EXCEPTION_CONTINUE_SEARCH,
        };

        let rec = &*(*ep).ExceptionRecord;
        let ctx = &mut *(*ep).ContextRecord;
        let code = rec.ExceptionCode as i32;

        let rip = ctx.Rip as usize;

        if code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP {
            // If the fault came from INSIDE the shellcode region, treat
            // it as a debuggee crash: snapshot regs, park, let the user
            // inspect, then on any resume command tear the session
            // down (continuing past an AV would just re-fault).
            //
            // If it came from outside the shellcode, pass through to
            // the system handler - that's some Win32 / runtime issue
            // we shouldn't swallow.
            let in_shellcode = rip >= st.base && rip < st.base + st.size;
            if !in_shellcode {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            snapshot_regs(st, ctx);
            let (line, col) = source_at(st, rip);
            let desc = describe_exception(code as u32, rec, rip);
            // Also surface as a console line so it's visible even if
            // the user dismisses the Stop reason.
            let _ = st.ev_tx.send(Event::Output {
                text: format!("[entc-debug] shellcode {}", desc),
            });
            let _ = st.ev_tx.send(Event::Stopped {
                offset: rip - st.base,
                rip:    rip as u64,
                line, col,
                reason: StopReason::Exception,
                description: Some(desc),
            });
            let _ = wait_for_resume_cmd(st);
            // Whatever the user picks, we can't safely keep running -
            // the original faulting instruction is still there. Push
            // an exit and let the host process clean up.
            let _ = st.ev_tx.send(Event::Exited { code: -1 });
            std::process::exit(1);
        }

        // ---- SINGLE_STEP first; usually paired with a planted-bp replant.
        if code == EXCEPTION_SINGLE_STEP {
            if st.replant_pending.swap(false, Ordering::SeqCst) {
                let addr = st.replant_at.load(Ordering::SeqCst);
                let offset = addr - st.base;
                let active = st.bps.lock().unwrap().iter().any(|(o, _)| *o == offset);
                if active {
                    let p = addr as *mut u8;
                    *p = 0xCC;
                }
            }

            // Three things can request a stop on the next SS:
            //   - step_instr_pending: the user asked for `stepIn` at
            //     instruction granularity.
            //   - pause_pending: the DAP server set TF externally via
            //     SuspendThread/SetThreadContext after the user hit
            //     the Pause button.
            // If neither is set, the SS was for our own bp-replant
            // dance and we just resume.
            let step  = st.step_instr_pending.swap(false, std::sync::atomic::Ordering::SeqCst);
            let pause = st.session.pause_pending.swap(false, std::sync::atomic::Ordering::SeqCst);
            if !step && !pause {
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            // Stop here. RIP is at the instruction AFTER the one that
            // was single-stepped; source mapping may be approximate.
            snapshot_regs(st, ctx);
            let (line, col) = source_at(st, rip);
            let offset = rip.wrapping_sub(st.base);
            let reason = if pause { StopReason::Pause } else { StopReason::Step };
            let _ = st.ev_tx.send(Event::Stopped {
                offset, rip: rip as u64, line, col,
                reason, description: None,
            });
            // Park; on resume, run the same dance the breakpoint
            // path uses (the byte at RIP may or may not be a planted
            // bp).
            let cmd = wait_for_resume_cmd(st);
            apply_resume(st, ctx, cmd, /*at_planted_bp=*/false);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // ---- EXCEPTION_BREAKPOINT: must be one of our planted bps.
        if rip < st.base || rip >= st.base + st.size {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let bp_offset = rip - st.base;
        let original = {
            let bps = st.bps.lock().unwrap();
            bps.iter().find(|(o, _)| *o == bp_offset).map(|(_, b)| *b)
        };
        let Some(original) = original else {
            return EXCEPTION_CONTINUE_SEARCH;
        };

        // Remove any temp source-step bps now that we've reached a
        // stop - they fulfilled their purpose. Restore originals.
        let temp = std::mem::take(&mut *st.step_temp_offsets.lock().unwrap());
        if !temp.is_empty() {
            let mut bps = st.bps.lock().unwrap();
            let mut keep: Vec<(usize, u8)> = Vec::new();
            for (off, byte) in bps.iter().copied() {
                if temp.contains(&off) {
                    let p = (st.base + off) as *mut u8;
                    *p = byte;
                } else {
                    keep.push((off, byte));
                }
            }
            *bps = keep;
            st.session.set_planted(&bps);
        }

        snapshot_regs(st, ctx);
        let (line, col) = source_at(st, rip);
        let _ = st.ev_tx.send(Event::Stopped {
            offset: bp_offset,
            rip:    rip as u64,
            line, col,
            reason: StopReason::Breakpoint,
            description: None,
        });

        // Stash the original byte so apply_resume knows what to write
        // back. We re-fetch inside apply_resume since the user may
        // have toggled this bp via SetBreakpoints while parked.
        let cmd = wait_for_resume_cmd(st);
        let _ = original; // bookkeeping; original byte resolved below.
        apply_resume(st, ctx, cmd, /*at_planted_bp=*/true);
        EXCEPTION_CONTINUE_EXECUTION
    }

    /// Block until the DAP server tells us how to resume. SetBreakpoints
    /// arriving while parked is applied in place and we keep waiting -
    /// it's not a resume command.
    fn wait_for_resume_cmd(st: &TracerState) -> Cmd {
        let rx = st.cmd_rx.lock().unwrap();
        loop {
            match rx.recv().unwrap_or(Cmd::Stop) {
                Cmd::SetBreakpoints { offsets } => {
                    apply_breakpoint_set(&offsets);
                }
                other => return other,
            }
        }
    }

    /// Execute the post-park dance: restore the trapped byte (if any),
    /// arm step temporaries, set TF, schedule replant/step.
    unsafe fn apply_resume(
        st: &TracerState,
        ctx: &mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
        cmd: Cmd,
        at_planted_bp: bool,
    ) {
        if matches!(cmd, Cmd::Stop) {
            // Restore every planted byte so the shellcode runs to a
            // clean exit without re-stopping.
            let mut bps = st.bps.lock().unwrap();
            for (off, byte) in bps.iter().copied() {
                let p = (st.base + off) as *mut u8;
                *p = byte;
            }
            bps.clear();
            st.session.set_planted(&bps);
            return;
        }

        let rip = ctx.Rip as usize;

        // For `Next` (source-line step), arm every source-line offset
        // not already planted, so the very next break is the next
        // source statement. We remember the temporary set so the next
        // stop can restore them.
        if matches!(cmd, Cmd::Next) {
            let mut temp: Vec<usize> = Vec::new();
            let mut bps = st.bps.lock().unwrap();
            for &off in &st.all_source_offsets {
                if off >= st.size { continue; }
                // Skip the offset we're sitting on - it'll get its
                // 0xCC replanted by the SINGLE_STEP path below.
                if at_planted_bp && st.base + off == rip { continue; }
                if !bps.iter().any(|(o, _)| *o == off) {
                    let p = (st.base + off) as *mut u8;
                    let original = *p;
                    *p = 0xCC;
                    bps.push((off, original));
                    temp.push(off);
                }
            }
            *st.step_temp_offsets.lock().unwrap() = temp;
            st.session.set_planted(&bps);
        }

        if at_planted_bp {
            // Restore the original byte at RIP. Find it fresh - the
            // user may have removed this bp via SetBreakpoints during
            // the park.
            let bp_offset = rip - st.base;
            let original = st.bps.lock().unwrap()
                .iter().find(|(o, _)| *o == bp_offset).map(|(_, b)| *b);
            if let Some(original) = original {
                let p = rip as *mut u8;
                *p = original;
                ctx.EFlags |= 0x100;
                st.replant_at.store(rip, Ordering::SeqCst);
                st.replant_pending.store(true, Ordering::SeqCst);
            }
        }

        if matches!(cmd, Cmd::StepInstruction) {
            ctx.EFlags |= 0x100;
            st.step_instr_pending.store(true, Ordering::SeqCst);
        }
    }

    /// Look up the source line for an RIP. Returns (0, 0) when there
    /// is no mapping (e.g. mid-instruction-step between source
    /// statements, or RIP outside the shellcode).
    fn source_at(st: &TracerState, rip: usize) -> (u32, u32) {
        if rip < st.base || rip >= st.base + st.size { return (0, 0); }
        match st.map.at(rip - st.base) {
            Some(e) => (e.line, e.col),
            None => match st.map.nearest(rip - st.base) {
                Some(e) => (e.line, e.col),
                None    => (0, 0),
            },
        }
    }

    fn snapshot_regs(
        st: &TracerState,
        ctx: &windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
    ) {
        let snap = RegSnapshot {
            rax: ctx.Rax, rbx: ctx.Rbx, rcx: ctx.Rcx, rdx: ctx.Rdx,
            rsi: ctx.Rsi, rdi: ctx.Rdi, rbp: ctx.Rbp, rsp: ctx.Rsp,
            r8:  ctx.R8,  r9:  ctx.R9,  r10: ctx.R10, r11: ctx.R11,
            r12: ctx.R12, r13: ctx.R13, r14: ctx.R14, r15: ctx.R15,
            rip: ctx.Rip, rflags: ctx.EFlags as u64,
        };
        *st.session.regs.lock().unwrap() = Some(snap);
    }

    /// Decode a Win32 exception code into a one-line description for
    /// the Stopped event's `description` field. We pull the
    /// access-violation operands out of `ExceptionInformation` -
    /// `[0]` is read(0)/write(1)/dep(8), `[1]` is the faulting
    /// address. Other exceptions don't have useful operands so we
    /// just name them.
    fn describe_exception(
        code: u32,
        rec: &windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD,
        rip: usize,
    ) -> String {
        match code {
            0xC0000005 => {
                let op = rec.ExceptionInformation[0];
                let addr = rec.ExceptionInformation[1];
                let verb = match op {
                    0 => "reading",
                    1 => "writing",
                    8 => "executing",
                    _ => "accessing",
                };
                format!("ACCESS_VIOLATION {verb} 0x{addr:x} at rip=0x{rip:x}")
            }
            0xC000001D => format!("ILLEGAL_INSTRUCTION at rip=0x{rip:x}"),
            0xC0000096 => format!("PRIV_INSTRUCTION at rip=0x{rip:x}"),
            0xC0000094 => format!("INT_DIVIDE_BY_ZERO at rip=0x{rip:x}"),
            0xC0000095 => format!("INT_OVERFLOW at rip=0x{rip:x}"),
            0xC00000FD => format!("STACK_OVERFLOW at rip=0x{rip:x}"),
            0x80000003 => format!("BREAKPOINT (foreign int3) at rip=0x{rip:x}"),
            other      => format!("exception 0x{other:08x} at rip=0x{rip:x}"),
        }
    }

    /// Reconcile the planted-bp set with `desired`. Idempotent: bps
    /// that are already in both are left as-is; bps no longer in the
    /// set get their original byte restored; new ones get 0xCC.
    ///
    /// Safe to call from the DAP server thread mid-run: we hold the
    /// `bps` mutex across all memory writes, so the VEH (running on
    /// the tracer thread) is forced to block on the lock if a planted
    /// trap fires concurrently. By the time it unblocks, `*bps` has
    /// been committed and contains the entry the VEH needs to look
    /// up the original byte.
    pub fn apply_breakpoint_set(desired: &[usize]) {
        // STATE is None when the tracer hasn't been started yet or
        // has already torn down. A no-op is the right thing in both
        // cases - the DAP server's setBreakpoints handler also
        // updates user_bps, which gets re-planted from scratch when
        // the tracer is (re)started.
        let st = match unsafe { STATE.as_ref() } { Some(s) => s, None => return };
        let mut bps = st.bps.lock().unwrap();
        let mut keep: Vec<(usize, u8)> = Vec::new();
        for (off, original) in bps.iter().copied() {
            if desired.contains(&off) {
                keep.push((off, original));
            } else {
                let p = (st.base + off) as *mut u8;
                unsafe { *p = original; }
            }
        }
        for &off in desired {
            if !keep.iter().any(|(o, _)| *o == off) {
                if off >= st.size { continue; }
                let p = (st.base + off) as *mut u8;
                let original = unsafe { *p };
                unsafe { *p = 0xCC; }
                keep.push((off, original));
            }
        }
        *bps = keep;
        st.session.set_planted(&bps);
    }
}

#[cfg(windows)]
pub use imp::{run, run_bof, apply_breakpoint_set as apply_breakpoints_live};

/// Plant/unplant breakpoints from outside the tracer thread (e.g.
/// the DAP server's `setBreakpoints` handler).  Safe to call any
/// time - no-op until the tracer has started, no-op after teardown.
#[cfg(not(windows))]
pub fn apply_breakpoints_live(_desired: &[usize]) {}

#[cfg(not(windows))]
pub fn run(
    _bin: &[u8],
    _map: SourceMap,
    _initial_bps: Vec<usize>,
    _session: Arc<TracerSession>,
    ev_tx: Sender<Event>,
    _cmd_rx: Receiver<Cmd>,
) {
    let _ = ev_tx.send(Event::Output {
        text: "entc-debug tracer requires Windows (VEH + TF single-step)".into(),
    });
}

#[cfg(not(windows))]
pub fn run_bof(
    _loaded: bof_loader::load::LoadedBof,
    _args: Vec<u8>,
    _map: SourceMap,
    _initial_bps: Vec<usize>,
    _session: Arc<TracerSession>,
    ev_tx: Sender<Event>,
    _cmd_rx: Receiver<Cmd>,
) {
    let _ = ev_tx.send(Event::Output {
        text: "entc-debug BOF mode requires Windows".into(),
    });
}
