# EntropyKit VS Code extension

Syntax highlighting **and a source-level debugger** for `.etpy`.
Press F5 on any `.etpy` - the debugger auto-detects shellcode vs BOF
from the source, rebuilds, then steps the execution arrow through
your `.etpy` as the artifact actually runs.

## Debugger quick-start

```sh
# 1. Build the compiler + debug backend.
cargo build --release -p entropykit            # entc
cargo build --release -p entc-debug            # entc-debug.exe

# 2. Install the extension (picks up entc-debug.exe automatically).
cd tools/vscode-entropykit
python build.py install

# 3. Open any .etpy in VS Code and press F5.
```

That's it - no manual `entc compile` step. The default launch config
passes the active editor's path as `program`. The adapter:

1. **Detects the build kind**: scans the source for `fn go(...)`  to 
   BOF, `fn main(...)`  to  shellcode.
2. **Recompiles every launch**: forces `entc compile --debug
   --type=<detected>` so the running `.obj`/`.bin` always matches
   what's on screen. No more "F5 ran last week's binary."
3. **Loads the matching `.dbg` sidecar**, plants source-line breakpoints,
   and traces.

If you'd rather skip the auto-rebuild (e.g. you're investigating a
prebuilt artifact someone else handed you), pick the **"Run pre-built
.bin/.obj (no rebuild)"** snippet when creating launch.json.

### Reliability notes

- `program: "${file}"` (the default) means F5 follows whatever you're
  editing. Keep the `.etpy` tab focused when you press F5 - `${file}`
  resolves to the active editor's path.
- The very first stop is at the first executable `.etpy` line
  (`stopOnEntry: true`). That confirms the right file launched. If
  the arrow doesn't land where you expect, the source path printed
  in the Debug Console reveals which file was actually built.
- The adapter writes a `[entc-debug] launching <source> as
  BOF/shellcode (artifact: <path>)` line at every launch - grep that
  if you're not sure what ran.
- Defender flags BOF tooling. Add `<repo>/target/` and your example
  folder to the AV exclusion list once and the F5 loop stops getting
  randomly interrupted.

What you can do at the breakpoint:

- **F10** - step one source line.
- **F5** - continue to next breakpoint.
- **F9** in the gutter - set/clear a source-line breakpoint. The
  debugger only stops at lines that have a planted `int 3` (= lines
  the compiler emitted a statement at); breakpoints on whitespace or
  declarations without code resolve to the nearest preceding stmt.
- **stopOnEntry**: defaults to true; the very first stop is at the
  first executable `.etpy` line. Set `false` in launch.json to run
  free until a user-set breakpoint hits.

The debug session shows up in the *Debug Console* with `[output]`
events for anything the tracer prints. The shellcode's own
`Kernel32.OutputDebugStringA` calls still go to DebugView (the
tracer runs in-process, so those traverse the host kernel32, not
ours).

## How the debugger works

Architecture is in [tools/entc-debug/](../entc-debug/). Pipeline:

```
VS Code  ──DAP──▶  entc-debug.exe (dap mode)  ──MPSC──▶  tracer thread
   ▲                       │                                  │
   │                       │                                  ▼
   └───────── stopped ─────┴────────── Stopped event ◀── VEH (int 3)
```

The tracer thread `VirtualAlloc`s an RWX buffer, plants `0xCC`
(`int 3`) at every source-mapped byte offset from the `.dbg` file,
registers a Vectored Exception Handler, then calls into the entry.
Each trap parks the tracer, the DAP server forwards a `stopped`
event to VS Code, and resumes when you press F5 / F10.

Software-breakpoint restoration uses the classic
"restore + single-step + re-plant" dance, running in-process via a
Vectored Exception Handler.

The `.bin` is byte-identical with or without `--debug`; debugging
is purely a property of the runtime tracer and the `.dbg` sidecar.

## Syntax-highlighting features

- Keywords: `fn`, `extern`, `var`, `static`, `struct`, `use_c`, `use`, `if`, `else`, `while`, `for`, `break`, `continue`, `ret`, `try`, `catch`, `raise`, `asm`, `macro`, `sizeof`.
- Types: `int`, `str`, `wstr`, `bool`, `void`, `char`, sized integers (`i8`..`u64`), plus user-declared struct types and pointer suffix (`T*`).
- Attributes:
  - OPSEC overrides - `[Override(Bootstrap)]`, `[Override(Resolver)]`, `[Override(NtCall)]`.
  - Aspect-oriented hooks - `[Hook("USER32$MessageBoxA")]`, `[NoHook]`, `[NoHook("Target")]` (string-literal arguments highlighted as strings).
- Namespaced calls split into "DLL" + "function" parts: `User32.MessageBoxA(...)`, `Kernel32.VirtualAlloc(...)`.
- Intrinsics highlighted as a separate scope: `mem.alloc`, `mem.copy`, `mem.collect`, `shared.get`, `shared.put`, `str.format`, `opsec.*` (legacy `gc.*` kept as a synonym).
- `str.format` placeholders (`{}`, `{d}`, `{x}`, `{X}`, `{u}`, `{s}`, `{p}`) and `{{` / `}}` escapes.
- Inline `asm { ... }` blocks - full coverage of the in-language assembler:
  - Mnemonics - `mov`, `lea`, `push`, `pop`, `add`, `sub`, `inc`, `dec`, `neg`, `xor`, `and`, `or`, `not`, `cmp`, `test`, `call`, `jmp`, the conditional-jump family (`je`/`jne`/`jz`/`jnz`/`jl`/`jg`/`jle`/`jge`/`jb`/`ja`/`jbe`/`jae`), `ret`, `nop`, `syscall`, `int3`, `cld`, `db`.
  - x86-64 GPRs + `rip` / `rflags`.
  - `%name` operand references (locals, parameters, statics, local functions) - `%` punctuation + variable scope.
  - Memory operands `[reg + idx*scale + disp]` with bracket scopes and inner register / number colouring.
  - Asm-local labels - `loop_top:` declarations highlighted as `entity.name.label`.
- C-style operators: `++`, `--`, `+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=`, `<<=`, `>>=`, `==`, `!=`, `<=`, `>=`, `&&`, `||`, `<<`, `>>`, `|`, `^`, `~`, `&`, `*`, `->`.
- `use bof;` bareword import highlights the stdlib module name; `use_c "path.h";` and `use "path.etpy";` keep the string scope.
- `//` and `/* */` comments. Hex and decimal numerics. String escapes.

## Install

Two paths, both via the bundled Python script (no Node.js needed).

### Local development install

Copies the extension into your user VS Code extensions directory. Pick this if you're iterating on the grammar.

```sh
python build.py install
```

Then reload VS Code: **Command Palette  to  "Developer: Reload Window"**.

For VS Code Insiders: `python build.py install --insiders`.

To remove: `python build.py uninstall`.
To inspect where it would go without writing: `python build.py status`.

### Build a `.vsix` for sharing

Produces a single shippable file you can hand to another operator and install via `code --install-extension`.

```sh
python build.py vsix
# wrote entropykit-0.3.0.vsix (~1.2 MB - the bulk is entc-debug.exe)

code --install-extension entropykit-0.3.0.vsix
```

The script hand-rolls the VSIX (it's a ZIP with a manifest), so you don't need `vsce` or any of the Node tooling.

## Files

```
tools/vscode-entropykit/
├── package.json                       extension manifest (language + grammar registration)
├── language-configuration.json        comments, brackets, auto-closing pairs
├── syntaxes/
│   └── entropykit.tmLanguage.json     TextMate grammar - the rules driving highlighting
├── build.py                           install / uninstall / vsix / status
└── README.md                          you are here
```

## Adding a new keyword / operator / scope

The grammar is `syntaxes/entropykit.tmLanguage.json`. Edit it, then re-run `python build.py install` and reload the VS Code window. New scopes appear immediately - no compiler restart needed.

To inspect what scope a token is getting in the editor: open `.etpy` source, then **Command Palette  to  "Developer: Inspect Editor Tokens and Scopes"**.

## Known gaps

- No semantic-token provider (it's a pure TextMate grammar). For real "go to definition", "hover", or "rename", we'd need to ship an LSP server backed by the compiler. Not worth it until the language stabilises further.
- Capitalised identifiers in type position get the type colour. Mostly correct for our Win32-derived conventions, but pure-EntropyKit code with capitalised local names will look type-like.
- The `[Override(...)]` parser detects the syntactic shape, not the slot validity - the compiler is the authority on which slot names are accepted.
