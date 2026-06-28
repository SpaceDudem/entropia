# Self-Loading BOF (`self_boot.etpy`)

A self-loading BOF runtime written in Entropia. Parses its own COFF sections from memory, walks each loaded DLL's export table, applies relocations, resolves each `__imp_*` import, and calls `go`. Bootstraps the BOF runtime without the harness's resolver.

## Usage

```bash
entc compile --type=bof self_boot.etpy --opsec=none
bof-runner tools/bof-loader/bin/self_boot.x64.o --args "echo self-booted"
```

## What it does

1. **COFF parsing** — reads its own sections (`.text`, `.rdata`, `.data`, `.bss`) from the `.obj` bytes in memory.
2. **Export table walking** — for each import: `LoadLibraryA` the DLL, walk `IMAGE_EXPORT_DIRECTORY` to find each function name.
3. **Relocation** — patches each `section_base + offset` site with the target address (REL32 / ADDR64).
4. **Entry point** — calls `go(args, len)` with the resolved imports and patched code.

## Language gaps hit

| Gap | Workaround |
| --- | --- |
| No `use bof;` — no Beacon stubs | declared `BeaconPrintf` locally as an extern fn |
| Inline asm for PE reads (no raw pointer casts) | `asm { mov rax, rcx; mov eax, [rax + 0x3C]; ... }` |
| Each section's base unknown (separate VirtualAlloc) | `section_base = args + offset` (contiguous assumption) |
| No struct initializers on array locals (`char[256] = 0`) | `var s: char[256];` then write each byte manually |
| No `{h}` hex format specifier in `str.format` | use `{x}` with explicit `0x` prefix |
| No `extern` cimport for Win32 (only for cimported `.h` files) | each Win32 function declared as `extern fn` directly |
| No generics / templates / traits | each struct typed manually |
| No `for` loop with init/cond/step | manual `while` loop with counter |
| No labels / goto / jump | structured linear flow in bootstrap function |
| `*u8` requires cast to `u64` for arithmetic | `(u64)addr + 8` not `addr + 8` |
| Dollar `$` separator only for cimport DLL prefix, not for call sites | use `DLL.FunctionName` (dot) form for calls |
