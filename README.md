# IDA Pro Scripts

A small, focused collection of IDAPython tools for reverse-engineering Windows
PE binaries — unpacking, dumping, debugger automation, and in-function
navigation. Everything here is designed to run inside IDA (7.x / 8.x / 9.x,
IDAPython 3) and to stay out of your way: sensible defaults, a config block at
the top of every script, and hotkeys for the things you do a hundred times a
day.

> Intended for analysis of software you own or are authorized to examine
> (malware research, CTFs, your own binaries). Use responsibly.

## Layout

```
IDA_PRO_SCRIPTS/
├── dumping/
│   └── pe_dumper.py                 # carve a full PE out of memory -> .exe/.dll/.sys
├── navigation/
│   └── function_conditions.py       # map every condition in the current function
├── scanning/
│   └── segment_scanner.py           # hunt PE/code/magic signatures in chosen segments
├── debugging/
│   ├── auto_tailjump.py             # peel packer/VM layers + instrument handlers
│   └── pass_exceptions.py           # pass all debugger exceptions to the app
├── loaders/
│   └── dll_loader_stub_generator.py # build a minimal EXE that LoadLibrary's a DLL
├── notes/
│   └── vm_handlers.txt              # analysis notes / scratch data
└── logs/                            # runtime logs (gitignored)
```

## How to run a script in IDA

- **File → Script file… (Alt+F7)** and pick the `.py`, or
- paste it into the **Output window** console, or
- add the folder to your `idapythonrc.py` if you want them always loaded.

Each script prints a one-line "ready" banner listing its commands and binds its
hotkeys on load.

---

## dumping/pe_dumper.py

Point it at an address whose first bytes are the `MZ` signature (`4D 5A ...`)
— a decrypted/unpacked payload, an embedded PE, a manually-mapped module — and
it reconstructs the whole PE to a file **next to the analyzed input**.

What it does:

- Parses DOS + PE + optional headers straight from memory (PE32 and PE32+).
- Computes the size **by itself**: `SizeOfImage` for a mapped image, or
  `max(PointerToRawData + SizeOfRawData)` for a raw on-disk image sitting in
  memory. A bogus `SizeOfImage` is recomputed from the section table.
- Reads the region gap-tolerantly: unreadable pages are zero-filled and
  counted, so one unmapped page never aborts the dump.
- **Virtual mode** repoints the section table so the mapped image is valid on
  disk (`PointerToRawData ← VirtualAddress`, `SizeOfRawData ← aligned
  VirtualSize`). **Raw mode** writes bytes verbatim. **Auto** picks one and
  tells you why.
- Chooses the extension from the headers: `.sys` (native/driver), `.dll`
  (DLL characteristic), else `.exe`.
- **Optionally rebuilds the import table** (`fix_imports=True`) — resolves each
  IAT pointer against the modules mapped in the live debug session, synthesizes
  a fresh import directory and appends it as a new section. This is the
  pe-sieve `/imp` equivalent, aimed squarely at the "that region was never
  packed, so pe-sieve saw no change and skipped it" case.

Commands:

| Command | Purpose |
|---|---|
| `dump_pe()` | Dump the PE at the cursor (auto layout detect) |
| `dump_pe(0x140000000)` | Dump the PE at an explicit base |
| `dump_pe(ea, mode="raw")` | Force raw / on-disk layout |
| `dump_pe(ea, mode="virtual")` | Force mapped → file reconstruction |
| `dump_pe(ea, ext=".sys")` | Force the output extension |
| `dump_pe_prompt()` | Ask for the address in a dialog |
| `scan_for_pe()` | List every MZ/PE candidate in the address space |
| `dump_all_pe()` | Dump every candidate found |
| `pe_info(ea)` | Print the header summary only |
| `dump_pe(ea, fix_imports=True)` | Dump **and rebuild the import table** (needs a live debugger) |
| `dump_pe(ea, oep=0x…)` | Override the entry point on the way out |
| `list_imports(ea)` | Resolve and print the IAT, write nothing |
| `rebuild_imports_in_file(path)` | Add imports to a file you already dumped |
| `save_region(ea, size)` | Raw blob dump, no PE parsing |

**Hotkey:** `Ctrl-Alt-D` → `dump_pe()` at the cursor.

> Import reconstruction is **opt-in** (`fix_imports=True`) and needs a live
> debug session, since it reads the dependent modules' export tables straight
> from memory. Without it the dump still opens cleanly in IDA / PE-bear / CFF
> for static work. If the blind IAT scan misses the table, pin it: run
> `list_imports(ea)` to eyeball it, then
> `dump_pe(ea, fix_imports=True, iat_rva=…, iat_size=…)`. Scylla / pe-sieve
> remain perfectly good alternatives.

---

## navigation/function_conditions.py

Put the cursor anywhere inside a function and get an address-by-address map of
every decision it makes — **without ever leaving the function**. It iterates
the function's own instruction items (all chunks, tail chunks included), so
unlike *Alt-T* / jump-to-xref it cannot leak into a neighbouring function.

For every conditional jump, `SETcc`, `CMOVcc` and `LOOP` you get:

- the exact address (double-click a row to jump),
- the mnemonic + full disassembly,
- a plain-English meaning (`je → "== (ZF=1)"`, `jg → "signed >"`, …),
- signed vs unsigned,
- the branch target and whether it stays **in-function** or is flagged
  `<< EXTERNAL >>` (the tail-calls that make Alt-T lie),
- the fall-through address,
- the instruction that **set the flags** this branch reads (the feeding
  `cmp`/`test`/arith, found by walking back within the basic block).

Commands:

| Command | Purpose |
|---|---|
| `conditions()` | Analyze the function at the cursor, open a jump-list |
| `conditions(0x401000)` | Analyze a specific function |
| `conditions_text()` | Same analysis as copy-paste text |
| `nc()` / `next_condition()` | Jump to the next conditional branch (in-function) |
| `pc()` / `prev_condition()` | Jump to the previous conditional branch |
| `goto_condition(3)` | Jump to the Nth condition from the last listing |
| `color_conditions()` / `uncolor_conditions()` | Tint / clear branch lines |

**Hotkeys:** `Ctrl-Alt-C` open the list · `Ctrl-Alt-N` next branch ·
`Ctrl-Alt-B` previous branch.

---

## scanning/segment_scanner.py

A **targeted** signature scanner — *you* choose which segments to look in, and
it reports every hit with an exact address you can double-click. Built for the
"pe-sieve won't see it and I don't want to sweep the whole address space" case,
and for spotting code hidden where it shouldn't be.

Three toggleable categories:

- **pe** — `MZ` headers, validated into `valid PE (arch/type/SizeOfImage)` vs
  `MZ (no PE header)`. These feed straight into `pe_dumper`.
- **code** — x86-64 function-prologue fingerprints (`sub rsp`, `mov [rsp],reg`,
  `push rbp; mov rbp,rsp`, …). Heuristic by nature.
- **magic** — other embedded payloads (ELF, ZIP, GZIP, PDF, PNG, 7z, CAB, OLE2,
  bzip2, …).

**Non-exec code alert:** a `code` signature found in a **non-executable**
segment (code stashed in `.rdata` / `.data` for a later trampoline or manual
map) is flagged `<< code in NON-EXEC segment >>` and tinted red — the
"analyst assumes read-only means no code" trick, surfaced.

Commands:

| Command | Purpose |
|---|---|
| `segs()` / `list_segments()` | List every segment (name, range, size, perms) |
| `scan()` | Scan the segment under the cursor |
| `scan(".rdata", ".data", ".grfn10")` | Scan just those segments |
| `scan("all")` | Scan every segment |
| `scan(0x7FF706180000)` | Scan the segment containing an address |
| `scan(".rdata", cats=("pe","code","magic"))` | Choose categories |
| `scan_code(...)` / `scan_magic(...)` | Shortcuts (pe+code / pe+magic) |
| `scan_exec()` | Only executable segments |
| `scan_range(lo, hi)` | Arbitrary `[lo, hi)` range |
| `rescan()` | Repeat the last scan |
| `dump(n)` | Dump hit `#n` via `pe_dumper.dump_pe` (if loaded) |
| `goto_hit(n)` | Jump to hit `#n` from the last listing |

**Hotkey:** `Ctrl-Alt-S` → `scan()` on the segment under the cursor.

> Pairs with the dumper: `scan(".rdata")` to find an MZ, then `dump(n)` (or
> `dump_pe(ea)`) to carve it. Names are case-insensitive and the leading dot is
> optional (`scan("rdata")` works).

---

## debugging/auto_tailjump.py

Automates and instruments layer-peeling in threaded-code / VM packers: from a
handler it runs to the function end, steps to the terminating indirect branch
(`jmp reg`), steps into the next handler, and records per layer the terminating
branch, call targets, conditionals and instruction count — then summarizes
which layers had calls / conditionals / API calls. That is where the VM's
branch, I/O and exit live.

- `tailjump_once()` — one layer (**hotkey `Ctrl-Alt-J`**)
- `tailjump(n)` — peel `n` layers with a progress/cancel box
- Toggle options from the console with `opts()` — e.g. `opts(REG_SNAPSHOT=True)`,
  `opts(STOP_AT_HANDLER="7FF706181C20")`, or the shortcuts `reg_snapshot()`,
  `log_anatomy()`, `log_to_file()`, `stop_at(addr)`. `opts()` on its own lists
  every switch with its meaning. **They are options, not arguments to
  `tailjump()`** — `tailjump(400) REG_SNAPSHOT` is a syntax error; do
  `opts(REG_SNAPSHOT=True); tailjump(400)`. Log path is `logs/tailjump_log.txt`.

## debugging/pass_exceptions.py

Stops the tedious *Debugger options → Edit exceptions* dance: every exception
is set to "pass to the application" without breaking, and the pop-ups are
disabled.

- `pass_all_exceptions()` (**hotkey `Ctrl-Alt-P`**), `pass_code("C0000005")`,
  `break_code(...)`, `pass_range("Range:0-FFFFFFFF")`, `list_exceptions()`,
  `install_addr_range_autopass(lo, hi)`.
- Zero-count tolerant matching: `0xC0000005`, `c0000005`, even `C000005`
  resolve to the same exception.

## loaders/dll_loader_stub_generator.py

Generates a minimal, dependency-free 64-bit EXE that `LoadLibraryW`'s the DLL
currently open in IDA and then `Sleep(INFINITE)`, so you can debug a DLL
through the normal Windows loader (including self-unpacking DllMain/TLS
samples) without `rundll32` or guessing an ordinal.

- `generate_loader_for_current_dll()` writes `<dllname>_<random>.exe` next to
  the DLL and best-effort configures the Windows debugger.
- Also runnable standalone for self-testing:
  `python dll_loader_stub_generator.py <dll_path> <output_exe>`.

---

## Requirements

- IDA Pro 7.x / 8.x / 9.x with IDAPython 3.
- The debugger-oriented scripts (`auto_tailjump.py`, `pass_exceptions.py`) need
  an active debugging session; the rest work statically.

## License

MIT — see `LICENSE` (add one before publishing if you want it explicit).
