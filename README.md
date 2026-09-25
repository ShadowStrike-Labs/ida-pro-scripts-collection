# IDA Pro Scripts

A small, focused collection of IDAPython tools for reverse-engineering Windows
PE binaries - unpacking, dumping, debugger automation, and in-function
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
├── integrity/
│   └── iat_hooks.py                 # detect IAT hooks vs the real (live) exports
├── disasm/
│   └── xdisasm.py                   # annotate a range as x86/x64 (Heaven's Gate)
├── strings/
│   └── author_strings.py            # isolate author-written strings from library noise
├── debugging/
│   ├── auto_tailjump.py             # peel packer/VM layers + instrument handlers
│   └── pass_exceptions.py           # pass all debugger exceptions to the app
├── loaders/
│   └── dll_loader_stub_generator.py # build a minimal EXE that loads a DLL with LoadLibrary
├── notes/
│   └── vm_handlers.txt              # analysis notes / scratch data
└── logs/                            # runtime logs (gitignored)
```

## How to run a script in IDA

* **File → Script file… (Alt+F7)** and pick the `.py`, or
* paste it into the **Output window** console, or
* add the folder to your `idapythonrc.py` if you want them always loaded.

Each script prints a one-line "ready" banner listing its commands and binds its
hotkeys on load.

## Contributing

Have an IDAPython script that could be useful for reverse engineering or
malware analysis? Feel free to contribute it.

Scripts for unpacking, debugging, dumping, scanning, deobfuscation,
navigation, analysis, and other useful IDA workflows are welcome.

Please keep contributions focused, documented, and compatible with the
supported IDA/IDAPython versions where possible.

Pull requests are welcome.

## Requirements

* IDA Pro 7.x / 8.x / 9.x with IDAPython 3.
* The debugger-oriented scripts (`auto_tailjump.py`, `pass_exceptions.py`) need
  an active debugging session; the rest work statically.

