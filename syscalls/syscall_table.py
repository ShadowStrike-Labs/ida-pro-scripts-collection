# ============================================================================
#  syscall_table.py  -  IDAPython: live, build-accurate Windows syscall table
# ----------------------------------------------------------------------------
#  A Debugger-menu table that maps every x64 Windows syscall number to the
#  Nt*/Zw*/user-mode function on the machine the script is running on. The
#  numbers are parsed from the actual DLLs on this system (ntdll.dll +
#  win32u.dll, plus the WoW64 variants when present) so they match the current
#  Windows build and patch level exactly - no static tables, no web lookups,
#  no "what is 0x19 on 22H2 vs 23H2" guesswork.
#
#  WHY ON-DISK PARSING IS "LIVE"
#  Every process on this machine loads the same %SystemRoot%\System32\ntdll.dll
#  (and win32u.dll). The syscall stubs are just a few bytes each, with the
#  number baked into a `mov eax, imm32`. Reading those bytes off disk gives
#  the exact same numbers the kernel is dispatching right now.
#
#  SOURCES SCANNED  (all optional; whatever exists is used)
#    %SystemRoot%\System32\ntdll.dll       NT syscalls, x64 stubs
#    %SystemRoot%\System32\win32u.dll      win32k syscalls, x64 stubs
#    %SystemRoot%\SysWOW64\ntdll.dll       NT syscalls, WoW64 x86 stubs
#    %SystemRoot%\SysWOW64\win32u.dll      win32k, WoW64 x86 stubs
#
#  STUB PATTERNS HANDLED
#    classic x64    4C 8B D1 B8 <imm32> ...  0F 05
#    CET x64        F3 0F 1E FA 4C 8B D1 B8 <imm32> ...
#    WoW64 x86      B8 <imm32> [BA ...|64 FF 15 C0 00 00 00|...]
#    Export forwarders (Nt* -> other DLL) are skipped (no syscall number).
#
#  UI
#    Debugger -> Syscall Table...        open the chooser
#    Ctrl-Alt-S                          same, from anywhere
#  Chooser columns: Number (hex), Decimal, Function, Source. Click a header to
#  sort; type to filter; double-click a row to copy the function name to the
#  console (there is no in-DB address to jump to - these are OS symbols).
#
#  CONSOLE COMMANDS
#    show_syscalls()            open the chooser
#    syscall_lookup(0x19)       -> prints every function with that number
#    syscall_lookup("0x19")     same (string form accepted)
#    syscall_find("NtClose")    -> prints every match (substring, case-insens.)
#    refresh_syscalls()         re-parse after a Windows update
#
#  LIMITATIONS
#    * x64 Windows only (parses the x64 DLLs; WoW64 x86 stubs reference the
#      same numbers via heaven's gate, so they are cross-shown but not
#      independently decoded).
#    * Reads the DLLs on THIS machine. For a different build (e.g. a VM you
#      are analysing), copy its ntdll/win32u into a folder and call
#      refresh_syscalls(paths=[...]) with absolute paths.
# ============================================================================

import os
import struct

try:
    import ida_kernwin
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


# ---- configuration ---------------------------------------------------------
_SL_TAG = "[syscalls]"
_SL_ACTION = "shadowstrike:syscall_table"
_SL_MENU = "Debugger/"
_SL_HOTKEY = "Ctrl-Alt-S"


def _sl_default_sources():
    """Candidate DLL paths on the running system; non-existent ones are
    silently dropped by _sl_load_source()."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return [
        (os.path.join(root, "System32", "ntdll.dll"),  "ntdll (x64)"),
        (os.path.join(root, "System32", "win32u.dll"), "win32u (x64)"),
        (os.path.join(root, "SysWOW64", "ntdll.dll"),  "ntdll (WoW64)"),
        (os.path.join(root, "SysWOW64", "win32u.dll"), "win32u (WoW64)"),
    ]


# ----------------------------------------------------------------------------
# PURE helpers (unit-testable offline, no IDA imports needed)
# ----------------------------------------------------------------------------
def _sl_parse_pe_exports(data):
    """Return [(name, rva, file_offset)] for every named export of `data`
    (bytes of a PE image on disk). Forwarders are skipped. Returns [] if the
    file is not a valid PE or has no export directory."""
    if len(data) < 0x80 or data[:2] != b"MZ":
        return []
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return []
    coff = e_lfanew + 4
    num_sec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32plus = (magic == 0x20B)
    dirs_off = opt + (112 if is_pe32plus else 96)
    if dirs_off + 8 > len(data):
        return []
    exp_rva  = struct.unpack_from("<I", data, dirs_off)[0]
    exp_size = struct.unpack_from("<I", data, dirs_off + 4)[0]
    if not exp_rva or not exp_size:
        return []
    sections = []
    sec_tbl = opt + opt_size
    for i in range(num_sec):
        sh = sec_tbl + i * 40
        if sh + 40 > len(data):
            break
        vsize = struct.unpack_from("<I", data, sh + 8)[0]
        vaddr = struct.unpack_from("<I", data, sh + 12)[0]
        rsize = struct.unpack_from("<I", data, sh + 16)[0]
        rptr  = struct.unpack_from("<I", data, sh + 20)[0]
        sections.append((vaddr, max(vsize, rsize), rptr))

    def rva_to_off(rva):
        for va, sz, p in sections:
            if va <= rva < va + sz:
                return p + (rva - va)
        return None

    exp_off = rva_to_off(exp_rva)
    if exp_off is None or exp_off + 40 > len(data):
        return []
    # IMAGE_EXPORT_DIRECTORY: nfuncs @+20, nnames @+24, funcs @+28, names @+32, ords @+36
    nfuncs    = struct.unpack_from("<I", data, exp_off + 20)[0]
    nnames    = struct.unpack_from("<I", data, exp_off + 24)[0]
    funcs_rva = struct.unpack_from("<I", data, exp_off + 28)[0]
    names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
    ords_rva  = struct.unpack_from("<I", data, exp_off + 36)[0]
    funcs_off = rva_to_off(funcs_rva)
    names_off = rva_to_off(names_rva)
    ords_off  = rva_to_off(ords_rva)
    if None in (funcs_off, names_off, ords_off):
        return []

    out = []
    for i in range(nnames):
        if names_off + i * 4 + 4 > len(data):
            break
        name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
        name_off = rva_to_off(name_rva)
        if name_off is None:
            continue
        end = data.find(b"\x00", name_off, min(len(data), name_off + 256))
        if end < 0:
            continue
        try:
            name = data[name_off:end].decode("latin-1")
        except Exception:
            continue
        ordinal = struct.unpack_from("<H", data, ords_off + i * 2)[0]
        if ordinal >= nfuncs:
            continue
        func_rva = struct.unpack_from("<I", data, funcs_off + ordinal * 4)[0]
        # forwarders point inside the export directory
        if exp_rva <= func_rva < exp_rva + exp_size:
            continue
        func_off = rva_to_off(func_rva)
        if func_off is None:
            continue
        out.append((name, func_rva, func_off))
    return out


def _sl_extract_syscall(stub, is_wow64=False):
    """Extract the syscall number from an Nt*/win32u stub, or None if the bytes
    do not match any known pattern. The number is returned masked to 16 bits -
    Windows service numbers are 12-bit indices + a 1-bit table selector, so
    they always fit; WoW64 stubs put stack-cleanup byte counts in the high 16
    bits of EAX, and masking strips that noise. Handles:
      - classic x64:   4C 8B D1 B8 <imm32>
      - CET-prefixed:  F3 0F 1E FA 4C 8B D1 B8 <imm32>
      - WoW64 x86:     B8 <imm32> + heaven's-gate transition  (is_wow64=True)
    is_wow64 should be set to True only when parsing a 32-bit PE; it gates the
    WoW64 patterns so they never match x64 bytes by accident."""
    if not stub or len(stub) < 8:
        return None
    b = stub
    i = 0
    # skip Intel CET endbr64
    if b[0:4] == b"\xf3\x0f\x1e\xfa":
        i = 4
    # classic x64 stub: mov r10, rcx ; mov eax, imm32
    if b[i:i + 3] == b"\x4c\x8b\xd1" and i + 8 <= len(b) and b[i + 3] == 0xB8:
        return struct.unpack_from("<I", b, i + 4)[0] & 0xFFFF
    # WoW64 x86 stub (ONLY when the caller knows it is a 32-bit PE)
    if is_wow64 and b[i] == 0xB8 and i + 10 <= len(b):
        tail = b[i + 5:i + 20]
        is_wow64_transition = (
            tail[:1] == b"\xba"                 # mov edx, Wow64Transition
            or tail[:3] == b"\x64\xff\x15"      # call fs:[0xC0] (heaven's gate)
            or tail[:2] == b"\xff\xd2"          # call edx (after mov edx, imm)
            or (tail[:1] == b"\xe8" and len(tail) >= 8 and b"\xc2" in tail[5:8])
        )
        if is_wow64_transition:
            return struct.unpack_from("<I", b, i + 1)[0] & 0xFFFF
    return None


# ----------------------------------------------------------------------------
# source loading
# ----------------------------------------------------------------------------
def _sl_log(msg):
    print("%s %s" % (_SL_TAG, msg))


def _sl_load_source(path, label):
    """Parse one DLL from disk; return [(number, name, label)]. Reads the PE
    machine field so the extractor knows whether to apply WoW64 patterns."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except Exception:
        return []
    machine = 0
    if len(data) >= 0x40 and data[:2] == b"MZ":
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 6 <= len(data) and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    is_wow64 = (machine == 0x014C)       # IMAGE_FILE_MACHINE_I386
    out = []
    for name, _rva, off in _sl_parse_pe_exports(data):
        if not (name.startswith("Nt") or name.startswith("Zw")):
            continue
        stub = data[off:off + 32]
        num = _sl_extract_syscall(stub, is_wow64=is_wow64)
        if num is not None:
            out.append((num, name, label))
    return out


def _sl_build_table(paths=None):
    """Build the deduplicated syscall table from the given sources (default:
    this machine's ntdll + win32u, including WoW64 copies). Each real syscall
    appears exactly once; the Source column lists every DLL that exports it."""
    sources = paths if paths else _sl_default_sources()
    merged = {}          # (number, name) -> set of labels
    stats = []
    for item in sources:
        path, label = (item if isinstance(item, tuple) else (item, os.path.basename(item)))
        if not os.path.isfile(path):
            continue
        got = _sl_load_source(path, label)
        stats.append((label, len(got)))
        for num, name, lbl in got:
            merged.setdefault((num, name), set()).add(lbl)
    rows = [(num, name, ", ".join(sorted(labels)))
            for (num, name), labels in merged.items()]
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows, stats


# ----------------------------------------------------------------------------
# cache + console commands
# ----------------------------------------------------------------------------
_sl_rows = []            # [(num, name, source)]
_sl_by_num = {}          # num -> [(name, source), ...]
_sl_by_name = {}         # name.lower() -> (num, source)


def _sl_rebuild_index():
    global _sl_by_num, _sl_by_name
    _sl_by_num = {}
    _sl_by_name = {}
    for num, name, src in _sl_rows:
        _sl_by_num.setdefault(num, []).append((name, src))
        _sl_by_name[name.lower()] = (num, src)


def _sl_ensure_loaded():
    """Lazy-load so script import is fast even on cold boots."""
    if _sl_rows:
        return True
    return refresh_syscalls()


def refresh_syscalls(paths=None):
    """(Re)parse the system DLLs and rebuild the index. Optionally pass a list
    of explicit DLL paths (useful to analyse another machine's binaries by
    pointing at its copies)."""
    global _sl_rows
    rows, stats = _sl_build_table(paths)
    _sl_rows = rows
    _sl_rebuild_index()
    if stats:
        parts = ", ".join("%s=%d" % (lbl, n) for lbl, n in stats)
        _sl_log("loaded %d syscall(s)  [%s]" % (len(_sl_rows), parts))
    else:
        _sl_log("no source DLLs found; set paths=[...] to point at them.")
    return bool(_sl_rows)


def _sl_coerce_num(v):
    if isinstance(v, int):
        return v
    s = str(v).strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return int(s, 16)


def syscall_lookup(n):
    """Print every function whose syscall number equals `n` (int or '0x19')."""
    _sl_ensure_loaded()
    try:
        num = _sl_coerce_num(n)
    except Exception as e:
        _sl_log("could not parse %r as a number: %s" % (n, e))
        return []
    hits = _sl_by_num.get(num, [])
    if not hits:
        _sl_log("no match for %#x (%d) on this build." % (num, num))
        return []
    _sl_log("%#x (%d):" % (num, num))
    for name, src in hits:
        print("  %-48s  [%s]" % (name, src))
    return hits


def syscall_find(substr):
    """Print every function whose name contains `substr` (case-insensitive)."""
    _sl_ensure_loaded()
    needle = str(substr).lower()
    hits = [(num, name, src) for (num, name, src) in _sl_rows
            if needle in name.lower()]
    if not hits:
        _sl_log("no match for %r on this build." % substr)
        return []
    _sl_log("%d match(es) for %r:" % (len(hits), substr))
    for num, name, src in hits:
        print("  %#06x  %-48s  [%s]" % (num, name, src))
    return hits


# ----------------------------------------------------------------------------
# chooser UI
# ----------------------------------------------------------------------------
if _IN_IDA:

    class _SyscallChooser(ida_kernwin.Choose):
        def __init__(self, rows):
            cols = [
                ["Number",   10 | ida_kernwin.Choose.CHCOL_HEX],
                ["Decimal",   8 | ida_kernwin.Choose.CHCOL_DEC],
                ["Function", 48 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Source",   20 | ida_kernwin.Choose.CHCOL_PLAIN],
            ]
            ida_kernwin.Choose.__init__(
                self, "Syscall Table (live, this machine)", cols,
                flags=ida_kernwin.Choose.CH_RESTORE
                      | ida_kernwin.Choose.CH_CAN_REFRESH)
            self.rows = rows
            self.items = [self._fmt(r) for r in rows]
            self.icon = -1

        @staticmethod
        def _fmt(r):
            num, name, src = r
            return ["%#06x" % num, str(num), name, src]

        def OnGetSize(self):
            return len(self.items)

        def OnGetLine(self, n):
            return self.items[n]

        def OnSelectLine(self, n):
            # Double-click: echo the selection to the console (no in-DB EA).
            idx = n[0] if isinstance(n, (list, tuple)) else n
            if idx is not None and 0 <= idx < len(self.rows):
                num, name, src = self.rows[idx]
                _sl_log("%#06x -> %s  [%s]" % (num, name, src))
            nc = getattr(ida_kernwin.Choose, "NOTHING_CHANGED", None)
            return (nc,) if nc is not None else None

        def OnRefresh(self, n):
            refresh_syscalls()
            self.rows = list(_sl_rows)
            self.items = [self._fmt(r) for r in self.rows]
            return None

    _sl_chooser = None

    def show_syscalls():
        """Open the Syscall Table chooser (reparses on first call)."""
        global _sl_chooser
        _sl_ensure_loaded()
        _sl_chooser = _SyscallChooser(list(_sl_rows))
        _sl_chooser.Show()
        return _sl_chooser

    # ------------------------------------------------------------------------
    # Debugger-menu action
    # ------------------------------------------------------------------------
    class _ShowSyscallsAction(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            show_syscalls()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    _sl_hk_ctx = None

    def _sl_bootstrap():
        global _sl_hk_ctx
        try:
            ida_kernwin.unregister_action(_SL_ACTION)
        except Exception:
            pass
        desc = ida_kernwin.action_desc_t(
            _SL_ACTION,
            "Syscall Table...",
            _ShowSyscallsAction(),
            _SL_HOTKEY,
            "Show the live Windows syscall table parsed from this machine's "
            "ntdll/win32u",
            -1,
        )
        if ida_kernwin.register_action(desc):
            ok = ida_kernwin.attach_action_to_menu(
                _SL_MENU, _SL_ACTION,
                getattr(ida_kernwin, "SETMENU_APP", 0))
            if ok:
                _sl_log("menu: Debugger -> Syscall Table...")
            else:
                _sl_log("could not attach menu entry; use show_syscalls()")
        else:
            _sl_log("could not register action; use show_syscalls()")
        # best-effort direct hotkey too, in case the action's shortcut is taken
        try:
            _sl_hk_ctx = ida_kernwin.add_hotkey(_SL_HOTKEY, show_syscalls)
        except Exception:
            pass
        _sl_log("ready. show_syscalls() opens the table (Ctrl-Alt-S); "
                "syscall_lookup(0x19) and syscall_find('NtClose') from the "
                "console; refresh_syscalls() after a Windows update.")

    _sl_bootstrap()
