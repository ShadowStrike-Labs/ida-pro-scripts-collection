# ============================================================================
#  iat_hooks.py - detect Import Address Table (IAT) hooks
# ----------------------------------------------------------------------------
#  For every entry in a module's IAT this compares the pointer that is actually
#  stored there (live, at runtime) against the real address of that export as
#  resolved from the currently loaded modules. A mismatch is a redirection - an
#  IAT hook - and is reported with the function that is hooked and the address
#  it now points to instead of the genuine API.
#
#  Trust model (why this does not drown you in false positives)
#    * Forwarded exports are followed to their final target (e.g. kernel32!
#      HeapAlloc -> ntdll!RtlAllocateHeap), so a forwarded import is not
#      mistaken for a hook.
#    * API-set stubs (api-ms-win-*.dll) are resolved by matching the export
#      name across every loaded module, so imports that bind to the host DLL
#      (kernelbase, ...) read as clean.
#    * Ordinal-only imports are resolved through the owning DLL's ordinal table.
#    * The target of every mismatch is located: another module (name + offset,
#      nearest export), the owning DLL itself, or private/unbacked memory - the
#      last being the strongest indicator of a trampoline or shellcode.
#
#  This is a runtime check. The IAT only holds resolved pointers once the loader
#  has run, so it must be used during an active debugging session (or on a
#  memory image loaded as the database).
#
#  Console interface
#    scan_iat_hooks(module=None)      scan a module's IAT (default: the analyzed
#                                     module); opens a jump-list of findings
#    iat_report(module=None, all=False)   text report (all=True lists clean too)
#    check_import("kernel32.dll", "CreateFileW")   inspect a single import
#    scan_all_modules()               scan the IAT of every loaded module
#    scan_inline_hooks(module=None)   bonus: detect prologue detours on the APIs
#                                     this module imports (heuristic)
#    list_modules()                   loaded modules (base / size / name)
#
#    `module` accepts a name, an ea (int) or a hex string.
#
#  Hotkey
#    Ctrl-Alt-H   scan_iat_hooks() on the analyzed module
# ============================================================================

import bisect
from collections import defaultdict

import ida_bytes
import ida_nalt
import ida_kernwin
import idc
import idautils
import idaapi

try:
    import ida_dbg
except Exception:                       # pragma: no cover
    ida_dbg = None
try:
    import ida_ida
except Exception:                       # pragma: no cover
    ida_ida = None

_IH_TAG = "[iathook]"

# verdict -> (label, BGR line colour, description). "flagged" verdicts are the
# ones surfaced by default.
_IH_META = {
    "HOOK_PRIVATE": ("HOOK", 0xC0C0FF, "target is private/unbacked memory (trampoline/shellcode)"),
    "HOOK_FOREIGN": ("HOOK", 0xC0C0FF, "redirected into a different module"),
    "REDIRECT":     ("REDIRECT", 0xC0E0FF, "points to a same-named export in another module"),
    "SUSPECT":      ("SUSPECT", 0xC0E0FF, "inside the owning DLL but not at the expected export"),
    "UNBOUND":      ("unbound", 0xE8E8E8, "slot is 0 (unresolved / delay import not yet called)"),
    "UNREADABLE":   ("unread", 0xE8E8E8, "could not read the slot"),
    "CLEAN":        ("clean", 0xC0FFC0, "points to the expected export"),
    "CLEAN_APISET": ("clean", 0xC0FFC0, "resolved via API set / forwarder"),
}
_IH_FLAGGED = ("HOOK_PRIVATE", "HOOK_FOREIGN", "REDIRECT", "SUSPECT")


# ----------------------------------------------------------------------------
# low-level helpers
# ----------------------------------------------------------------------------
def _ih_log(msg):
    print("%s %s" % (_IH_TAG, msg))


def _ih_basename(path):
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1]


def _ih_norm(name):
    return _ih_basename(name).lower()


def _ih_ptrsize():
    fn = getattr(ida_ida, "inf_get_app_bitness", None) if ida_ida else None
    if fn is not None:
        try:
            return 8 if fn() == 64 else 4
        except Exception:
            pass
    try:
        return 8 if idaapi.get_inf_structure().is_64bit() else 4
    except Exception:
        return 8


def _ih_rd(mem, ea, size):
    b = mem(ea, size)
    return b if (b and len(b) == size) else None


def _ih_u16(b, off):
    return b[off] | (b[off + 1] << 8) if off + 2 <= len(b) else 0


def _ih_u32(b, off):
    if off + 4 > len(b):
        return 0
    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)


def _ih_ptr(ea, ps, mem):
    b = mem(ea, ps)
    if not b or len(b) != ps:
        return None
    return int.from_bytes(b, "little")


def _ih_cstr(mem, ea, limit=512):
    out = bytearray()
    got = 0
    while got < limit:
        chunk = mem(ea + got, 32)
        if not chunk:
            break
        for ch in bytearray(chunk):
            if ch == 0:
                return out.decode("latin-1", "replace")
            out.append(ch)
        got += 32
    return out.decode("latin-1", "replace")


def _ih_modules():
    out = []
    try:
        for m in idautils.Modules():
            out.append({"name": _ih_norm(m.name), "path": m.name,
                        "base": m.base, "size": m.size or 0})
    except Exception as exc:
        _ih_log("module enumeration failed: %s" % exc)
    return out


def _ih_module_of(modules, ea):
    if ea is None:
        return None
    for m in modules:
        if m["base"] <= ea < m["base"] + m["size"]:
            return m
    return None


# ----------------------------------------------------------------------------
# export tables (pure: driven by a mem(ea,size)->bytes reader)
# ----------------------------------------------------------------------------
def _ih_export_raw(base, mem):
    """Return {'by_name': {name: rva|fwd}, 'by_ord': {ord: rva|fwd}} for a module
    at `base`. A value is an int RVA, or a forwarder string 'Dll.Func'."""
    dos = _ih_rd(mem, base, 0x40)
    if not dos or dos[:2] != b"MZ":
        return None
    e = _ih_u32(dos, 0x3C)
    pe = _ih_rd(mem, base + e, 0x108)
    if not pe or pe[0:4] != b"PE\x00\x00":
        return None
    magic = _ih_u16(pe, 24)
    dd = 24 + (112 if magic == 0x20B else 96)
    exp_rva = _ih_u32(pe, dd)
    exp_size = _ih_u32(pe, dd + 4)
    empty = {"by_name": {}, "by_ord": {}}
    if not exp_rva:
        return empty
    ed = _ih_rd(mem, base + exp_rva, 40)
    if not ed:
        return empty
    ord_base = _ih_u32(ed, 16)
    nfun = _ih_u32(ed, 20)
    nnam = _ih_u32(ed, 24)
    a_fun = _ih_u32(ed, 28)
    a_nam = _ih_u32(ed, 32)
    a_ord = _ih_u32(ed, 36)
    if nfun > 0x20000 or nnam > 0x20000:
        return empty
    eat = _ih_rd(mem, base + a_fun, nfun * 4) or b""
    names = (_ih_rd(mem, base + a_nam, nnam * 4) if a_nam else b"") or b""
    ords = (_ih_rd(mem, base + a_ord, nnam * 2) if a_ord else b"") or b""
    idx_name = {}
    for k in range(nnam):
        if (k + 1) * 4 > len(names) or (k + 1) * 2 > len(ords):
            break
        idx_name[_ih_u16(ords, k * 2)] = _ih_cstr(mem, base + _ih_u32(names, k * 4))
    by_name, by_ord = {}, {}
    lo, hi = exp_rva, exp_rva + exp_size
    for i in range(nfun):
        if (i + 1) * 4 > len(eat):
            break
        frva = _ih_u32(eat, i * 4)
        if not frva:
            continue
        val = _ih_cstr(mem, base + frva) if lo <= frva < hi else frva
        by_ord[ord_base + i] = val
        nm = idx_name.get(i)
        if nm:
            by_name[nm] = val
    return {"by_name": by_name, "by_ord": by_ord}


def _ih_find_mod(modmap, dllname):
    n = _ih_norm(dllname)
    if n in modmap:
        return n
    if not n.endswith(".dll") and (n + ".dll") in modmap:
        return n + ".dll"
    stem = n.rsplit(".", 1)[0]
    if stem in modmap:
        return stem
    if (stem + ".dll") in modmap:
        return stem + ".dll"
    return None


def _ih_resolve_value(modmap, modname, value, depth=0):
    """Resolve an export value (int RVA or 'Dll.Func' forwarder) to a final VA."""
    if depth > 16:
        return None
    if isinstance(value, int):
        entry = modmap.get(modname)
        return entry["base"] + value if entry else None
    if "." not in value:
        return None
    dll, fn = value.split(".", 1)
    key = _ih_find_mod(modmap, dll)
    if key is None:
        return None
    raw = modmap[key]["raw"]
    if fn.startswith("#"):
        try:
            nxt = raw["by_ord"].get(int(fn[1:]))
        except ValueError:
            return None
    else:
        nxt = raw["by_name"].get(fn)
    if nxt is None:
        return None
    return _ih_resolve_value(modmap, key, nxt, depth + 1)


def _ih_build_index(modules, mem):
    """Parse every module's exports, resolve forwarders, and return
    (modmap, name_to_addrs, addr_to_name, mod_sorted)."""
    modmap = {}
    for m in modules:
        raw = _ih_export_raw(m["base"], mem)
        if raw is None:
            continue
        modmap[m["name"]] = {"base": m["base"], "size": m["size"], "raw": raw}
    name_to_addrs = defaultdict(set)
    addr_to_name = {}
    mod_sorted = defaultdict(list)
    for modname, e in modmap.items():
        raw = e["raw"]
        for nm, val in raw["by_name"].items():
            a = _ih_resolve_value(modmap, modname, val)
            if a is not None:
                name_to_addrs[nm].add(a)
                addr_to_name.setdefault(a, "%s!%s" % (modname, nm))
                mod_sorted[modname].append((a, nm))
        for ordv, val in raw["by_ord"].items():
            a = _ih_resolve_value(modmap, modname, val)
            if a is not None:
                addr_to_name.setdefault(a, "%s!#%d" % (modname, ordv))
                mod_sorted[modname].append((a, "#%d" % ordv))
    for k in list(mod_sorted):
        mod_sorted[k] = sorted(set(mod_sorted[k]))
    return modmap, name_to_addrs, addr_to_name, mod_sorted


def _ih_expected(modmap, name_to_addrs, dll, name, ordinal):
    """Return (strict, broad) address sets for an import.
    strict = resolution through the named DLL; broad = any module exporting the
    name (covers API sets / forwarders / multiple exporters)."""
    strict = set()
    key = _ih_find_mod(modmap, dll) if dll else None
    if key:
        raw = modmap[key]["raw"]
        if name and name in raw["by_name"]:
            a = _ih_resolve_value(modmap, key, raw["by_name"][name])
            if a is not None:
                strict.add(a)
        if (not name) and ordinal and ordinal in raw["by_ord"]:
            a = _ih_resolve_value(modmap, key, raw["by_ord"][ordinal])
            if a is not None:
                strict.add(a)
    broad = set(name_to_addrs.get(name, ())) if name else set()
    broad |= strict
    return strict, broad


def _ih_describe(actual, modules, addr_to_name, mod_sorted):
    if actual is None:
        return ""
    if actual in addr_to_name:
        return addr_to_name[actual]
    m = _ih_module_of(modules, actual)
    if m is None:
        return "PRIVATE/unbacked memory"
    lst = mod_sorted.get(m["name"])
    if lst:
        i = bisect.bisect_right(lst, (actual, "\uffff")) - 1
        if i >= 0:
            a, fn = lst[i]
            return "%s!%s+0x%X" % (m["name"], fn, actual - a)
    return "%s+0x%X" % (m["name"], actual - m["base"])


def _ih_classify(actual, dll, name, ordinal, modmap, name_to_addrs, modules,
                 addr_to_name, mod_sorted):
    strict, broad = _ih_expected(modmap, name_to_addrs, dll, name, ordinal)
    det = {"strict": sorted(strict), "broad": sorted(broad), "actual": actual,
           "target": _ih_describe(actual, modules, addr_to_name, mod_sorted)}
    if actual is None:
        return "UNREADABLE", det
    if actual == 0:
        return "UNBOUND", det
    if actual in strict:
        return "CLEAN", det
    if actual in broad:
        return ("CLEAN_APISET" if not strict else "REDIRECT"), det
    owner = _ih_module_of(modules, actual)
    if owner is None:
        return "HOOK_PRIVATE", det
    if _ih_norm(owner["name"]) == _ih_norm(dll):
        return "SUSPECT", det
    return "HOOK_FOREIGN", det


# ----------------------------------------------------------------------------
# import enumeration
# ----------------------------------------------------------------------------
def _ih_imports_ida():
    """Imports of the analyzed module, via IDA's own parse (authoritative and
    survives an erased in-memory import directory)."""
    out = []
    for i in range(ida_nalt.get_import_module_qty()):
        dll = ida_nalt.get_import_module_name(i) or "?"
        acc = []

        def cb(ea, name, ordinal, _acc=acc):
            _acc.append((ea, name, ordinal))
            return True

        ida_nalt.enum_import_names(i, cb)
        for ea, name, ordinal in acc:
            out.append({"dll": dll, "name": name or None,
                        "ordinal": ordinal or 0, "slot": ea, "delay": False})
    return out


def _ih_imports_mem(base, mem, ps, delay=True):
    """Imports of any module, parsed from its in-memory PE directories."""
    dos = _ih_rd(mem, base, 0x40)
    if not dos or dos[:2] != b"MZ":
        return []
    e = _ih_u32(dos, 0x3C)
    pe = _ih_rd(mem, base + e, 0x108)
    if not pe or pe[0:4] != b"PE\x00\x00":
        return []
    magic = _ih_u16(pe, 24)
    dd = 24 + (112 if magic == 0x20B else 96)
    imp_rva = _ih_u32(pe, dd + 1 * 8)
    delay_rva = _ih_u32(pe, dd + 13 * 8)
    ord_flag = 1 << (ps * 8 - 1)
    out = []

    def walk(dll, ilt_rva, iat_rva, have_names, is_delay):
        i = 0
        while True:
            te = _ih_rd(mem, base + ilt_rva + i * ps, ps)
            if not te:
                break
            val = int.from_bytes(te, "little")
            if val == 0:
                break
            slot = base + iat_rva + i * ps
            if val & ord_flag:
                out.append({"dll": dll, "name": None, "ordinal": val & 0xFFFF,
                            "slot": slot, "delay": is_delay})
            elif have_names:
                out.append({"dll": dll, "name": _ih_cstr(mem, base + val + 2),
                            "ordinal": 0, "slot": slot, "delay": is_delay})
            else:
                out.append({"dll": dll, "name": None, "ordinal": 0,
                            "slot": slot, "delay": is_delay})
            i += 1

    off = 0
    while imp_rva:
        d = _ih_rd(mem, base + imp_rva + off, 20)
        if not d:
            break
        oft = _ih_u32(d, 0)
        name_rva = _ih_u32(d, 12)
        ft = _ih_u32(d, 16)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        walk(_ih_cstr(mem, base + name_rva), oft if oft else ft, ft, oft != 0, False)
        off += 20

    off = 0
    while delay and delay_rva:
        d = _ih_rd(mem, base + delay_rva + off, 32)
        if not d:
            break
        dll_rva = _ih_u32(d, 4)
        iat_rva = _ih_u32(d, 12)
        int_rva = _ih_u32(d, 16)
        if dll_rva == 0 and iat_rva == 0:
            break
        if int_rva:
            walk(_ih_cstr(mem, base + dll_rva), int_rva, iat_rva, True, True)
        off += 32
    return out


# ----------------------------------------------------------------------------
# target resolution
# ----------------------------------------------------------------------------
def _ih_target(module):
    abase = idaapi.get_imagebase()
    aname = _ih_norm(ida_nalt.get_input_file_path() or "")
    if module is None:
        return "analyzed", abase, aname
    mods = _ih_modules()
    if isinstance(module, int):
        m = _ih_module_of(mods, module)
        return (("analyzed" if m and m["base"] == abase else "mem"),
                (m["base"] if m else module), (m["name"] if m else ""))
    s = str(module).strip()
    try:
        v = int(s.replace("0x", ""), 16)
        m = _ih_module_of(mods, v)
        return (("analyzed" if m and m["base"] == abase else "mem"),
                (m["base"] if m else v), (m["name"] if m else ""))
    except ValueError:
        pass
    for m in mods:
        if m["name"] == _ih_norm(s):
            return ("analyzed" if m["base"] == abase else "mem"), m["base"], m["name"]
    return "mem", None, _ih_norm(s)


def _ih_collect(module=None, delay=True):
    """Resolve the target module, build the export index, enumerate its imports
    and classify each one. Returns (name, findings)."""
    kind, base, name = _ih_target(module)
    if base is None:
        _ih_log("could not resolve target module %r (see list_modules())" % (module,))
        return name, []
    if ida_dbg is not None and not ida_dbg.is_debugger_on():
        _ih_log("WARNING: no active debug session - the IAT is not resolved "
                "statically, so results are only meaningful on a live process "
                "or a memory image.")
    mem = ida_bytes.get_bytes
    ps = _ih_ptrsize()
    modules = _ih_modules()
    modmap, n2a, a2n, msorted = _ih_build_index(modules, mem)
    imports = _ih_imports_ida() if kind == "analyzed" else _ih_imports_mem(base, mem, ps, delay)
    if not delay:
        imports = [i for i in imports if not i.get("delay")]
    findings = []
    for imp in imports:
        actual = _ih_ptr(imp["slot"], ps, mem)
        verdict, det = _ih_classify(actual, imp["dll"], imp["name"],
                                    imp["ordinal"], modmap, n2a, modules, a2n, msorted)
        findings.append({
            "verdict": verdict, "dll": imp["dll"],
            "func": imp["name"] or ("#%d" % imp["ordinal"]),
            "slot": imp["slot"], "actual": actual, "delay": imp.get("delay", False),
            "expected": det["strict"] or det["broad"], "target": det["target"],
            "flagged": verdict in _IH_FLAGGED,
        })
    return name, findings


# ----------------------------------------------------------------------------
# reporting + chooser
# ----------------------------------------------------------------------------
def _ih_expected_str(f):
    exp = f["expected"]
    if not exp:
        return "-"
    return ",".join("%X" % a for a in exp[:3]) + ("..." if len(exp) > 3 else "")


def _ih_summary(name, findings):
    counts = defaultdict(int)
    for f in findings:
        counts[f["verdict"]] += 1
    flagged = [f for f in findings if f["flagged"]]
    _ih_log("module %s: %d imports  |  %d clean  |  %d flagged"
            % (name, len(findings),
               counts["CLEAN"] + counts["CLEAN_APISET"], len(flagged)))
    for v in _IH_FLAGGED + ("UNBOUND", "UNREADABLE"):
        if counts.get(v):
            _ih_log("   %-12s %d   (%s)" % (_IH_META[v][0], counts[v], _IH_META[v][2]))
    return flagged


class _IHChooser(ida_kernwin.Choose):
    def __init__(self, title, rows):
        cols = [["Verdict", 10], ["DLL", 16], ["Function", 28],
                ["Slot", ida_kernwin.Choose.CHCOL_HEX | 16],
                ["Actual", ida_kernwin.Choose.CHCOL_HEX | 16],
                ["Expected", 20], ["Target", 40]]
        ida_kernwin.Choose.__init__(self, title, cols,
                                    flags=ida_kernwin.Choose.CH_RESTORE)
        self.rows = rows
        self.items = [[
            _IH_META[r["verdict"]][0], r["dll"], r["func"],
            "%X" % r["slot"],
            ("%X" % r["actual"]) if r["actual"] is not None else "?",
            _ih_expected_str(r), r["target"],
        ] for r in rows]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetLineAttr(self, n):
        if 0 <= n < len(self.rows):
            return [_IH_META[self.rows[n]["verdict"]][1], 0]
        return None

    def OnSelectLine(self, n):
        idx = n[0] if isinstance(n, (list, tuple)) else n
        if idx is not None and 0 <= idx < len(self.rows):
            r = self.rows[idx]
            ida_kernwin.jumpto(r["actual"] if r["actual"] else r["slot"])
        nc = getattr(ida_kernwin.Choose, "NOTHING_CHANGED", None)
        return (nc,) if nc is not None else None


def scan_iat_hooks(module=None, delay=True, show_clean=False):
    """Scan a module's IAT for hooks and open a jump-list of the findings."""
    name, findings = _ih_collect(module, delay)
    if not findings:
        _ih_log("no imports found for %s" % name)
        return None
    flagged = _ih_summary(name, findings)
    rows = findings if show_clean else flagged
    if not rows:
        _ih_log("no IAT hooks detected in %s." % name)
        return findings
    for f in flagged:
        _ih_log("  [%s] %s!%s  slot@%X  actual=%s -> %s"
                % (_IH_META[f["verdict"]][0], f["dll"], f["func"], f["slot"],
                   ("%X" % f["actual"]) if f["actual"] is not None else "?",
                   f["target"]))
    _IHChooser("IAT hooks: %s" % name, rows).Show()
    return findings


def iat_report(module=None, all=False):
    """Text-only report. all=True also lists the clean imports."""
    name, findings = _ih_collect(module)
    if not findings:
        _ih_log("no imports found for %s" % name)
        return findings
    _ih_summary(name, findings)
    for f in findings:
        if not all and not f["flagged"]:
            continue
        _ih_log("  %-9s %s!%s  slot@%X  actual=%s  expected=%s  -> %s"
                % (_IH_META[f["verdict"]][0], f["dll"], f["func"], f["slot"],
                   ("%X" % f["actual"]) if f["actual"] is not None else "?",
                   _ih_expected_str(f), f["target"]))
    return findings


def check_import(dll, func):
    """Inspect one import of the analyzed module by DLL + function name."""
    name, findings = _ih_collect(None)
    hit = [f for f in findings
           if _ih_norm(f["dll"]) == _ih_norm(dll) and f["func"] == func]
    if not hit:
        _ih_log("import %s!%s not found in %s" % (dll, func, name))
        return None
    for f in hit:
        _ih_log("%s!%s  [%s]  slot@%X  actual=%s  expected=%s  -> %s"
                % (f["dll"], f["func"], _IH_META[f["verdict"]][0], f["slot"],
                   ("%X" % f["actual"]) if f["actual"] is not None else "?",
                   _ih_expected_str(f), f["target"]))
    return hit


def scan_all_modules():
    """Scan the IAT of every loaded module. Reports modules with findings."""
    total = 0
    for m in _ih_modules():
        _name, findings = _ih_collect(m["base"])
        flagged = [f for f in findings if f["flagged"]]
        if flagged:
            total += len(flagged)
            _ih_log("== %s: %d flagged ==" % (m["name"], len(flagged)))
            for f in flagged:
                _ih_log("   [%s] %s!%s -> %s"
                        % (_IH_META[f["verdict"]][0], f["dll"], f["func"], f["target"]))
    _ih_log("scan_all_modules: %d flagged import(s) across all modules" % total)
    return total


def list_modules():
    """Print every loaded module with base, size and name."""
    mods = _ih_modules()
    _ih_log("%d module(s):" % len(mods))
    for m in sorted(mods, key=lambda x: x["base"]):
        _ih_log("   %018X  size=%-9X  %s" % (m["base"], m["size"], m["name"]))
    return mods


# ----------------------------------------------------------------------------
# bonus: inline (prologue detour) detection on imported APIs
# ----------------------------------------------------------------------------
def _ih_detour(ea, ps, mem):
    b = _ih_rd(mem, ea, 16)
    if not b:
        return None
    if b[0] == 0xE9:
        return ea + 5 + int.from_bytes(b[1:5], "little", signed=True), "jmp rel32"
    if b[0] == 0xEB:
        return ea + 2 + int.from_bytes(b[1:2], "little", signed=True), "jmp rel8"
    if b[0] == 0xFF and b[1] == 0x25:
        disp = int.from_bytes(b[2:6], "little", signed=True)
        ptr_loc = (ea + 6 + disp) if ps == 8 else (disp & 0xFFFFFFFF)
        return _ih_ptr(ptr_loc, ps, mem), "jmp [mem]"
    if b[0] == 0x68 and b[5] == 0xC3:
        return int.from_bytes(b[1:5], "little"), "push/ret"
    if b[0] == 0x48 and b[1] == 0xB8 and b[10] == 0xFF and b[11] == 0xE0:
        return int.from_bytes(b[2:10], "little"), "mov rax;jmp rax"
    return None


def scan_inline_hooks(module=None):
    """Heuristic: for each API the module imports, check the API's prologue for
    a detour (jmp/push-ret) that leaves the owning module."""
    kind, base, name = _ih_target(module)
    if base is None:
        _ih_log("could not resolve target module %r" % (module,))
        return []
    mem = ida_bytes.get_bytes
    ps = _ih_ptrsize()
    modules = _ih_modules()
    modmap, n2a, a2n, msorted = _ih_build_index(modules, mem)
    imports = _ih_imports_ida() if kind == "analyzed" else _ih_imports_mem(base, mem, ps)
    seen = set()
    hits = []
    for imp in imports:
        strict, broad = _ih_expected(modmap, n2a, imp["dll"], imp["name"], imp["ordinal"])
        for api in (strict or broad):
            if api in seen:
                continue
            seen.add(api)
            det = _ih_detour(api, ps, mem)
            if not det:
                continue
            tgt, kindstr = det
            owner = _ih_module_of(modules, api)
            tmod = _ih_module_of(modules, tgt)
            if owner and (tmod is None or tmod["name"] != owner["name"]):
                where = _ih_describe(tgt, modules, a2n, msorted)
                hits.append((api, imp["dll"], imp["name"] or ("#%d" % imp["ordinal"]),
                             kindstr, tgt, where))
                _ih_log("  INLINE %s!%s @%X  %s -> %s (%s)"
                        % (imp["dll"], imp["name"] or "?", api, kindstr,
                           ("%X" % tgt) if tgt else "?", where))
    _ih_log("scan_inline_hooks: %d inline detour(s) on %s's imported APIs"
            % (len(hits), name))
    return hits


# ----------------------------------------------------------------------------
# bootstrap
# ----------------------------------------------------------------------------
_ih_hotkey = None


def _ih_bootstrap():
    global _ih_hotkey
    try:
        _ih_hotkey = ida_kernwin.add_hotkey("Ctrl-Alt-H", scan_iat_hooks)
    except Exception as exc:
        _ih_log("could not bind hotkey: %s" % exc)
    _ih_log("ready. scan_iat_hooks() scans the analyzed module's IAT (Ctrl-Alt-H); "
            "iat_report(all=True) for a full table; check_import(dll, fn) for one; "
            "scan_all_modules() for everything; scan_inline_hooks() for prologue "
            "detours. Needs an active debug session.")


_ih_bootstrap()
