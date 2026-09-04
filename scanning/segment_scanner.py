# ============================================================================
#  segment_scanner.py  -  IDAPython: hunt signatures in the segments YOU choose
# ----------------------------------------------------------------------------
#  A targeted scanner, not a blanket sweep. You tell it which segments to look
#  in (by name, by cursor, by address, or "all") and it reports every hit with
#  an exact address you can double-click to jump to.
#
#  It looks for three kinds of thing, each toggleable:
#     * pe    - MZ headers, validated into "valid PE (arch/type/SizeOfImage)"
#               vs "MZ (no PE header)". This is what feeds pe_dumper.
#     * code  - x86-64 function-prologue fingerprints (sub rsp / mov [rsp],reg /
#               push rbp;mov rbp,rsp / ...). HEURISTIC by nature.
#     * magic - other embedded payloads (ELF, ZIP, GZIP, PDF, PNG, 7z, CAB, ...)
#
#  THE SNEAKY-CODE ALERT: if a `code` signature turns up inside a segment that
#  is NOT executable (e.g. code stashed in .rdata / .data for a later trampoline
#  or manual map), the row is flagged  << code in NON-EXEC segment >>  and tinted
#  red. That is the "analyst assumes read-only == no code" trick, surfaced.
#
#  COMMANDS (from the IDAPython console)
#    segs()  / list_segments()      list every segment (name, range, perms)
#    scan()                         scan the segment under the cursor
#    scan(".rdata", ".data", ".grfn10")   scan just those segments
#    scan("all")                    scan every segment (explicit)
#    scan(0x7FF706180000)           scan the segment containing that address
#    scan(".rdata", cats=("pe","code","magic"))   choose what to look for
#    scan_code(".rdata", ".data")   shortcut: pe + code
#    scan_magic(".rsrc")            shortcut: pe + magic
#    scan_exec()                    scan only executable segments
#    scan_range(lo, hi)             scan an arbitrary address range
#    rescan()                       repeat the last scan
#    dump(n)                        dump hit #n with pe_dumper.dump_pe (if loaded)
#    goto_hit(n)                    jump to hit #n from the last listing
#
#  HOTKEY:  Ctrl-Alt-S  ->  scan() on the segment under the cursor.
#
#  Verified API: ida_segment.get_segm_qty/getnseg/getseg/get_segm_name give the
#  segment table + perms (SEGPERM_*); ida_bytes.get_bytes reads the current view
#  (live memory while debugging); ida_kernwin.Choose drives the jump-list.
# ============================================================================

import ida_bytes
import ida_segment
import ida_kernwin
import idc

try:
    import idaapi
    _SS_BADADDR = idaapi.BADADDR
except Exception:                       # pragma: no cover
    _SS_BADADDR = 0xFFFFFFFFFFFFFFFF

# ------------------------------- customization ------------------------------
DEFAULT_CATS   = ("pe", "code")   # what scan() looks for unless told otherwise
CODE_HIT_CAP   = 40               # max `code` hits reported per segment (noise)
MAX_SEG_BYTES  = 0x8000000        # 128 MB per-segment read cap
ALERT_NONEXEC_CODE = True         # flag code found in non-executable segments
COLOR_HITS     = True             # tint hit lines in the disassembly
VERBOSE        = True
# ----------------------------------------------------------------------------

_SS_TAG = "[segscan]"
_SS_PAGE = 0x1000

# ---- architecture + PE bits (for the pe label) ----
_SS_ARCH = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01C0: "ARM",
            0x01C4: "ARMNT", 0x0200: "IA64", 0x5064: "RISCV64"}

# ---- signature tables (name, byte-pattern, category, human detail) ----
_SS_PE_SIGS = [
    ("MZ", b"MZ", "pe", "DOS/MZ header"),
]
_SS_PEHDR_SIGS = [
    ("PE\\0\\0", b"PE\x00\x00", "pehdr", "lone PE header (no MZ)"),
]
# x86-64 prologue / frame fingerprints - deliberately conservative
_SS_CODE_SIGS = [
    ("mov[rsp+x],rbx",  b"\x48\x89\x5C\x24", "code", "x64: mov [rsp+X], rbx"),
    ("mov[rsp+x],rbp",  b"\x48\x89\x6C\x24", "code", "x64: mov [rsp+X], rbp"),
    ("mov[rsp+x],rsi",  b"\x48\x89\x74\x24", "code", "x64: mov [rsp+X], rsi"),
    ("mov[rsp+x],rdi",  b"\x48\x89\x7C\x24", "code", "x64: mov [rsp+X], rdi"),
    ("push rbp;mov rbp,rsp", b"\x55\x48\x8B\xEC", "code", "x64: frame setup"),
    ("sub rsp,imm8",    b"\x48\x83\xEC", "code", "x64: sub rsp, imm8"),
    ("sub rsp,imm32",   b"\x48\x81\xEC", "code", "x64: sub rsp, imm32"),
    ("mov rax,rsp",     b"\x48\x8B\xC4", "code", "x64: mov rax, rsp (arg save)"),
    ("mov r11,rsp",     b"\x4C\x8B\xDC", "code", "x64: mov r11, rsp (arg save)"),
    ("push rbp(REX)",   b"\x40\x55",     "code", "x64: push rbp (REX.B)"),
]
_SS_MAGIC_SIGS = [
    ("ELF",     b"\x7FELF",              "magic", "ELF executable"),
    ("ZIP",     b"PK\x03\x04",           "magic", "ZIP / modern Office / JAR"),
    ("GZIP",    b"\x1F\x8B\x08",         "magic", "gzip stream"),
    ("PDF",     b"%PDF",                 "magic", "PDF document"),
    ("PNG",     b"\x89PNG\r\n\x1a\n",    "magic", "PNG image"),
    ("RAR",     b"Rar!\x1a\x07",         "magic", "RAR archive"),
    ("7z",      b"7z\xBC\xAF\x27\x1C",   "magic", "7-Zip archive"),
    ("CAB",     b"MSCF",                 "magic", "MS Cabinet"),
    ("OLE2",    b"\xD0\xCF\x11\xE0",     "magic", "OLE2 / legacy Office"),
    ("BZ2",     b"BZh",                  "magic", "bzip2 stream"),
]

_SS_CAT_TABLE = {
    "pe": _SS_PE_SIGS,
    "pehdr": _SS_PEHDR_SIGS,
    "code": _SS_CODE_SIGS,
    "magic": _SS_MAGIC_SIGS,
}
_SS_CAT_COLOR = {          # BGR line tints
    "pe": 0xC8F0C8,        # green   - valid PE / MZ
    "pehdr": 0xC8F0C8,
    "magic": 0xF0E0C0,     # cyan-ish - embedded payloads
    "code": 0xE8E8E8,      # grey    - code hit (normal)
    "alert": 0xC0C0FF,     # red     - code in non-exec segment
}


# ----------------------------------------------------------------------------
# low-level helpers
# ----------------------------------------------------------------------------
def _ss_log(msg):
    if VERBOSE:
        print("%s %s" % (_SS_TAG, msg))


def _ss_u16(b, off):
    return (b[off] | (b[off + 1] << 8)) if off + 2 <= len(b) else 0


def _ss_u32(b, off):
    if off + 4 > len(b):
        return 0
    return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)


def _ss_read(ea, size):
    """Read exactly `size` bytes, zero-filling unreadable pages (bounded)."""
    out = bytearray(size)
    pos = 0
    while pos < size:
        n = min(_SS_PAGE, size - pos)
        chunk = ida_bytes.get_bytes(ea + pos, n)
        if chunk and len(chunk) == n:
            out[pos:pos + n] = chunk
        pos += n
    return bytes(out)


def _ss_page_reader(ea, n):
    chunk = ida_bytes.get_bytes(ea, n)
    if chunk and len(chunk) == n:
        return chunk
    return b"\x00" * n              # unmapped -> zeros (won't match anything)


# ----------------------------------------------------------------------------
# segment utilities
# ----------------------------------------------------------------------------
def _ss_seg_name(seg):
    try:
        return ida_segment.get_segm_name(seg) or "?"
    except Exception:
        try:
            return idc.get_segm_name(seg.start_ea) or "?"
        except Exception:
            return "?"


def _ss_perm_str(seg):
    p = getattr(seg, "perm", 0) or 0
    r = "r" if p & ida_segment.SEGPERM_READ else "-"
    w = "w" if p & ida_segment.SEGPERM_WRITE else "-"
    x = "x" if p & ida_segment.SEGPERM_EXEC else "-"
    return r + w + x


def _ss_is_exec(seg):
    return bool((getattr(seg, "perm", 0) or 0) & ida_segment.SEGPERM_EXEC)


def _ss_all_segments():
    segs = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s:
            segs.append(s)
    return segs


def _ss_norm(name):
    name = (name or "").strip().lower()
    return name[1:] if name.startswith(".") else name


def _ss_match_name(query, segs):
    """Return segments whose name matches `query` (case-insensitive, the leading
    dot is optional). Falls back to a substring match."""
    q = _ss_norm(query)
    exact = [s for s in segs if _ss_norm(_ss_seg_name(s)) == q]
    if exact:
        return exact
    return [s for s in segs if q in _ss_norm(_ss_seg_name(s))]


def _ss_resolve_targets(args):
    """Turn scan() arguments into a list of (lo, hi, name, perm_str, is_exec)."""
    all_segs = _ss_all_segments()
    chosen = []

    def add(seg):
        if seg is None:
            return
        chosen.append((seg.start_ea, seg.end_ea, _ss_seg_name(seg),
                       _ss_perm_str(seg), _ss_is_exec(seg)))

    if not args:
        seg = ida_segment.getseg(idc.get_screen_ea())
        if seg is None:
            _ss_log("cursor is not inside a segment; pass a name or 'all'")
        add(seg)
        return _ss_dedupe(chosen)

    for a in args:
        if isinstance(a, int):
            add(ida_segment.getseg(a))
            continue
        s = str(a).strip().lower()
        if s in ("all", "*"):
            for seg in all_segs:
                add(seg)
        elif s in ("exec", "x", "code_segs"):
            for seg in all_segs:
                if _ss_is_exec(seg):
                    add(seg)
        else:
            matches = _ss_match_name(a, all_segs)
            if not matches:
                _ss_log("no segment matches %r. Available: %s"
                        % (a, ", ".join(_ss_seg_name(x) for x in all_segs)))
            for seg in matches:
                add(seg)
    return _ss_dedupe(chosen)


def _ss_dedupe(targets):
    seen, out = set(), []
    for t in targets:
        if t[0] not in seen:
            seen.add(t[0])
            out.append(t)
    return out


# ----------------------------------------------------------------------------
# scanning core
# ----------------------------------------------------------------------------
def _ss_active_sigs(cats):
    sigs = []
    for c in cats:
        sigs.extend(_SS_CAT_TABLE.get(c, []))
    return sigs


def _ss_scan_region(lo, hi, sigs):
    """Find every signature occurrence in [lo, hi). Returns [(ea, sig)] where
    sig is the (name, pattern, category, detail) tuple. Page-chunked with a
    carry so matches spanning a page boundary are not missed."""
    if hi <= lo or not sigs:
        return []
    span = min(hi - lo, MAX_SEG_BYTES)
    truncated = (hi - lo) > MAX_SEG_BYTES
    keep = max(len(p) for _, p, _, _ in sigs) - 1
    hits, seen = [], set()

    carry = b""
    carry_ea = lo
    ea = lo
    end = lo + span
    while ea < end:
        n = min(_SS_PAGE, end - ea)
        buf = carry + _ss_page_reader(ea, n)
        base = carry_ea
        for sig in sigs:
            pat = sig[1]
            start = 0
            while True:
                idx = buf.find(pat, start)
                if idx < 0:
                    break
                abs_ea = base + idx
                key = (abs_ea, sig[0])
                if key not in seen and lo <= abs_ea < end:
                    seen.add(key)
                    hits.append((abs_ea, sig))
                start = idx + 1
        carry = buf[-keep:] if keep > 0 else b""
        carry_ea = base + len(buf) - len(carry)
        ea += n
    if truncated:
        _ss_log("  note: region > %#x bytes; scanned first %#x only"
                % (MAX_SEG_BYTES, span))
    return hits


def _ss_pe_label(ea):
    """Validate an MZ into a human label. Returns (label, is_valid_pe)."""
    dos = _ss_read(ea, 0x40)
    if dos[:2] != b"MZ":
        return ("not MZ", False)
    e = _ss_u32(dos, 0x3C)
    if not (0 < e < 0x10000000):
        return ("MZ (bad e_lfanew)", False)
    if _ss_read(ea + e, 4) != b"PE\x00\x00":
        return ("MZ (no PE header)", False)
    coff = _ss_read(ea + e + 4, 20)
    opt = _ss_read(ea + e + 24, 0x48)
    machine = _ss_u16(coff, 0)
    chars = _ss_u16(coff, 18)
    magic = _ss_u16(opt, 0)
    soi = _ss_u32(opt, 56)
    arch = _SS_ARCH.get(machine, "m%X" % machine)
    if _ss_u16(opt, 68) == 1:                     # native subsystem
        kind = "SYS?"
    elif chars & 0x2000:
        kind = "DLL"
    else:
        kind = "EXE"
    tag = "PE32+" if magic == 0x20B else "PE32"
    return ("valid PE  %s %s %s  SizeOfImage=%#x" % (arch, tag, kind, soi), True)


def _ss_make_row(ea, seg_name, perm, is_exec, sig):
    name, _pat, cat, detail = sig
    alert = False
    if cat == "pe":
        label, valid = _ss_pe_label(ea)
        detail = label
        cat = "pe" if valid else "pehdr"
    elif cat == "code" and ALERT_NONEXEC_CODE and not is_exec:
        alert = True
        detail = detail + "   << code in NON-EXEC segment >>"
    return {"ea": ea, "seg": seg_name, "perm": perm, "cat": cat,
            "sig": name, "detail": detail, "alert": alert}


def collect_hits(targets, cats):
    """Scan resolved `targets` for categories `cats`. Returns list of row dicts.
    (IDA-independent apart from the byte/segment readers.)"""
    sigs = _ss_active_sigs(cats)
    rows = []
    for (lo, hi, name, perm, is_exec) in targets:
        raw = _ss_scan_region(lo, hi, sigs)
        code_seen = 0
        capped = 0
        for (ea, sig) in sorted(raw, key=lambda t: (t[0], t[1][0])):
            if sig[2] == "code":
                code_seen += 1
                if code_seen > CODE_HIT_CAP:
                    capped += 1
                    continue
            rows.append(_ss_make_row(ea, name, perm, is_exec, sig))
        if capped:
            _ss_log("  %s: capped %d extra 'code' hit(s) (CODE_HIT_CAP=%d)"
                    % (name, capped, CODE_HIT_CAP))
    return rows


# ----------------------------------------------------------------------------
# reporting + chooser
# ----------------------------------------------------------------------------
_ss_last_rows = []
_ss_last_call = None


def _ss_summary(targets, rows):
    npe = sum(1 for r in rows if r["cat"] == "pe")
    npehdr = sum(1 for r in rows if r["cat"] == "pehdr")
    ncode = sum(1 for r in rows if r["cat"] == "code")
    nmagic = sum(1 for r in rows if r["cat"] == "magic")
    nalert = sum(1 for r in rows if r["alert"])
    _ss_log("scanned %d segment(s): %s"
            % (len(targets), ", ".join(t[2] for t in targets)))
    _ss_log("hits: %d valid-PE, %d MZ/PE-hdr, %d code, %d magic  (%d ALERT)"
            % (npe, npehdr, ncode, nmagic, nalert))
    if nalert:
        _ss_log("  !! %d executable-code signature(s) in NON-EXEC segment(s) - "
                "inspect these first" % nalert)


class _SSChooser(ida_kernwin.Choose):
    def __init__(self, title, rows):
        cols = [
            ["Address", ida_kernwin.Choose.CHCOL_HEX | 18],
            ["Segment", 12],
            ["Perm", 5],
            ["Kind", 6],
            ["Signature", 20],
            ["Detail", 52],
        ]
        ida_kernwin.Choose.__init__(self, title, cols,
                                    flags=ida_kernwin.Choose.CH_RESTORE)
        self.rows = rows
        self.items = [[
            "%X" % r["ea"], r["seg"], r["perm"], r["cat"].upper(),
            r["sig"], r["detail"],
        ] for r in rows]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetLineAttr(self, n):
        if 0 <= n < len(self.rows):
            r = self.rows[n]
            color = _SS_CAT_COLOR["alert"] if r["alert"] \
                else _SS_CAT_COLOR.get(r["cat"])
            if color is not None:
                return [color, 0]
        return None

    def OnSelectLine(self, n):
        idx = n[0] if isinstance(n, (list, tuple)) else n
        if idx is not None and 0 <= idx < len(self.rows):
            ida_kernwin.jumpto(self.rows[idx]["ea"])
        nc = getattr(ida_kernwin.Choose, "NOTHING_CHANGED", None)
        return (nc, ) if nc is not None else None


def _ss_color_rows(rows):
    if not COLOR_HITS:
        return
    for r in rows:
        color = _SS_CAT_COLOR["alert"] if r["alert"] else _SS_CAT_COLOR.get(r["cat"])
        if color is not None:
            try:
                idc.set_color(r["ea"], idc.CIC_ITEM, color)
            except Exception:
                pass


def _ss_present(title, targets, rows):
    global _ss_last_rows
    _ss_last_rows = rows
    _ss_summary(targets, rows)
    if not rows:
        _ss_log("  (no signatures found in the chosen segment(s))")
        return None
    _ss_color_rows(rows)
    ch = _SSChooser(title, rows)
    ch.Show()
    return ch


def _ss_norm_cats(cats):
    if cats is None:
        return DEFAULT_CATS
    if isinstance(cats, str):
        cats = (cats,)
    good = tuple(c for c in cats if c in _SS_CAT_TABLE)
    return good or DEFAULT_CATS


# ----------------------------------------------------------------------------
# public commands
# ----------------------------------------------------------------------------
def scan(*names, **kw):
    """Scan the chosen segment(s). With no name, scans the segment at the cursor.
    Names are matched case-insensitively (leading dot optional). Special names:
    "all" (every segment) and "exec" (executable segments only).
    Keyword `cats=(...)` selects categories among pe/pehdr/code/magic."""
    global _ss_last_call
    cats = _ss_norm_cats(kw.get("cats") or kw.get("categories"))
    targets = _ss_resolve_targets(list(names))
    if not targets:
        _ss_log("nothing to scan")
        return None
    _ss_last_call = (list(names), cats)
    rows = collect_hits(targets, cats)
    title = "SegScan: %s [%s]" % (", ".join(t[2] for t in targets),
                                  "/".join(cats))
    return _ss_present(title, targets, rows)


def scan_code(*names, **kw):
    """Shortcut: scan for PE + executable-code signatures."""
    return scan(*names, cats=("pe", "code"))


def scan_magic(*names, **kw):
    """Shortcut: scan for PE + embedded-file magics."""
    return scan(*names, cats=("pe", "magic"))


def scan_all(cats=None):
    """Explicitly scan every segment."""
    return scan("all", cats=cats)


def scan_exec(cats=None):
    """Scan only executable segments."""
    return scan("exec", cats=cats)


def scan_range(lo, hi, cats=None):
    """Scan an arbitrary [lo, hi) address range."""
    if isinstance(lo, str):
        lo = int(lo, 16)
    if isinstance(hi, str):
        hi = int(hi, 16)
    cats = _ss_norm_cats(cats)
    seg = ida_segment.getseg(lo)
    perm = _ss_perm_str(seg) if seg else "???"
    is_exec = _ss_is_exec(seg) if seg else False
    targets = [(lo, hi, "range", perm, is_exec)]
    rows = collect_hits(targets, cats)
    return _ss_present("SegScan: %X-%X [%s]" % (lo, hi, "/".join(cats)),
                       targets, rows)


def rescan():
    """Repeat the last scan()."""
    if not _ss_last_call:
        _ss_log("nothing to rescan yet")
        return None
    names, cats = _ss_last_call
    return scan(*names, cats=cats)


def list_segments():
    """Print every segment with its range, size and permissions."""
    segs = _ss_all_segments()
    _ss_log("%d segment(s):" % len(segs))
    _ss_log("   %-16s %-18s %-18s %-10s %-5s %s"
            % ("name", "start", "end", "size", "perm", "class"))
    for s in segs:
        try:
            cls = ida_segment.get_segm_class(s) or ""
        except Exception:
            cls = ""
        _ss_log("   %-16s %-18X %-18X %-10X %-5s %s"
                % (_ss_seg_name(s), s.start_ea, s.end_ea,
                   s.end_ea - s.start_ea, _ss_perm_str(s), cls))
    _ss_log("scan a subset, e.g.:  scan('.rdata', '.data')   or   scan('all')")
    return segs


def segs():
    """Alias for list_segments()."""
    return list_segments()


def goto_hit(n):
    """Jump to hit #n from the last listing."""
    if not _ss_last_rows or n < 0 or n >= len(_ss_last_rows):
        _ss_log("no such hit (have %d)" % len(_ss_last_rows))
        return None
    ea = _ss_last_rows[n]["ea"]
    ida_kernwin.jumpto(ea)
    return ea


def _ss_get_dumper():
    import sys
    m = sys.modules.get("__main__")
    fn = getattr(m, "dump_pe", None) if m else None
    return fn or globals().get("dump_pe")


def dump(n=0):
    """Dump hit #n via pe_dumper.dump_pe (must be loaded in this session)."""
    if not _ss_last_rows or n < 0 or n >= len(_ss_last_rows):
        _ss_log("no such hit (have %d)" % len(_ss_last_rows))
        return None
    ea = _ss_last_rows[n]["ea"]
    fn = _ss_get_dumper()
    if fn is None:
        _ss_log("dump_pe not found - load dumping/pe_dumper.py, then "
                "dump_pe(0x%X)" % ea)
        return None
    _ss_log("handing 0x%X to dump_pe()" % ea)
    return fn(ea)


# ----------------------------------------------------------------------------
# bootstrap
# ----------------------------------------------------------------------------
_ss_hotkey = None


def _ss_bootstrap():
    global _ss_hotkey
    try:
        _ss_hotkey = ida_kernwin.add_hotkey("Ctrl-Alt-S", scan)
        _ss_log("hotkey Ctrl-Alt-S -> scan() on the segment under the cursor")
    except Exception as e:
        _ss_log("could not bind hotkey: %s" % e)
    _ss_log("ready. segs() to list; scan('.rdata','.data') to target; "
            "scan('all') for everything; cats=('pe','code','magic'). "
            "Code found in a non-exec segment gets flagged.")


_ss_bootstrap()
