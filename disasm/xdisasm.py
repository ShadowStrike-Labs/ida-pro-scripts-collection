# ============================================================================
#  xdisasm.py - annotate a range with disassembly decoded in a chosen CPU mode
# ----------------------------------------------------------------------------
#  Purpose
#    Code that uses the "Heaven's Gate" technique runs 32- and 64-bit stretches
#    in one image (far jumps through selectors 0x23 / 0x33). IDA fixes one
#    addressing width per segment, so the other-mode stretch decodes as garbage
#    and there is no per-instruction way to switch the disassembler.
#
#    This decodes an address range in whatever mode you ask for (16 / 32 / 64)
#    and writes the correct instruction as a line comment on every instruction,
#    so the alien-mode code is readable in place - without carving segments,
#    changing the database bitness, or otherwise disturbing the rest of the IDB.
#
#  Engine
#    Capstone is used on purpose: IDA's own disassembler can only decode at the
#    containing segment's width, so cross-mode decoding would require flipping
#    the segment (and a 64-bit database). Capstone decodes at the real address -
#    branch targets stay correct - and touches nothing in the database.
#    Install once into IDA's Python:  <ida>\python -m pip install capstone
#
#  Console interface
#    disasm_as(start, end=None, mode=None, count=None)   annotate [start, end)
#    dis(start, end=None, mode=None)                     print only, no changes
#    find_mode_switches(start, end=None)                 locate far jmp/call/retf
#    clear_annotations(start, end)                       remove the annotations
#
#    mode  : "x86"/"x64"/"x16" (or 32/64/16). Default = the OTHER width from the
#            segment at `start` (32-bit segment -> x64, and vice versa).
#    end   : omit and pass count=N to decode N instructions instead of a range.
#    Addresses accept ints or hex strings.
#
#  Options on disasm_as: comment=True, items=True, color=False, echo=False.
#    items reforms the range into one data item per decoded instruction, so each
#    instruction is a single line carrying its `[mode] ...` comment (reversible
#    via clear_annotations, which re-analyses the range in its native width).
#    echo=False keeps the Output window quiet; the decoded data stays in
#    get_last(). color=True tints the whole annotated range (off by default).
#
#  Hotkey
#    Ctrl-Alt-X   annotate the current selection (or current function) in the
#                 opposite width from its segment
# ============================================================================

import ida_bytes
import ida_segment
import ida_kernwin
import ida_auto
import idc
import idaapi

try:
    import capstone as _cs
    _XD_HAVE_CS = True
except Exception:                       # pragma: no cover
    _XD_HAVE_CS = False

_XD_TAG = "[xdisasm]"
_XD_MARK = {16: "[x16] ", 32: "[x86] ", 64: "[x64] "}
_XD_COLOR = 0xF0E0C0                     # BGR: pale cyan tint for annotated lines
_DELIT_SIMPLE = getattr(ida_bytes, "DELIT_SIMPLE", 0x0000)

_xd_last = []                            # instructions from the most recent run
_xd_last_switches = []                   # hits from the most recent scan


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _xd_log(msg):
    print("%s %s" % (_XD_TAG, msg))


def _xd_addr(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip().lower().replace("0x", ""), 16)
        except ValueError:
            return None
    return None


def _xd_bits(mode):
    if mode is None:
        return None
    if isinstance(mode, int):
        return mode if mode in (16, 32, 64) else None
    s = str(mode).strip().lower()
    return {"x16": 16, "16": 16, "x86": 32, "x32": 32, "32": 32,
            "x64": 64, "64": 64, "amd64": 64}.get(s)


def _xd_seg_bits(ea):
    seg = ida_segment.getseg(ea)
    if seg is None:
        return 32
    return {0: 16, 1: 32, 2: 64}.get(seg.bitness, 32)


def _xd_default_mode(start):
    return 64 if _xd_seg_bits(start) == 32 else 32


def _xd_read(start, size):
    """Read `size` bytes, tolerating unreadable pages (zero-filled, bounded)."""
    out = bytearray(size)
    pos = 0
    while pos < size:
        n = min(0x1000, size - pos)
        chunk = ida_bytes.get_bytes(start + pos, n)
        if chunk and len(chunk) == n:
            out[pos:pos + n] = chunk
        pos += n
    return bytes(out)


# ----------------------------------------------------------------------------
# pure decode / scan (driven by a bytes buffer, so they are testable offline)
# ----------------------------------------------------------------------------
def _xd_cs_mode(bits):
    return {16: _cs.CS_MODE_16, 32: _cs.CS_MODE_32, 64: _cs.CS_MODE_64}[bits]


def _xd_decode(data, base, bits, count=None):
    """Decode `data` at address `base` in `bits` mode. Returns a list of
    dicts {ea, size, text, bytes, bad}. Undecodable bytes become 'db 0xNN' and
    decoding resynchronises one byte later, so embedded data cannot derail it."""
    if not _XD_HAVE_CS:
        return []
    md = _cs.Cs(_cs.CS_ARCH_X86, _xd_cs_mode(bits))
    out = []
    n = len(data)
    off = 0
    while off < n:
        produced = 0
        for insn in md.disasm(bytes(data[off:]), base + off):
            ops = (" " + insn.op_str) if insn.op_str else ""
            out.append({"ea": insn.address, "size": insn.size,
                        "text": insn.mnemonic + ops,
                        "bytes": bytes(insn.bytes), "bad": False})
            off += insn.size
            produced += 1
            if count and len(out) >= count:
                return out
        if produced == 0:
            out.append({"ea": base + off, "size": 1,
                        "text": "db 0x%02X" % data[off],
                        "bytes": bytes(data[off:off + 1]), "bad": True})
            off += 1
            if count and len(out) >= count:
                return out
    return out


def _xd_find_switches(data, base):
    """Scan bytes for far transfers / selector pushes used by mode switches."""
    def sel_note(sel):
        if sel == 0x33:
            return "  -> 64-bit (selector 0x33)"
        if sel == 0x23:
            return "  -> 32-bit (selector 0x23)"
        return ""

    hits = []
    n = len(data)
    i = 0
    while i < n:
        b = data[i]
        if b == 0xEA and i + 7 <= n:                 # jmp far ptr16:32
            off = int.from_bytes(data[i + 1:i + 5], "little")
            sel = int.from_bytes(data[i + 5:i + 7], "little")
            hits.append((base + i, "jmp far", "%04X:%08X%s" % (sel, off, sel_note(sel))))
            i += 7
            continue
        if b == 0x9A and i + 7 <= n:                 # call far ptr16:32
            off = int.from_bytes(data[i + 1:i + 5], "little")
            sel = int.from_bytes(data[i + 5:i + 7], "little")
            hits.append((base + i, "call far", "%04X:%08X%s" % (sel, off, sel_note(sel))))
            i += 7
            continue
        if b == 0xCB:                                # retf
            hits.append((base + i, "retf", ""))
            i += 1
            continue
        if b == 0xCA and i + 3 <= n:                 # retf imm16
            hits.append((base + i, "retf", "0x%04X" % int.from_bytes(data[i + 1:i + 3], "little")))
            i += 3
            continue
        if b == 0x6A and i + 2 <= n and data[i + 1] in (0x33, 0x23):   # push sel
            hits.append((base + i, "push selector",
                         "0x%02X%s" % (data[i + 1], sel_note(data[i + 1]))))
            i += 2
            continue
        if b == 0xFF and i + 2 <= n:                 # jmp/call far m16:16/32
            reg = (data[i + 1] >> 3) & 7
            if reg == 3:
                hits.append((base + i, "call far [mem]", "FF /3"))
            elif reg == 5:
                hits.append((base + i, "jmp far [mem]", "FF /5"))
        i += 1
    return hits


# ----------------------------------------------------------------------------
# annotation
# ----------------------------------------------------------------------------
def _xd_is_ours(ea):
    cmt = idc.get_cmt(ea, 0) or ""
    return any(cmt.startswith(m) for m in _XD_MARK.values())


def _xd_prepare(start, end, mode, count):
    """Resolve arguments, read the bytes and decode. Returns
    (s, bits, insns, real_end) or None on error (with a logged reason)."""
    if not _XD_HAVE_CS:
        _xd_log("capstone is not available in IDA's Python. Install it once: "
                "<ida>\\python -m pip install capstone")
        return None
    s = _xd_addr(start)
    if s is None:
        _xd_log("bad start address %r" % (start,))
        return None
    bits = _xd_bits(mode) if mode is not None else _xd_default_mode(s)
    if bits is None:
        _xd_log("bad mode %r (use x86/x64/x16 or 32/64/16)" % (mode,))
        return None
    e = _xd_addr(end) if end is not None else None
    if e is not None and e <= s:
        _xd_log("end (%X) must be greater than start (%X)" % (e, s))
        return None
    size = (e - s) if e is not None else (count or 64) * 15
    data = _xd_read(s, size)
    insns = _xd_decode(data, s, bits, count=(None if e is not None else (count or 64)))
    if not insns:
        _xd_log("nothing decoded at %X" % s)
        return None
    real_end = insns[-1]["ea"] + insns[-1]["size"]
    return s, bits, insns, real_end


def disasm_as(start, end=None, mode=None, count=None, comment=True,
              items=True, color=False, echo=False):
    """Annotate [start, end) (or `count` instructions) with disassembly decoded
    in `mode`, one line per instruction carrying a `[mode] ...` comment.

    Prints only a one-line summary; the decoded data is kept in get_last() and
    nothing large is returned, so the console stays clean. Pass echo=True for a
    full printed listing, or use dis() to print without changing the database."""
    global _xd_last
    prep = _xd_prepare(start, end, mode, count)
    if prep is None:
        return None
    s, bits, insns, real_end = prep
    mark = _XD_MARK[bits]

    if items:
        ida_bytes.del_items(s, _DELIT_SIMPLE, real_end - s)
    for ins in insns:
        if items and ins["size"] > 0:
            try:                                # one data item -> one clean line
                ida_bytes.create_data(ins["ea"], ida_bytes.FF_BYTE,
                                      ins["size"], idaapi.BADADDR)
            except Exception:
                pass
        if comment:
            idc.set_cmt(ins["ea"], mark + ins["text"], 0)
        if color:
            idc.set_color(ins["ea"], idc.CIC_ITEM, _XD_COLOR)
    _xd_refresh()
    _xd_last = insns

    if echo:
        for ins in insns:
            hexb = " ".join("%02X" % b for b in ins["bytes"])[:23]
            _xd_log("  %012X  %-24s %s%s" % (ins["ea"], hexb, mark, ins["text"]))
    _xd_log("annotated %d instruction(s) as %s over %X..%X. "
            "clear_annotations(0x%X, 0x%X) to undo; get_last() for the data."
            % (len(insns), mark.strip(), s, real_end, s, real_end))
    return None


def dis(start, end=None, mode=None, count=None):
    """Print the decoded listing to Output only - no comments, no DB changes."""
    global _xd_last
    prep = _xd_prepare(start, end, mode, count)
    if prep is None:
        return None
    s, bits, insns, real_end = prep
    mark = _XD_MARK[bits]
    _xd_log("%d instruction(s) as %s over %X..%X:"
            % (len(insns), mark.strip(), s, real_end))
    for ins in insns:
        hexb = " ".join("%02X" % b for b in ins["bytes"])[:23]
        _xd_log("  %012X  %-24s %s" % (ins["ea"], hexb, ins["text"]))
    _xd_last = insns
    return None


def get_last():
    """Return the instruction list from the most recent disasm_as()/dis()."""
    return list(_xd_last)


def find_mode_switches(start, end=None):
    """Locate far jmp/call, retf and selector pushes (mode-switch points)."""
    s = _xd_addr(start)
    if s is None:
        _xd_log("bad start address %r" % (start,))
        return []
    e = _xd_addr(end) if end is not None else s + 0x400
    data = _xd_read(s, max(0, e - s))
    global _xd_last_switches
    hits = _xd_find_switches(data, s)
    _xd_log("%d mode-switch candidate(s) in %X..%X:" % (len(hits), s, e))
    for ea, kind, detail in hits:
        _xd_log("  %012X  %-14s %s" % (ea, kind, detail))
    _xd_last_switches = hits
    return None


def clear_annotations(start, end):
    """Remove annotations/colour in [start, end) and re-analyse the range."""
    s = _xd_addr(start)
    e = _xd_addr(end)
    if s is None or e is None or e <= s:
        _xd_log("bad range")
        return 0
    ea = s
    cleared = 0
    while ea < e:
        if _xd_is_ours(ea):
            idc.set_cmt(ea, "", 0)
            cleared += 1
        idc.set_color(ea, idc.CIC_ITEM, 0xFFFFFFFF)
        nxt = idc.next_head(ea, e)
        ea = nxt if nxt > ea else ea + 1
    try:
        ida_auto.plan_and_wait(s, e)
    except Exception:
        pass
    _xd_refresh()
    _xd_log("cleared %d annotation(s) and re-analysed %X..%X" % (cleared, s, e))
    return cleared


def _xd_refresh():
    for fn in ("refresh_idaview_anyway", "request_refresh"):
        try:
            getattr(ida_kernwin, fn)()
            return
        except Exception:
            continue


# ----------------------------------------------------------------------------
# hotkey: annotate the current selection (or function) in the opposite width
# ----------------------------------------------------------------------------
def _xd_hk_annotate():
    sel = ida_kernwin.read_range_selection(None)
    if isinstance(sel, tuple) and len(sel) == 3 and sel[0]:
        s, e = sel[1], sel[2]
    else:
        f = idc.get_func_attr(idc.get_screen_ea(), idc.FUNCATTR_START)
        if f == idaapi.BADADDR:
            _xd_log("select a range, or place the cursor in a function")
            return
        s = f
        e = idc.get_func_attr(f, idc.FUNCATTR_END)
    disasm_as(s, e, mode=_xd_default_mode(s))


_xd_hotkey = None


def _xd_bootstrap():
    global _xd_hotkey
    try:
        _xd_hotkey = ida_kernwin.add_hotkey("Ctrl-Alt-X", _xd_hk_annotate)
    except Exception as exc:
        _xd_log("could not bind hotkey: %s" % exc)
    if not _XD_HAVE_CS:
        _xd_log("WARNING: capstone not found in IDA's Python. Install it: "
                "<ida>\\python -m pip install capstone")
    _xd_log("ready. disasm_as(start, end, mode) annotates each line in the IDA "
            "view (Ctrl-Alt-X does the selection); dis(...) prints to Output; "
            "get_last() returns the data; find_mode_switches(...) locates far "
            "jmp/retf; clear_annotations(start, end) undoes it.")


_xd_bootstrap()
