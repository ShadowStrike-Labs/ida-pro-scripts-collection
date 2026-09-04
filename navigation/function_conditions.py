# ============================================================================
#  function_conditions.py  -  IDAPython: see EVERY condition in THIS function
# ----------------------------------------------------------------------------
#  Put the cursor anywhere inside a function and get a precise, address-by-
#  address map of every decision the function makes - conditional jumps,
#  SETcc, CMOVcc and LOOP - WITHOUT ever wandering into a neighbouring
#  function.  It iterates the function's own instruction items (all chunks
#  included, tail chunks too), so unlike Alt-T / "jump to xref" it can never
#  leak across the function boundary and pollute your analysis.
#
#  For every condition you get:
#     * the EXACT address                       (double-click a row to jump)
#     * the mnemonic and full disassembly
#     * a plain-English meaning                 (je -> "== (ZF=1)", etc.)
#     * signed vs unsigned comparison           (jg vs ja, jl vs jb, ...)
#     * the branch target + whether it stays INSIDE the function or leaves it
#       (external targets are flagged loudly - those are the tail-calls that
#        make Alt-T lie to you)
#     * the fall-through (not-taken) address
#     * the instruction that SET THE FLAGS this branch reads (the feeding
#       cmp/test/arith), found by walking back within the same basic block
#
#  COMMANDS (from the IDAPython console)
#    conditions()             analyze the function at the cursor, open a chooser
#    conditions(0x401000)     analyze a specific function
#    conditions_text()        same analysis, printed as copy-paste text only
#    nc() / next_condition()  jump to the next conditional branch (in-function)
#    pc() / prev_condition()  jump to the previous conditional branch
#    goto_condition(3)        jump to the Nth condition from the last listing
#    color_conditions()       tint every conditional-branch line (toggle off:
#                             uncolor_conditions())
#
#  HOTKEYS
#    Ctrl-Alt-C   ->  conditions()      (open the chooser for this function)
#    Ctrl-Alt-N   ->  nc()             (next branch, stays in the function)
#    Ctrl-Alt-B   ->  pc()             (previous branch, stays in the function)
#
#  Verified API: idautils.FuncItems(start) yields every head in the function
#  and respects chunk boundaries; ida_funcs.func_contains() tests membership
#  across chunks; ida_kernwin.Choose drives the jump-list; jumpto() navigates.
# ============================================================================

import ida_funcs
import ida_kernwin
import ida_bytes
import idautils
import idc

try:
    import idaapi
    BADADDR = idaapi.BADADDR
except Exception:                       # pragma: no cover
    BADADDR = 0xFFFFFFFFFFFFFFFF

# ------------------------------- customization ------------------------------
FEEDER_LOOKBACK   = 16      # how many instructions to walk back for the cmp/test
COLOR_BRANCHES    = False   # auto-tint conditional lines when listing
BRANCH_COLOR      = 0xC0FFC0  # BGR pastel green for taken-branch lines
VERBOSE           = True
# ----------------------------------------------------------------------------

_TAG = "[conds]"

# ---- condition-suffix -> (signedness, plain English) -----------------------
#  keyed by the cc suffix shared across Jcc / SETcc / CMOVcc.
_CC = {
    "o":   ("",  "overflow (OF=1)"),
    "no":  ("",  "no overflow (OF=0)"),
    "b":   ("u", "unsigned <  (CF=1)"),
    "c":   ("u", "unsigned <  (CF=1)"),
    "nae": ("u", "unsigned <  (CF=1)"),
    "ae":  ("u", "unsigned >= (CF=0)"),
    "nb":  ("u", "unsigned >= (CF=0)"),
    "nc":  ("u", "unsigned >= (CF=0)"),
    "e":   ("",  "==          (ZF=1)"),
    "z":   ("",  "==          (ZF=1)"),
    "ne":  ("",  "!=          (ZF=0)"),
    "nz":  ("",  "!=          (ZF=0)"),
    "be":  ("u", "unsigned <= (CF=1 | ZF=1)"),
    "na":  ("u", "unsigned <= (CF=1 | ZF=1)"),
    "a":   ("u", "unsigned >  (CF=0 & ZF=0)"),
    "nbe": ("u", "unsigned >  (CF=0 & ZF=0)"),
    "s":   ("",  "negative    (SF=1)"),
    "ns":  ("",  "positive    (SF=0)"),
    "p":   ("",  "parity even (PF=1)"),
    "pe":  ("",  "parity even (PF=1)"),
    "np":  ("",  "parity odd  (PF=0)"),
    "po":  ("",  "parity odd  (PF=0)"),
    "l":   ("s", "signed <    (SF!=OF)"),
    "nge": ("s", "signed <    (SF!=OF)"),
    "ge":  ("s", "signed >=   (SF=OF)"),
    "nl":  ("s", "signed >=   (SF=OF)"),
    "le":  ("s", "signed <=   (ZF=1 | SF!=OF)"),
    "ng":  ("s", "signed <=   (ZF=1 | SF!=OF)"),
    "g":   ("s", "signed >    (ZF=0 & SF=OF)"),
    "nle": ("s", "signed >    (ZF=0 & SF=OF)"),
}

# counting-register conditionals (no flags involved)
_CXZ = {
    "jcxz":  "CX == 0",
    "jecxz": "ECX == 0",
    "jrcxz": "RCX == 0",
}
_LOOP = {
    "loop":   "dec (r/e)cx; jump while cx != 0",
    "loope":  "dec (r/e)cx; jump while cx != 0 AND ZF=1",
    "loopz":  "dec (r/e)cx; jump while cx != 0 AND ZF=1",
    "loopne": "dec (r/e)cx; jump while cx != 0 AND ZF=0",
    "loopnz": "dec (r/e)cx; jump while cx != 0 AND ZF=0",
}

# instructions that set the flags a Jcc consumes (for feeder pairing)
_FLAG_SETTERS = {
    "cmp", "test", "add", "sub", "adc", "sbb", "and", "or", "xor",
    "inc", "dec", "neg", "shl", "shr", "sar", "sal", "rol", "ror",
    "rcl", "rcr", "bt", "bts", "btr", "btc", "mul", "imul", "div",
    "idiv", "cmpxchg", "xadd", "bsf", "bsr", "lzcnt", "tzcnt", "popcnt",
    "cmps", "scas", "cmpsb", "cmpsw", "cmpsd", "cmpsq", "scasb", "scasw",
}
_DIRECT_CMP = {"cmp", "test"}


def _log(msg):
    if VERBOSE:
        print("%s %s" % (_TAG, msg))


def _mnem(ea):
    return (idc.print_insn_mnem(ea) or "").lower()


def _is_cond_jump(m):
    return m.startswith("j") and m != "jmp" and m not in _CXZ


def _is_branchy(m):
    """Any control-flow instruction that ends a basic block."""
    return (m.startswith("j") or m in _LOOP or m == "call"
            or m in ("ret", "retn", "retf", "iret", "iretd", "iretq"))


def _in_func(func, ea):
    try:
        return ida_funcs.func_contains(func, ea)
    except Exception:
        return func.start_ea <= ea < func.end_ea


def _classify(ea):
    """Return (kind, cc_suffix, meaning, signedness) or None if not a condition."""
    m = _mnem(ea)
    if not m:
        return None
    if m in _CXZ:
        return ("BRANCH", m, _CXZ[m], "")
    if m in _LOOP:
        return ("LOOP", m, _LOOP[m], "")
    if _is_cond_jump(m):
        suf = m[1:]
        sign, text = _CC.get(suf, ("", "conditional (%s)" % suf))
        return ("BRANCH", m, text, sign)
    if m.startswith("set"):
        suf = m[3:]
        sign, text = _CC.get(suf, ("", "set-if (%s)" % suf))
        return ("SETcc", m, text, sign)
    if m.startswith("cmov"):
        suf = m[4:]
        sign, text = _CC.get(suf, ("", "cmov-if (%s)" % suf))
        return ("CMOVcc", m, text, sign)
    return None


def _find_feeder(heads, idx):
    """Walk back from heads[idx] within the same block for the flag setter."""
    lo = max(0, idx - FEEDER_LOOKBACK)
    for j in range(idx - 1, lo - 1, -1):
        ea = heads[j]
        m = _mnem(ea)
        if _is_branchy(m):          # crossed a block boundary / flag-clobber
            break
        if m in _FLAG_SETTERS:
            return ea, (m in _DIRECT_CMP)
    return None, False


def _target_desc(func, ea, kind):
    """Return (target_ea or None, human string) for the branch target."""
    if kind not in ("BRANCH", "LOOP"):
        return None, "-"
    tgt = idc.get_operand_value(ea, 0)
    if tgt in (None, BADADDR) or tgt == 0:
        # register/indirect conditional target (rare); show operand text
        return None, (idc.print_operand(ea, 0) or "?")
    direction = "back" if tgt <= ea else "fwd "
    if _in_func(func, tgt):
        return tgt, "%s  %X (in-func)" % (direction, tgt)
    name = idc.get_name(tgt) or idc.get_func_name(tgt) or ""
    tag = (" %s" % name) if name else ""
    return tgt, "%s  %X  << EXTERNAL%s >>" % (direction, tgt, tag)


def collect_conditions(ea=None):
    """Analyze the function containing `ea` (default: cursor).
    Returns (func, rows) where each row is a dict; rows is [] if none."""
    if ea is None:
        ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func is None:
        _log("no function at %X - put the cursor inside a function." % ea)
        return None, []

    heads = list(idautils.FuncItems(func.start_ea))   # respects all chunks
    index_of = {h: i for i, h in enumerate(heads)}
    rows = []
    for i, h in enumerate(heads):
        info = _classify(h)
        if not info:
            continue
        kind, mnem, meaning, sign = info
        tgt, tgt_txt = _target_desc(func, h, kind)
        feeder_ea, direct = _find_feeder(heads, i)
        rows.append({
            "ea": h,
            "kind": kind,
            "mnem": mnem,
            "cc": (mnem[1:] if kind == "BRANCH" and mnem not in _CXZ else mnem),
            "sign": {"s": "signed", "u": "unsigned", "": ""}[sign],
            "meaning": meaning,
            "disasm": idc.GetDisasm(h) or "",
            "target": tgt,
            "target_txt": tgt_txt,
            "external": (tgt is not None and not _in_func(func, tgt)),
            "fallthrough": idc.next_head(h, func.end_ea),
            "feeder_ea": feeder_ea,
            "feeder": (idc.GetDisasm(feeder_ea) if feeder_ea else "?"),
            "feeder_direct": direct,
        })
    return func, rows


# ----------------------------------------------------------------------------
# text output
# ----------------------------------------------------------------------------
def _summary(func, rows):
    branches = [r for r in rows if r["kind"] == "BRANCH"]
    loops = [r for r in rows if r["kind"] == "LOOP"]
    sets = [r for r in rows if r["kind"] == "SETcc"]
    cmov = [r for r in rows if r["kind"] == "CMOVcc"]
    ext = [r for r in rows if r["external"]]
    name = idc.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)
    _log("function %s  [%X - %X]" % (name, func.start_ea, func.end_ea))
    _log("  %d conditional branch(es), %d loop(s), %d SETcc, %d CMOVcc; "
         "%d target(s) leave the function"
         % (len(branches), len(loops), len(sets), len(cmov), len(ext)))


def conditions_text(ea=None):
    """Print the conditions as a plain text table (no chooser)."""
    func, rows = collect_conditions(ea)
    if func is None:
        return []
    _summary(func, rows)
    if not rows:
        _log("  (no conditions in this function)")
        return rows
    print("%s   %-16s %-7s %-8s %-26s %-26s %s"
          % (_TAG, "address", "kind", "mnem", "meaning", "target", "feeds-from"))
    for r in rows:
        print("%s   %-16X %-7s %-8s %-26s %-26s %s"
              % (_TAG, r["ea"], r["kind"], r["mnem"],
                 r["meaning"], r["target_txt"],
                 ("%X %s" % (r["feeder_ea"], "cmp/test" if r["feeder_direct"]
                             else "(arith)")) if r["feeder_ea"] else "?"))
    _globals_store(rows)
    return rows


# ----------------------------------------------------------------------------
# chooser
# ----------------------------------------------------------------------------
class _CondChooser(ida_kernwin.Choose):
    def __init__(self, title, func, rows):
        cols = [
            ["Address",     ida_kernwin.Choose.CHCOL_HEX | 16],
            ["Kind",        8],
            ["Cond",        6],
            ["S/U",         8],
            ["Meaning",     26],
            ["Target",      30],
            ["Instruction", 40],
            ["Feeds from (flags set by)", 44],
        ]
        ida_kernwin.Choose.__init__(
            self, title, cols,
            flags=ida_kernwin.Choose.CH_RESTORE | ida_kernwin.Choose.CH_CAN_REFRESH)
        self.func = func
        self.rows = rows
        self.items = [self._fmt(r) for r in rows]

    def _fmt(self, r):
        if r["feeder_ea"]:
            feeder = "%X  %s" % (r["feeder_ea"], r["feeder"])
        else:
            feeder = "?"
        return [
            "%X" % r["ea"],
            r["kind"],
            r["cc"],
            r["sign"],
            r["meaning"],
            r["target_txt"],
            r["disasm"],
            feeder,
        ]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetLineAttr(self, n):
        # tint rows whose target leaves the function so they stand out
        if 0 <= n < len(self.rows) and self.rows[n]["external"]:
            return [0xE0E0FF, 0]        # light red-ish (BGR), normal style
        return None

    def _jump(self, n):
        idx = n[0] if isinstance(n, (list, tuple)) else n
        if idx is not None and 0 <= idx < len(self.rows):
            ida_kernwin.jumpto(self.rows[idx]["ea"])

    def OnSelectLine(self, n):
        self._jump(n)
        nc = getattr(ida_kernwin.Choose, "NOTHING_CHANGED", None)
        return (nc, ) if nc is not None else None

    def OnRefresh(self, n):
        self.func, self.rows = collect_conditions(
            self.func.start_ea if self.func else None)
        self.items = [self._fmt(r) for r in self.rows]
        return None


def conditions(ea=None):
    """Analyze the function at `ea` (default cursor) and open the jump-list."""
    func, rows = collect_conditions(ea)
    if func is None:
        return None
    _summary(func, rows)
    _globals_store(rows)
    if COLOR_BRANCHES:
        color_conditions(rows)
    if not rows:
        _log("  (no conditions here - nothing to list)")
        return None
    name = idc.get_func_name(func.start_ea) or ("sub_%X" % func.start_ea)
    ch = _CondChooser("Conditions: %s" % name, func, rows)
    ch.Show()
    return ch


# ----------------------------------------------------------------------------
# keyboard navigation (stays inside the current function)
# ----------------------------------------------------------------------------
_last_rows = []


def _globals_store(rows):
    global _last_rows
    _last_rows = rows


def _branch_addrs(ea=None):
    _func, rows = collect_conditions(ea)
    return [r["ea"] for r in rows if r["kind"] in ("BRANCH", "LOOP")]


def next_condition(ea=None):
    """Jump to the next conditional branch after the cursor, within the func."""
    if ea is None:
        ea = idc.get_screen_ea()
    addrs = _branch_addrs(ea)
    nxt = [a for a in addrs if a > ea]
    if nxt:
        ida_kernwin.jumpto(nxt[0])
        return nxt[0]
    if addrs:
        _log("wrapped to first branch")
        ida_kernwin.jumpto(addrs[0])
        return addrs[0]
    _log("no conditional branches in this function")
    return None


def prev_condition(ea=None):
    """Jump to the previous conditional branch before the cursor, within func."""
    if ea is None:
        ea = idc.get_screen_ea()
    addrs = _branch_addrs(ea)
    prv = [a for a in addrs if a < ea]
    if prv:
        ida_kernwin.jumpto(prv[-1])
        return prv[-1]
    if addrs:
        _log("wrapped to last branch")
        ida_kernwin.jumpto(addrs[-1])
        return addrs[-1]
    _log("no conditional branches in this function")
    return None


def goto_condition(index):
    """Jump to the Nth condition (0-based) from the most recent listing."""
    if not _last_rows:
        _log("run conditions() first")
        return None
    if index < 0 or index >= len(_last_rows):
        _log("index out of range (0..%d)" % (len(_last_rows) - 1))
        return None
    ea = _last_rows[index]["ea"]
    ida_kernwin.jumpto(ea)
    return ea


# short aliases
def nc():
    return next_condition()


def pc():
    return prev_condition()


# ----------------------------------------------------------------------------
# coloring (QoL)
# ----------------------------------------------------------------------------
def color_conditions(rows=None, ea=None):
    """Tint every conditional-branch line in the function."""
    if rows is None:
        _func, rows = collect_conditions(ea)
    n = 0
    for r in rows:
        if r["kind"] in ("BRANCH", "LOOP"):
            idc.set_color(r["ea"], idc.CIC_ITEM, BRANCH_COLOR)
            n += 1
    _log("tinted %d branch line(s)" % n)
    return n


def uncolor_conditions(ea=None):
    """Remove line tint from conditional branches in the function."""
    _func, rows = collect_conditions(ea)
    DEFAULT = 0xFFFFFFFF
    for r in rows:
        idc.set_color(r["ea"], idc.CIC_ITEM, DEFAULT)
    _log("cleared tint on %d line(s)" % len(rows))


# ----------------------------------------------------------------------------
# bootstrap
# ----------------------------------------------------------------------------
_hotkeys = []


def _bind(seq, fn):
    try:
        ctx = ida_kernwin.add_hotkey(seq, fn)
        if ctx:
            _hotkeys.append(ctx)
            _log("hotkey %s -> %s()" % (seq, fn.__name__))
    except Exception as e:
        _log("could not bind %s: %s" % (seq, e))


def _bootstrap():
    _bind("Ctrl-Alt-C", conditions)
    _bind("Ctrl-Alt-N", nc)
    _bind("Ctrl-Alt-B", pc)
    _log("ready. conditions() = jump-list for this function; nc()/pc() = "
         "next/prev branch (stays in-function); conditions_text() = paste-able "
         "table; color_conditions()/uncolor_conditions().")


_bootstrap()
