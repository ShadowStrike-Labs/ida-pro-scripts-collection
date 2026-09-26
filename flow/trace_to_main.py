# ============================================================================
#  trace_to_main.py - follow a trampoline / tail-call chain to the real code
# ----------------------------------------------------------------------------
#  Some binaries bury their entry logic behind a chain of pass-through
#  functions: `start` ends in `jmp start_0`, which ends in `jmp start_0_0`, and
#  so on for an arbitrary depth. IDA names each hop `_0`, `_0_0`, ... and
#  double-clicking only walks one link at a time; in the debugger single-step
#  crawls one hop while run just sails past the interesting code. Neither lets
#  you land on `main`.
#
#  This follows the chain statically. From an entry point (or the cursor) it
#  hops along the single unconditional TAIL transfer to a non-library function
#  - a direct `jmp`, a `push addr; ret`, a fall-through into the next function,
#  or (absent those) a lone tail `call` - until it reaches the first SUBSTANTIVE
#  function: one with several real successors, or a leaf. Internal conditional
#  branches and incidental calls to runtime/helper functions are ignored, so an
#  obfuscated layer that still tail-hops to the next layer is followed through.
#
#  It is purely static (no debugger) and read-only by default (it only adds a
#  comment and moves the cursor; pass rename=True to name the terminus).
#
#  What stops the walk
#    * a function with more than one non-library tail successor (a real branch)
#    * a leaf / a function that only calls the runtime and returns
#    * an indirect `jmp reg` / `jmp [mem]` tail-call that cannot be resolved
#      statically (reported, so you know the single spot to breakpoint)
#    * a cycle, the hop cap, or Cancel
#
#  Console interface
#    find_main()                 trace from the entry point to the real code,
#                                jump there, and report the path
#    trace_chain(start=None)     trace from `start` (default: cursor); jump to
#                                the terminus
#    diagnose(ea=None)           explain the transfers + follow decision at one
#                                function (run it where a trace stops early)
#    chain_list()                reprint the last traced chain
#    goto_terminus()             jump to the last terminus
#
#    start accepts a name, an ea (int) or a hex string.
#    Options: follow_calls=True, max_hops=1000000, rename=False.
#
#  Hotkey
#    Ctrl-Alt-M   find_main() from the program entry point
# ============================================================================

import re
import warnings

import ida_funcs
import ida_ua
import ida_kernwin
import idautils
import idc
import idaapi

try:
    import ida_ida
except Exception:                       # pragma: no cover
    ida_ida = None

try:
    BADADDR = idaapi.BADADDR
except Exception:                       # pragma: no cover
    BADADDR = 0xFFFFFFFFFFFFFFFF

_CH_TAG = "[trace2main]"

O_IMM = getattr(ida_ua, "o_imm", 5)
O_NEAR = getattr(ida_ua, "o_near", 7)
O_FAR = getattr(ida_ua, "o_far", 6)
FUNC_LIB = getattr(idaapi, "FUNC_LIB", 0x00000004)
FUNC_THUNK = getattr(idaapi, "FUNC_THUNK", 0x00000080)

# small trampoline body: at most this many instructions to follow a lone `call`
_CH_SMALL = 64

_CH_LIB_NAME_RE = re.compile(
    r"@@|^\?\?|^_Z|^__cxa|^__scrt|^__acrt|^__crt|^_RTC|^__security|^_guard|"
    r"__GSHandler|__C_specific|^__report_gsfailure|^_CxxThrow", re.IGNORECASE)


def _ch_get_func(ea):
    """ida_funcs.get_func without the 9.4 DeprecationWarning noise."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ida_funcs.get_func(ea)


def _ch_name_is_lib(name):
    """True if a function name looks like runtime/CRT/STL/helper code."""
    if not name:
        return False
    if _CH_LIB_NAME_RE.search(name):
        return True
    low = name.lower()
    for h in _CH_RUNTIME_HEADS:
        if low.startswith((h + ".", h + "_", h + "::")):
            return True
    return low.startswith(("system_", "system.", "microsoft_", "s_p_corelib",
                           "__libc_", "_dl_"))


def _ch_is_lib_func(ea):
    """True if the function at `ea` is a library / helper (skip when chaining).
    Undefined targets are treated as non-library (a candidate continuation)."""
    f = _ch_get_func(ea)
    if not f:
        return False
    if f.flags & (FUNC_LIB | FUNC_THUNK):
        return True
    return _ch_name_is_lib(ida_funcs.get_func_name(f.start_ea) or "")

# APIs that indicate the code is reading program input (main-likeness)
_CH_INPUT_API = (
    "readfile", "readconsole", "getstdhandle", "fgets", "gets", "scanf",
    "fscanf", "_read", "read", "recv", "fread", "getline", "std::getline",
    "os.args", "bufio", "os.stdin", "readstring", "readline",
    "getcommandline", "__acrt_iob", "cin", "std::cin",
)

_CH_MAIN_RE = re.compile(r"(^|[._])(w?w?main|wWinMain|WinMain)$", re.IGNORECASE)
_CH_RUNTIME_HEADS = ("runtime", "os", "internal", "std", "core", "alloc",
                     "fmt", "sync", "syscall", "reflect", "time")


# ----------------------------------------------------------------------------
# logging
# ----------------------------------------------------------------------------
def _ch_log(msg):
    print("%s %s" % (_CH_TAG, msg))


def _ch_addr(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        ea = idc.get_name_ea_simple(s)
        if ea != BADADDR:
            return ea
        try:
            return int(s.lower().replace("0x", ""), 16)
        except ValueError:
            return None
    return None


# ----------------------------------------------------------------------------
# pure decision logic (no IDA state - unit-testable offline)
# ----------------------------------------------------------------------------
def _ch_pick(transfers, is_lib, n_insn, follow_calls):
    """Decide the single chain successor for one function.

    transfers : list of (kind, target, cond); kind in {'jmp','fall','call'},
                targets already external and mapped to function starts.
    is_lib    : is_lib(target)->bool, so library/helper targets are skipped.
    Returns (kind, target) to follow, or None if the function is substantive
    (several real successors / a leaf) or the successor is ambiguous.

    The continuation of a trampoline chain is the single UNCONDITIONAL tail
    transfer (jmp / fall-through / push;ret) to a non-library function.
    Internal conditional branches and incidental helper calls are ignored, so
    an obfuscated layer that still tail-hops to the next layer is followed."""
    tails = [t for (k, t, c) in transfers if k in ("jmp", "fall") and not c]
    tail_nonlib = sorted({t for t in tails if not is_lib(t)})
    if len(tail_nonlib) == 1:
        return ("jmp", tail_nonlib[0])
    if len(tail_nonlib) > 1:               # branches to several real places
        return None
    if tails:                              # tails exist but all go to library
        return None
    if follow_calls and n_insn <= _CH_SMALL:
        calls_nonlib = sorted({t for (k, t, c) in transfers
                               if k == "call" and not c and not is_lib(t)})
        if len(calls_nonlib) == 1:
            return ("call", calls_nonlib[0])
    return None


def _ch_walk(start, get_succ, max_hops=1000000, on_step=None):
    """Follow successors from `start`. get_succ(ea) -> (target|None, reason).
    Returns (chain, reason). Pure: the resolver and the optional on_step
    (progress/cancel) callback are injected. on_step(i, ea) returning False
    aborts with reason 'cancelled'."""
    chain = [start]
    seen = {start}
    cur = start
    for i in range(max_hops):
        if on_step is not None and on_step(i, cur) is False:
            return chain, "cancelled"
        nxt, reason = get_succ(cur)
        if nxt is None:
            return chain, (reason or "terminus")
        if nxt in seen:
            chain.append(nxt)
            return chain, "loop"
        chain.append(nxt)
        seen.add(nxt)
        cur = nxt
    return chain, "max_hops"


def _ch_is_main_name(name):
    if not name:
        return False
    low = name.lower()
    if low in ("main", "_main", "wmain", "winmain", "wwinmain",
               "main.main", "start_main"):
        return True
    if low.endswith(("::main", ".main", "__main")):
        head = re.split(r"[.:_]+", low, 1)[0]
        return head not in _CH_RUNTIME_HEADS
    return bool(_CH_MAIN_RE.search(name))


# ----------------------------------------------------------------------------
# IDA-backed successor resolver
# ----------------------------------------------------------------------------
def _ch_func_name(ea):
    return ida_funcs.get_func_name(ea) or ("0x%X" % ea)


def _ch_is_cond_jmp(mnem):
    return mnem.startswith("j") and mnem != "jmp"


def _ch_transfers(ea):
    """Collect external control transfers of the function at `ea`.
    Returns (func, transfers, n_insn, indirect_tail) or None. Each transfer is
    (kind, target_func_start, cond): kind in {'jmp','fall','call'}, cond True
    for a conditional (jcc) edge. Targets are mapped to their function start."""
    f = _ch_get_func(ea)
    if not f:
        return None
    items = list(idautils.FuncItems(f.start_ea))
    if not items:
        return None
    transfers = []
    n_insn = 0
    indirect_tail = False
    prev_push_imm = None

    def add(kind, tv, cond):
        if tv in (None, BADADDR):
            return
        if f.start_ea <= tv < f.end_ea:          # stays inside -> internal
            return
        g = _ch_get_func(tv)
        tgt = g.start_ea if g else tv
        if tgt == f.start_ea:                    # self reference
            return
        transfers.append((kind, tgt, cond))

    for ie in items:
        mnem = (idc.print_insn_mnem(ie) or "").lower()
        if not mnem:
            continue
        n_insn += 1
        ot = idc.get_operand_type(ie, 0)
        tv = idc.get_operand_value(ie, 0)
        if mnem == "jmp":
            if ot in (O_NEAR, O_FAR):
                add("jmp", tv, False)
            else:
                indirect_tail = True             # jmp reg / jmp [mem]
        elif _ch_is_cond_jmp(mnem):
            if ot in (O_NEAR, O_FAR):
                add("jmp", tv, True)             # conditional inter-proc edge
        elif mnem == "call":
            if ot in (O_NEAR, O_FAR):
                add("call", tv, False)

        if mnem == "push" and ot == O_IMM:
            prev_push_imm = tv
        elif mnem in ("retn", "ret", "retf"):
            if prev_push_imm is not None:        # push addr; ret -> tail jump
                add("jmp", prev_push_imm, False)
            prev_push_imm = None
        else:
            prev_push_imm = None

    last = items[-1]
    lm = (idc.print_insn_mnem(last) or "").lower()
    if lm and lm not in ("ret", "retn", "retf", "jmp") and not lm.startswith("int"):
        nh = idc.next_head(last, f.end_ea + 0x40)
        if nh == f.end_ea and _ch_get_func(f.end_ea):
            add("fall", f.end_ea, False)         # split chain: _0 -> _0_0
    return f, transfers, n_insn, indirect_tail


def _ch_ida_succ(ea, follow_calls=True):
    """Resolve the chain successor of the function at `ea`.
    Returns (target|None, reason). reason 'unresolved' flags an indirect tail
    transfer; 'undefined:XX' flags a target that is not a defined function."""
    info = _ch_transfers(ea)
    if info is None:
        return (None, None)
    f, transfers, n_insn, indirect_tail = info
    pick = _ch_pick(transfers, _ch_is_lib_func, n_insn, follow_calls)
    if pick is None:
        tails = [t for (k, t, c) in transfers if k in ("jmp", "fall") and not c]
        if indirect_tail and not any(not _ch_is_lib_func(t) for t in tails):
            return (None, "unresolved")
        return (None, None)
    target = pick[1]
    if _ch_get_func(target) is None:
        return (None, "undefined:%X" % target)
    return (target, pick[0])


def _ch_reads_input(ea):
    """True if the function at `ea` calls a known input-reading API."""
    f = _ch_get_func(ea)
    if not f:
        return False
    for ie in idautils.FuncItems(f.start_ea):
        if (idc.print_insn_mnem(ie) or "").lower() in ("call", "jmp"):
            tv = idc.get_operand_value(ie, 0)
            nm = (idc.get_name(tv) or "").lower()
            if nm and any(api in nm for api in _CH_INPUT_API):
                return True
    return False


def _ch_entry():
    if ida_ida is not None:
        try:
            ea = ida_ida.inf_get_start_ea()
            if ea not in (0, BADADDR):
                return ea
        except Exception:
            pass
    try:
        ea = idc.get_inf_attr(idc.INF_START_EA)
        if ea not in (0, BADADDR):
            return ea
    except Exception:
        pass
    for nm in ("start", "_start", "mainCRTStartup", "wmainCRTStartup",
               "WinMainCRTStartup", "_rt0_amd64_windows", "__mainCRTStartup"):
        ea = idc.get_name_ea_simple(nm)
        if ea != BADADDR:
            return ea
    return None


# ----------------------------------------------------------------------------
# commands
# ----------------------------------------------------------------------------
_ch_last_chain = []
_ch_last_reason = ""


def _ch_report(chain, reason):
    _ch_log("chain of %d hop(s):" % len(chain))
    for i, ea in enumerate(chain):
        tag = ""
        if _ch_is_main_name(_ch_func_name(ea)):
            tag += "  <-- main-like name"
        if _ch_reads_input(ea):
            tag += "  <-- reads input"
        arrow = "    " if i else "start "
        _ch_log("  %s%2d  %012X  %s%s" % (arrow, i, ea, _ch_func_name(ea), tag))
    notes = {
        "terminus": "landed on the first substantive function (the real code).",
        "loop": "the chain loops back on itself (dispatcher / obfuscator).",
        "max_hops": "hit the hop cap; raise max_hops if the chain is longer.",
        "cancelled": "cancelled; re-run to continue (raise max_hops if needed).",
    }
    if reason.startswith("undefined:"):
        ea = int(reason.split(":", 1)[1], 16)
        _ch_log("stopped: the next target %X is not a defined function. Press C "
                "(code) / P (make function) there, then re-run." % ea)
    elif reason == "unresolved":
        _ch_log("stopped: the tail transfer is indirect (jmp reg / jmp [mem]). "
                "This is the ONE spot to breakpoint in the debugger; its target "
                "is the next hop.")
    else:
        _ch_log(notes.get(reason, reason))


def trace_chain(start=None, follow_calls=True, max_hops=1000000, rename=False):
    """Follow the trampoline/tail-call chain from `start` (default: cursor) to
    the first substantive function, jump there, and print the path."""
    global _ch_last_chain, _ch_last_reason
    ea = _ch_addr(start) if start is not None else idc.get_screen_ea()
    if ea is None or ea == BADADDR:
        _ch_log("no start address")
        return None
    f = _ch_get_func(ea)
    if not f:
        _ch_log("no function at %X - place the cursor in a function or pass one"
                % ea)
        return None

    def _step(i, cur):
        if i and i % 512 == 0:
            if ida_kernwin.user_cancelled():
                return False
            ida_kernwin.replace_wait_box("trace2main: %d hops..." % i)
        return True

    ida_kernwin.show_wait_box("trace2main: following chain (Cancel to stop)")
    try:
        chain, reason = _ch_walk(
            f.start_ea, lambda x: _ch_ida_succ(x, follow_calls), max_hops, _step)
    finally:
        ida_kernwin.hide_wait_box()

    _ch_last_chain, _ch_last_reason = chain, reason
    _ch_report(chain, reason)
    terminus = chain[-1]
    if reason == "terminus":
        idc.set_cmt(terminus, "trace2main: chain terminus (%d hops from %s)"
                    % (len(chain) - 1, _ch_func_name(chain[0])), 0)
        if rename and not _ch_is_main_name(_ch_func_name(terminus)):
            idc.set_name(terminus, "traced_main", idc.SN_NOWARN)
    ida_kernwin.jumpto(terminus)
    _ch_log("cursor moved to %012X (%s)" % (terminus, _ch_func_name(terminus)))
    return terminus


def diagnose(ea=None):
    """Explain what the tracer sees at one function: its external transfers,
    how each is classified, and the follow decision. Run this where a trace
    stops unexpectedly to understand (and tune) the result."""
    e = _ch_addr(ea) if ea is not None else idc.get_screen_ea()
    info = _ch_transfers(e)
    if info is None:
        _ch_log("no function at %X" % (e or 0))
        return None
    f, transfers, n_insn, indirect_tail = info
    _ch_log("function %s  [%X, %X)  insn=%d  indirect_tail=%s"
            % (_ch_func_name(f.start_ea), f.start_ea, f.end_ea, n_insn,
               indirect_tail))
    if not transfers:
        _ch_log("  no external transfers (leaf / returns) -> terminus")
    for kind, tgt, cond in transfers:
        _ch_log("  %-5s %-11s %012X  %-28s %s"
                % (kind, "conditional" if cond else "uncond", tgt,
                   _ch_func_name(tgt),
                   "[library/helper]" if _ch_is_lib_func(tgt) else "[continuation]"))
    pick = _ch_pick(transfers, _ch_is_lib_func, n_insn, True)
    if pick is None:
        tails = [t for (k, t, c) in transfers if k in ("jmp", "fall") and not c]
        nonlib = [t for t in tails if not _ch_is_lib_func(t)]
        if indirect_tail and not nonlib:
            _ch_log("decision: STOP (indirect tail - breakpoint here to get the "
                    "target).")
        elif len(nonlib) > 1:
            _ch_log("decision: STOP (%d non-library tail successors - a real "
                    "branch). Follow one explicitly with trace_chain(0x%X)."
                    % (len(nonlib), nonlib[0]))
        else:
            _ch_log("decision: STOP (substantive / no single continuation).")
    else:
        _ch_log("decision: FOLLOW %s -> %012X (%s)"
                % (pick[0], pick[1], _ch_func_name(pick[1])))
    return None


def find_main(follow_calls=True, max_hops=1000000, rename=False):
    """Trace from the program entry point to the real code."""
    ea = _ch_entry()
    if ea is None:
        _ch_log("could not locate the entry point; use trace_chain(start).")
        return None
    _ch_log("entry point: %012X (%s)" % (ea, _ch_func_name(ea)))
    terminus = trace_chain(ea, follow_calls, max_hops, rename)
    if terminus is None:
        return None
    # highlight the best main candidate anywhere along the path
    named = [e for e in _ch_last_chain if _ch_is_main_name(_ch_func_name(e))]
    io = [e for e in _ch_last_chain if _ch_reads_input(e)]
    if named:
        _ch_log("main-like name on the path: %s @ %012X"
                % (_ch_func_name(named[-1]), named[-1]))
    if io:
        _ch_log("input is read at: %s @ %012X"
                % (_ch_func_name(io[0]), io[0]))
    if not named and not io:
        _ch_log("no name/I/O anchor matched; the terminus above is the real "
                "code the chain led to.")
    return terminus


def chain_list():
    """Reprint the last traced chain."""
    if not _ch_last_chain:
        _ch_log("no chain traced yet - run find_main() or trace_chain().")
        return None
    _ch_report(_ch_last_chain, _ch_last_reason)
    return list(_ch_last_chain)


def goto_terminus():
    """Jump to the last terminus."""
    if not _ch_last_chain:
        _ch_log("no chain traced yet.")
        return None
    ida_kernwin.jumpto(_ch_last_chain[-1])
    return _ch_last_chain[-1]


# ----------------------------------------------------------------------------
# bootstrap
# ----------------------------------------------------------------------------
_ch_hotkey = None


def _ch_bootstrap():
    global _ch_hotkey
    try:
        _ch_hotkey = ida_kernwin.add_hotkey("Ctrl-Alt-M", find_main)
    except Exception as exc:
        _ch_log("could not bind hotkey: %s" % exc)
    _ch_log("ready. find_main() traces the entry point through the trampoline "
            "chain to the real code (Ctrl-Alt-M); trace_chain(start) traces from "
            "anywhere; diagnose(ea) explains why a trace stops; chain_list() "
            "reprints; goto_terminus() jumps to the end.")


_ch_bootstrap()
