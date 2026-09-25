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
#  hops along single, unconditional transfers - direct `jmp`, `push addr; ret`,
#  a lone tail `call`, or a fall-through into the next function - until it
#  reaches the first SUBSTANTIVE function: one with real control flow
#  (conditional branches / a loop), several distinct calls, or that reads input.
#  That terminus is the real code the chain was hiding.
#
#  It is purely static (no debugger) and read-only by default (it only adds a
#  comment and moves the cursor; pass rename=True to name the terminus).
#
#  What stops the walk
#    * a function with conditional branches (a real CFG) - substantive
#    * more than one distinct outgoing jump target - a real branch
#    * an indirect/`jmp reg` or import tail-call that cannot be resolved
#      statically (reported, so you know the single spot to breakpoint)
#    * a cycle, or the hop cap
#
#  Console interface
#    find_main()                 trace from the entry point to the real code,
#                                jump there, and report the path
#    trace_chain(start=None)     trace from `start` (default: cursor); jump to
#                                the terminus
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

# small trampoline body: at most this many instructions to follow a lone `call`
_CH_SMALL = 48

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
def _ch_pick(transfers, n_cond, n_insn, follow_calls):
    """Decide the single chain successor for one function.

    transfers : list of (kind, target) with kind in {'jmp', 'call'}, already
                filtered to targets OUTSIDE the function.
    n_cond    : number of conditional branches in the function.
    n_insn    : instruction count.
    Returns (kind, target) to follow, or None if the function is substantive
    (a real branch / body) or the successor is ambiguous."""
    if n_cond > 0:                         # a real control-flow graph -> stop
        return None
    jmps = sorted({t for k, t in transfers if k == "jmp"})
    calls = sorted({t for k, t in transfers if k == "call"})
    if len(jmps) > 1:                      # branches to several places -> stop
        return None
    if len(jmps) == 1:
        return ("jmp", jmps[0])
    if follow_calls and len(calls) == 1 and n_insn <= _CH_SMALL:
        return ("call", calls[0])
    return None


def _ch_walk(start, get_succ, max_hops=1000000):
    """Follow successors from `start`. get_succ(ea) -> (target|None, kind).
    Returns (chain, reason) with reason in {'terminus','loop','max_hops',
    'unresolved'}. Pure: the resolver is injected."""
    chain = [start]
    seen = {start}
    cur = start
    for _ in range(max_hops):
        nxt, kind = get_succ(cur)
        if nxt is None:
            return chain, ("unresolved" if kind == "unresolved" else "terminus")
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


def _ch_is_uncond_jmp(mnem):
    return mnem == "jmp"


def _ch_is_cond_jmp(mnem):
    return mnem.startswith("j") and mnem != "jmp"


def _ch_ida_succ(ea, follow_calls=True):
    """Resolve the chain successor of the function containing `ea`.
    Returns (target|None, kind). kind='unresolved' flags an indirect tail
    transfer (jmp reg / jmp [mem]) that only a debugger could follow."""
    f = ida_funcs.get_func(ea)
    if not f:
        return (None, None)
    items = list(idautils.FuncItems(f.start_ea))
    if not items:
        return (None, None)
    transfers = []
    n_cond = 0
    n_insn = 0
    unresolved_tail = False
    prev_push_imm = None

    for ie in items:
        mnem = (idc.print_insn_mnem(ie) or "").lower()
        if not mnem:
            continue
        n_insn += 1
        if _ch_is_uncond_jmp(mnem):
            ot = idc.get_operand_type(ie, 0)
            tv = idc.get_operand_value(ie, 0)
            if ot in (O_NEAR, O_FAR) and tv not in (None, BADADDR):
                if not (f.start_ea <= tv < f.end_ea):
                    transfers.append(("jmp", tv))
            else:
                unresolved_tail = True     # jmp reg / jmp [mem]
        elif mnem == "call":
            ot = idc.get_operand_type(ie, 0)
            tv = idc.get_operand_value(ie, 0)
            if ot in (O_NEAR, O_FAR) and tv not in (None, BADADDR) \
                    and not (f.start_ea <= tv < f.end_ea):
                transfers.append(("call", tv))
        elif _ch_is_cond_jmp(mnem):
            n_cond += 1

        if mnem == "push" and idc.get_operand_type(ie, 0) == O_IMM:
            prev_push_imm = idc.get_operand_value(ie, 0)
        elif mnem in ("retn", "ret", "retf"):
            if prev_push_imm is not None:          # push addr; ret  -> tail jump
                if not (f.start_ea <= prev_push_imm < f.end_ea):
                    transfers.append(("jmp", prev_push_imm))
            prev_push_imm = None
        else:
            prev_push_imm = None

    # fall-through into the next function (IDA split the chain into _0, _0_0 ...)
    last = items[-1]
    lm = (idc.print_insn_mnem(last) or "").lower()
    if lm and lm not in ("ret", "retn", "retf", "jmp") and not lm.startswith("int"):
        nh = idc.next_head(last, f.end_ea + 0x40)
        if nh == f.end_ea and ida_funcs.get_func(f.end_ea):
            transfers.append(("jmp", f.end_ea))

    pick = _ch_pick(transfers, n_cond, n_insn, follow_calls)
    if pick is None:
        if unresolved_tail and n_cond == 0 and not transfers:
            return (None, "unresolved")
        return (None, None)
    target, kind = pick[1], pick[0]
    if ida_funcs.get_func(target) is None:
        # target is not a defined function yet - report it as the landing spot
        return (None, "undefined:%X" % target)
    return (target, kind)


def _ch_reads_input(ea):
    """True if the function at `ea` calls a known input-reading API."""
    f = ida_funcs.get_func(ea)
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
    f = ida_funcs.get_func(ea)
    if not f:
        _ch_log("no function at %X - place the cursor in a function or pass one"
                % ea)
        return None
    chain, reason = _ch_walk(f.start_ea,
                             lambda x: _ch_ida_succ(x, follow_calls), max_hops)
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
            "anywhere; chain_list() reprints; goto_terminus() jumps to the end.")


_ch_bootstrap()
