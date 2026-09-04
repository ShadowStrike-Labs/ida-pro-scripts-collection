# ============================================================================
#  auto_tailjump.py  -  IDAPython: automate + INSTRUMENT the packer/VM stepping
# ----------------------------------------------------------------------------
#  Peels one "layer" per Ctrl-Alt-J (or tailjump(n)) in a threaded-code VM:
#     function end ('endp') -> N instr up -> F4 -> F8 x M -> at 'jmp reg' F7.
#
#  This build is for finding the DECISION (flag check) without eyeballing
#  hundreds of layers by hand. For every handler it visits it statically
#  records, per layer:
#     * the terminating branch      (jmp rax / jmp r10 / ret / ...)
#     * every call target           (call sub_X / call cs:ExitProcess / call rax)
#     * conditional instructions    (cmp / test / cmovcc / setcc / jcc)
#     * instruction count
#  and at the end it prints WHICH layers had calls / conditionals / API calls,
#  plus call-target frequency. That is where the VM branch + I/O + exit live.
#
#  Everything is switchable (below). Handler analysis is cached per entry
#  address, so repeated handlers cost nothing.
#
#  Verified API (IDA SDK dbg.hpp): run_to/step_over/step_into async; wait with
#  wait_for_next_event(WFNE_SUSP,t) (>0 real event, <=0 timeout/error).
# ============================================================================

import collections
import os

import ida_dbg
import ida_funcs
import ida_ua
import ida_auto
import ida_kernwin
import idaapi
import idc

# ------------------------------- customization ------------------------------
LINES_UP_FROM_END     = 2          # instr heads above 'endp' for run-to-cursor
NUM_STEP_OVERS        = 1          # F8 count after run-to-cursor
STEP_INTO_MNEMS       = ("jmp",)   # step INTO when current mnem is one of these
STEP_INTO_REG_ONLY    = True       # ...and target is a register (jmp rax/...)
HUNT_LIMIT            = 40          # max step-overs while hunting the branch
STEP_TIMEOUT          = 10         # SECONDS per step; finite -> runaway becomes
                                   # a logged timeout instead of a frozen IDA
DISABLE_AUTO_ANALYSIS = True       # turn analysis off during tailjump(n)

# ---- logging switches (not everyone wants the verbose view) ----
LOG_TO_FILE           = True       # master: write the log file at all
LOG_ANATOMY           = True       # per-handler term/calls/conds/insn count
REG_SNAPSHOT          = False      # log rcx,rdx,r8,r9,rax at each landing
COMMENT_LANDINGS      = False      # drop an IDB comment at each landing
PROGRESS_EVERY        = 100
LOOP_WARN_COUNT       = 3
VERBOSE               = True       # also print to the IDA output window

# ---- QoL: stop right before entering a specific handler (e.g. the ExitProcess
#      handler). Put its ENTRY address here as a hex string; "" disables.
STOP_AT_HANDLER       = ""         # e.g. "7FF61E15DE21"

# Resolve the log path relative to this script so the tool stays portable
# (no hard-coded, machine-specific path). Falls back to the CWD when __file__
# is unavailable (e.g. when the script is pasted into the console).
_TJ_DIR = os.path.dirname(os.path.abspath(__file__)) if globals().get("__file__") else os.getcwd()
LOG_FILE = os.path.normpath(os.path.join(_TJ_DIR, "..", "logs", "tailjump_log.txt"))
# ----------------------------------------------------------------------------

O_REG = getattr(ida_ua, "o_reg", 1)
_REGS = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
         "eax", "ebx", "ecx", "edx", "esi", "edi"}
_anat_cache = {}


def _log(msg, to_file=True):
    line = "[tailjump] " + msg
    if VERBOSE:
        print(line)
    if to_file and LOG_TO_FILE and LOG_FILE:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass


def _ip():
    for reg in ("RIP", "EIP"):
        try:
            return idc.get_reg_value(reg)
        except Exception:
            pass
    return None


def _wait():
    return ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, STEP_TIMEOUT) > 0


def _capture_runaway():
    try:
        ida_dbg.suspend_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
    except Exception:
        pass
    ip = _ip()
    if ip is None:
        _log("  runaway: could not read IP after suspend (process may have exited)")
    else:
        _log("  runaway @ %X  seg=%s  %s" % (ip, idc.get_segm_name(ip) or "?", idc.GetDisasm(ip) or ""))


def _is_indirect_branch(ea):
    mnem = (idc.print_insn_mnem(ea) or "").lower()
    if mnem not in STEP_INTO_MNEMS:
        return False
    if STEP_INTO_REG_ONLY:
        return idc.get_operand_type(ea, 0) == O_REG
    return True


def _func_end_target(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    tgt = f.end_ea
    for _ in range(max(1, LINES_UP_FROM_END)):
        tgt = idc.prev_head(tgt)
    return tgt


def _branch_target(branch_ea):
    """Resolve the runtime target of 'jmp reg' by reading that register."""
    op = (idc.print_operand(branch_ea, 0) or "").strip().lower()
    if op in _REGS:
        try:
            return idc.get_reg_value(op)
        except Exception:
            return None
    return None


def _looks_api(sym):
    s = (sym or "").strip()
    if ":" in s:                       # segment-qualified import, e.g. cs:ExitProcess
        return True
    low = s.lower()
    if low in _REGS:
        return False
    if low.startswith(("sub_", "loc_", "unk_", "off_", "j_", "$", "short", "byte_", "qword_", "dword_")):
        return False
    return s[:1].isalpha()


def _handler_anatomy(entry):
    """Static, cached: walk a handler from its entry to the function end and
    record calls, conditionals, terminating branch and instruction count."""
    if entry in _anat_cache:
        return _anat_cache[entry]
    res = {"term": "?", "calls": [], "conds": set(), "ninsn": 0}
    f = ida_funcs.get_func(entry)
    end = f.end_ea if f else (entry + 0x400)
    ea, last, guard = entry, entry, 0
    while ea != idaapi.BADADDR and ea < end and guard < 8192:
        mnem = idc.print_insn_mnem(ea) or ""
        ml = mnem.lower()
        if ml == "call":
            res["calls"].append(idc.print_operand(ea, 0) or "?")
        elif ml.startswith("cmov") or ml.startswith("set") or ml in ("cmp", "test") \
                or (ml.startswith("j") and ml != "jmp"):
            res["conds"].add(ml)
        if mnem:
            res["ninsn"] += 1
            last = ea
        nxt = idc.next_head(ea, end)
        if nxt <= ea:
            break
        ea = nxt
        guard += 1
    res["term"] = ((idc.print_insn_mnem(last) or "?") + " " + (idc.print_operand(last, 0) or "")).strip()
    _anat_cache[entry] = res
    return res


def _regsnap():
    out = []
    for r in ("RCX", "RDX", "R8", "R9", "RAX"):
        try:
            out.append("%s=%X" % (r.lower(), idc.get_reg_value(r)))
        except Exception:
            pass
    return "{" + " ".join(out) + "}"


def tailjump_once(layer=None, state=None):
    """Peel one layer. Status: 'ok'|'not_running'|'no_func'|'no_branch'|
    'timeout'|'reached_stop'."""
    tag = ("layer %d: " % layer) if layer is not None else ""
    if not ida_dbg.is_debugger_on():
        _log(tag + "debugger not running")
        return "not_running"

    cur = _ip()
    tgt = _func_end_target(cur)
    if tgt is None:
        _log(tag + "RIP %X not inside a defined function" % (cur or 0))
        return "no_func"

    ida_dbg.run_to(tgt)
    if not _wait():
        _log(tag + "TIMEOUT on run_to(%X) after %ds" % (tgt, STEP_TIMEOUT))
        _capture_runaway()
        return "timeout"

    for i in range(NUM_STEP_OVERS):
        ida_dbg.step_over()
        if not _wait():
            _log(tag + "TIMEOUT on step_over #%d" % (i + 1))
            _capture_runaway()
            return "timeout"

    if not _is_indirect_branch(_ip()):
        for _ in range(HUNT_LIMIT):
            if _is_indirect_branch(_ip()):
                break
            ida_dbg.step_over()
            if not _wait():
                _log(tag + "TIMEOUT while hunting the branch")
                _capture_runaway()
                return "timeout"

    branch_ea = _ip()
    if not _is_indirect_branch(branch_ea):
        _log(tag + "no matching indirect branch (stopped @ %X  %s)"
             % (branch_ea or 0, idc.GetDisasm(branch_ea) or ""))
        return "no_branch"

    # QoL: stop before entering a watched handler (e.g. the ExitProcess one)
    if state and state.get("stop_at") is not None:
        target = _branch_target(branch_ea)
        if target == state["stop_at"]:
            _log(tag + "about to enter STOP handler %X via %s @ %X - stopping here "
                 "(you are on the deciding jmp)" % (target, idc.print_operand(branch_ea, 0), branch_ea))
            return "reached_stop"

    ida_dbg.step_into()
    if not _wait():
        _log(tag + "TIMEOUT on step_into(%X)" % branch_ea)
        _capture_runaway()
        return "timeout"

    land = _ip()
    seg = idc.get_segm_name(land) or "?"
    line = tag + "branch %X -> landed %X  seg=%s  %s" % (branch_ea, land or 0, seg, idc.GetDisasm(land) or "")

    if LOG_ANATOMY and land is not None:
        a = _handler_anatomy(land)
        calls = ",".join(a["calls"]) if a["calls"] else "-"
        conds = ",".join(sorted(a["conds"])) if a["conds"] else "-"
        line += "  [term=%s | calls=%s | conds=%s | insn=%d]" % (a["term"], calls, conds, a["ninsn"])
    if REG_SNAPSHOT:
        line += "  " + _regsnap()
    _log(line)

    if COMMENT_LANDINGS:
        try:
            idc.set_cmt(land, "tailjump landing (auto)", 0)
        except Exception:
            pass

    # bookkeeping for the end-of-run summary
    if state is not None and land is not None:
        state["landings"][land] = state["landings"].get(land, 0) + 1
        if state["landings"][land] == LOOP_WARN_COUNT:
            _log(tag + "LOOP? landing %X seen %d times (dispatcher/VM handler reused)"
                 % (land, LOOP_WARN_COUNT))
        if LOG_ANATOMY:
            a = _anat_cache.get(land)
            if a:
                if a["calls"]:
                    state["call_layers"].append((layer, land, list(a["calls"])))
                    for c in a["calls"]:
                        state["call_freq"][c] += 1
                        if _looks_api(c):
                            state["api_calls"].append((layer, land, c))
                if a["conds"]:
                    state["cond_layers"].append((layer, land, sorted(a["conds"])))
    return "ok"


def _print_summary(state, done):
    _log("---- summary: %d layer(s), %d unique handlers ----"
         % (done, len(state["landings"])))
    api = state["api_calls"]
    if api:
        _log("API-ish calls (layer, handler, target):")
        for (ly, h, c) in api[:60]:
            _log("   L%s  H=%X  %s" % (ly, h, c))
    cl = state["cond_layers"]
    _log("layers with conditionals: %d" % len(cl))
    for (ly, h, cs) in cl[:80]:
        _log("   L%s  H=%X  conds=%s" % (ly, h, ",".join(cs)))
    if state["call_freq"]:
        top = state["call_freq"].most_common(15)
        _log("call-target frequency (top 15): " + ", ".join("%s x%d" % (c, n) for c, n in top))


def tailjump(n=1):
    _log("==== tailjump(%d) start ====" % n)
    state = {
        "landings": {},
        "call_layers": [],
        "cond_layers": [],
        "api_calls": [],
        "call_freq": collections.Counter(),
        "stop_at": int(STOP_AT_HANDLER, 16) if STOP_AT_HANDLER.strip() else None,
    }
    prev_auto = None
    if DISABLE_AUTO_ANALYSIS:
        try:
            prev_auto = ida_auto.enable_auto(False)
            _log("auto-analysis disabled for the run")
        except Exception as e:
            _log("could not toggle auto-analysis: %s" % e)
    if n > 1:
        try:
            ida_kernwin.show_wait_box("Tailjump: peeling layers (Cancel to stop)")
        except Exception:
            pass
    done = 0
    try:
        for k in range(n):
            if n > 1 and ida_kernwin.user_cancelled():
                _log("user cancelled at layer %d" % (k + 1))
                break
            status = tailjump_once(layer=k + 1, state=state)
            done = k + 1
            if status != "ok":
                _log("STOPPED at layer %d (status=%s)" % (done, status))
                break
            if PROGRESS_EVERY and done % PROGRESS_EVERY == 0:
                msg = "progress: %d/%d  unique handlers=%d" % (done, n, len(state["landings"]))
                _log(msg)
                try:
                    ida_kernwin.replace_wait_box(msg)
                except Exception:
                    pass
    finally:
        if n > 1:
            try:
                ida_kernwin.hide_wait_box()
            except Exception:
                pass
        if DISABLE_AUTO_ANALYSIS and prev_auto is not None:
            try:
                ida_auto.enable_auto(prev_auto)
                _log("auto-analysis restored")
            except Exception:
                pass
        _print_summary(state, done)
        _log("==== tailjump end ====")


# ----------------------------------------------------------------------------
# console options  -  flip the switches at runtime (they are NOT arguments to
# tailjump()). Usage:  opts()  prints them all;  opts(REG_SNAPSHOT=True)  sets.
# ----------------------------------------------------------------------------
_TJ_BOOL_OPTS = {"LOG_TO_FILE", "LOG_ANATOMY", "REG_SNAPSHOT",
                 "COMMENT_LANDINGS", "VERBOSE", "DISABLE_AUTO_ANALYSIS",
                 "STEP_INTO_REG_ONLY"}
_TJ_INT_OPTS = {"NUM_STEP_OVERS", "HUNT_LIMIT", "STEP_TIMEOUT",
                "LINES_UP_FROM_END", "PROGRESS_EVERY", "LOOP_WARN_COUNT"}
_TJ_STR_OPTS = {"STOP_AT_HANDLER"}

_TJ_OPT_DOC = {
    "LOG_ANATOMY": "per-handler [term=..|calls=..|conds=..|insn=..] + end summary "
                   "of which layers had calls/conditionals/API calls",
    "REG_SNAPSHOT": "log rcx,rdx,r8,r9,rax at every landing (watch args/state)",
    "STOP_AT_HANDLER": "handler ENTRY (hex); stop ON the deciding jmp before "
                       "entering it. '' = disabled",
    "LOG_TO_FILE": "also write the run to logs/tailjump_log.txt (master switch)",
    "VERBOSE": "echo everything to the Output window",
    "COMMENT_LANDINGS": "drop an IDB comment at each landing address",
    "DISABLE_AUTO_ANALYSIS": "turn IDA auto-analysis off during tailjump(n)",
    "NUM_STEP_OVERS": "F8 count after run-to-cursor before hunting the branch",
    "HUNT_LIMIT": "max step-overs while hunting the terminating branch",
    "STEP_TIMEOUT": "seconds per step; a runaway becomes a logged timeout",
    "LINES_UP_FROM_END": "instruction heads above 'endp' for run-to-cursor",
    "PROGRESS_EVERY": "print a progress line every N layers in tailjump(n)",
    "LOOP_WARN_COUNT": "warn when a landing repeats this many times",
    "STEP_INTO_REG_ONLY": "only treat 'jmp reg' (not jmp imm) as the branch",
}


def _tj_coerce(name, val):
    if name in _TJ_STR_OPTS:                 # STOP_AT_HANDLER: keep a hex string
        if val in (None, "", 0, False):
            return ""
        if isinstance(val, int):
            return "%X" % val
        return str(val).strip().lower().replace("0x", "").upper()
    if name in _TJ_BOOL_OPTS:
        if isinstance(val, str):
            return val.strip().lower() in ("1", "true", "yes", "on", "y")
        return bool(val)
    if name in _TJ_INT_OPTS:
        return int(val, 0) if isinstance(val, str) else int(val)
    return val


def opts(*args, **kw):
    """Show or set tailjump options from the console.

      opts()                          print every option, its value + meaning
      opts(REG_SNAPSHOT=True)         set one (or several) by keyword
      opts("STOP_AT_HANDLER", "7FF706181C20")   set one by (name, value) pair
    Options take effect on the NEXT tailjump()/tailjump_once()/Ctrl-Alt-J.
    """
    names = sorted(_TJ_BOOL_OPTS | _TJ_INT_OPTS | _TJ_STR_OPTS)
    if len(args) == 2 and not kw:            # positional (name, value)
        kw = {args[0]: args[1]}
        args = ()
    if not kw:
        print("[tailjump] options (set with opts(NAME=value)):")
        for n in names:
            print("   %-22s = %-16r %s" % (n, globals().get(n), _TJ_OPT_DOC.get(n, "")))
        print("[tailjump] e.g.  opts(REG_SNAPSHOT=True)  |  "
              "opts(STOP_AT_HANDLER='7FF706181C20')  |  opts(LOG_ANATOMY=False)")
        return
    changed = {}
    for name, val in kw.items():
        key = str(name).upper()
        if key not in names:
            print("[tailjump] unknown option %r (known: %s)" % (name, ", ".join(names)))
            continue
        newv = _tj_coerce(key, val)
        globals()[key] = newv
        changed[key] = newv
        print("[tailjump] %s = %r    (%s)" % (key, newv, _TJ_OPT_DOC.get(key, "")))
    return changed


# quick single-switch shortcuts for the four you use most
def reg_snapshot(on=True):
    """Toggle REG_SNAPSHOT (log rcx,rdx,r8,r9,rax at each landing)."""
    return opts(REG_SNAPSHOT=on)


def log_anatomy(on=True):
    """Toggle LOG_ANATOMY (per-handler term/calls/conds/insn + run summary)."""
    return opts(LOG_ANATOMY=on)


def log_to_file(on=True):
    """Toggle LOG_TO_FILE (also write logs/tailjump_log.txt)."""
    return opts(LOG_TO_FILE=on)


def stop_at(addr=""):
    """Set STOP_AT_HANDLER to a handler entry (hex string/int); '' clears it."""
    return opts(STOP_AT_HANDLER=addr)


_tj_hotkey = None


def _bootstrap():
    global _tj_hotkey
    try:
        _tj_hotkey = ida_kernwin.add_hotkey("Ctrl-Alt-J", tailjump_once)
        _log("hotkey Ctrl-Alt-J -> tailjump_once()", to_file=False)
    except Exception as e:
        _log("could not bind hotkey: %s" % e, to_file=False)
    _log("loaded. Ctrl-Alt-J = one layer; tailjump(n) = n layers. Set switches "
         "from the console with opts()  (e.g. opts(REG_SNAPSHOT=True)); opts() "
         "alone lists them. Switches are NOT arguments to tailjump().",
         to_file=False)


_bootstrap()
