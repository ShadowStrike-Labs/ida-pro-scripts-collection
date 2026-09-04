# ============================================================================
#  pass_exceptions.py  -  IDAPython debugger exception automation
# ----------------------------------------------------------------------------
#  Stops the tedious manual work in Debugger > Debugger options > Edit
#  exceptions. Run it once and every exception is set to "pass to the
#  application" without breaking, and the "pass exception to app?" popups are
#  turned off.
#
#  VERIFIED against the IDA SDK (dbg.hpp) for this release:
#    - retrieve_exceptions() returns the live exception vector; you modify it
#      in place and then call store_exceptions()  (store takes NO arguments).
#    - set_debugger_options(): clearing DOPT_EXCDLG (-> EXCDLG_NEVER = 0)
#      makes IDA never show the exception dialog.
#    - DBG_Hooks.dbg_exception(...) return 0 == "never display the dialog".
#  The EXC_* flag *values* live in idd.hpp; they are read via getattr() with
#  the standard fallbacks (EXC_BREAK=1, EXC_HANDLE=2). Run list_exceptions()
#  to see the effect; adjust the fallback values above if your build differs.
#
#  COMMANDS (call from the IDAPython console)
#    pass_all_exceptions()          every known exception -> pass, no break
#    pass_code("C0000005")          one code; zero-count tolerant (see below)
#    break_code("C0000005")         make one code break again
#    pass_code_range(lo, hi)        pass every code in [lo, hi]
#    pass_range("Range:0-FFFFFFFF") same, parsing a 'Range:LO-HI' string
#    list_exceptions()              print the current table
#    install_addr_range_autopass(lo, hi) / remove_addr_range_autopass()
#                                   while running, auto-pass exceptions raised
#                                   inside an ADDRESS range, break otherwise
#
#  ZERO-COUNT TOLERANCE: codes are matched first exactly, then by a
#  "zero-insensitive skeleton" (all '0' chars removed). So 0xC0000005,
#  c0000005 and even a mistyped C000005 all resolve to the same exception.
#
#  HOTKEY: Ctrl-Alt-P  ->  pass_all_exceptions()
#  On load this file runs pass_all_exceptions() + suppress_exception_dialogs().
# ============================================================================

import ida_dbg
import ida_kernwin

# ---- flag values (idd.hpp); standard values, overridden if the module has them
EXC_BREAK  = getattr(ida_dbg, "EXC_BREAK", 0x0001)   # debugger stops on the exception
EXC_HANDLE = getattr(ida_dbg, "EXC_HANDLE", 0x0002)  # exception is passed to the app

# ---- debugger-option bits for the exception dialog (verified from dbg.hpp)
DOPT_EXCDLG  = 0x00006000
EXCDLG_NEVER = 0x00000000

_retrieve = getattr(ida_dbg, "retrieve_exceptions", None)
_store    = getattr(ida_dbg, "store_exceptions", None)


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _skeleton(code):
    """Zero-insensitive skeleton: 0xC0000005 -> 'C5', mistyped C000005 -> 'C5'."""
    if isinstance(code, int):
        s = "%X" % (code & 0xFFFFFFFF)
    else:
        s = str(code).strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        s = s.upper()
    return s.replace("0", "") or "0"


def _as_code(v):
    """Parse an exception code (32-bit) from int or hex string."""
    if isinstance(v, int):
        return v & 0xFFFFFFFF
    s = str(v).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16) & 0xFFFFFFFF


def _as_addr(v):
    """Parse an address (no 32-bit masking) from int or hex string."""
    if isinstance(v, int):
        return v
    s = str(v).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)


def _excs():
    if _retrieve is None:
        raise RuntimeError("ida_dbg.retrieve_exceptions not available on this IDA build")
    return _retrieve()


def _commit():
    if _store is None:
        raise RuntimeError("ida_dbg.store_exceptions not available on this IDA build")
    return _store()          # NOTE: no arguments - operates on the live vector


def _apply(exc, do_pass, do_break):
    f = exc.flags
    f = (f | EXC_HANDLE) if do_pass else (f & ~EXC_HANDLE)
    f = (f | EXC_BREAK) if do_break else (f & ~EXC_BREAK)
    exc.flags = f


def _match(user_code, e):
    """Exact code match first, then zero-insensitive skeleton match."""
    try:
        if _as_code(user_code) == (e.code & 0xFFFFFFFF):
            return True
    except Exception:
        pass
    return _skeleton(user_code) == _skeleton(e.code)


# ----------------------------------------------------------------------------
# public commands
# ----------------------------------------------------------------------------
def suppress_exception_dialogs():
    """Turn off the 'pass exception to application?' popups (EXCDLG_NEVER)."""
    try:
        cur = ida_dbg.set_debugger_options(0)                 # returns current opts
        ida_dbg.set_debugger_options((cur & ~DOPT_EXCDLG) | EXCDLG_NEVER)
        print("[pass_exceptions] exception dialogs disabled (EXCDLG_NEVER)")
    except Exception as e:
        print("[pass_exceptions] could not change debugger options: %s" % e)


def pass_all_exceptions(do_break=False):
    """Set EVERY known exception to pass-to-application, no-break."""
    excs = _excs()
    n = 0
    for e in excs:
        _apply(e, do_pass=True, do_break=do_break)
        n += 1
    _commit()
    print("[pass_exceptions] %d exception(s) -> PASS to app, break=%s" % (n, do_break))
    return n


def set_code(code, do_pass=True, do_break=False):
    """Configure the exception(s) matching 'code' (exact or zero-insensitive)."""
    excs = _excs()
    hits = [e for e in excs if _match(code, e)]
    if not hits:
        print("[pass_exceptions] no known exception matches %r (skeleton %s). "
              "See list_exceptions()." % (code, _skeleton(code)))
        return 0
    for e in hits:
        _apply(e, do_pass, do_break)
        print("[pass_exceptions]  %08X  %-30s pass=%s break=%s"
              % (e.code & 0xFFFFFFFF, str(e.name), do_pass, do_break))
    _commit()
    return len(hits)


def pass_code(code):
    """Pass one exception code to the app, don't break. Zero-count tolerant."""
    return set_code(code, do_pass=True, do_break=False)


def break_code(code):
    """Make one exception code break (stop) again."""
    return set_code(code, do_pass=False, do_break=True)


def pass_code_range(lo, hi):
    """Pass every exception whose code is within [lo, hi]."""
    lo, hi = _as_code(lo), _as_code(hi)
    excs = _excs()
    n = 0
    for e in excs:
        if lo <= (e.code & 0xFFFFFFFF) <= hi:
            _apply(e, do_pass=True, do_break=False)
            n += 1
    _commit()
    print("[pass_exceptions] %d exception(s) in [%08X..%08X] -> PASS" % (n, lo, hi))
    return n


def parse_range(spec):
    """Split 'Range:LO-HI' or 'LO-HI' into (lo, hi) as raw ints (no masking)."""
    s = str(spec).strip()
    if ":" in s:
        s = s.split(":", 1)[1]
    lo, hi = s.split("-", 1)
    return _as_addr(lo), _as_addr(hi)


def pass_range(spec):
    """Accept a 'Range:LO-HI' string and pass every exception code in it."""
    lo, hi = parse_range(spec)
    return pass_code_range(lo, hi)


def list_exceptions():
    """Print the current exception table (B=breaks, P=passes to app)."""
    excs = _excs()
    print("  CODE      BRK PASS  NAME")
    for e in excs:
        f = e.flags
        print("  %08X   %s    %s    %s"
              % (e.code & 0xFFFFFFFF,
                 "B" if f & EXC_BREAK else ".",
                 "P" if f & EXC_HANDLE else ".",
                 str(e.name)))
    print("  (B = debugger breaks on it, P = passed to the application)")


# ----------------------------------------------------------------------------
# address-range auto-pass (QoL): while running, pass exceptions raised inside
# an address range and keep breaking on the rest. Honors 'Range:LO-HI' for
# addresses (IDA keys exceptions by code, so per-address logic needs a hook).
# ----------------------------------------------------------------------------
class _AddrRangeAutoPass(ida_dbg.DBG_Hooks):
    def __init__(self, lo, hi):
        ida_dbg.DBG_Hooks.__init__(self)
        self.lo, self.hi = lo, hi

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        where = exc_ea if exc_ea not in (0, 0xFFFFFFFFFFFFFFFF) else ea
        if self.lo <= where <= self.hi:
            print("[autopass] exc %08X @ %X in range -> pass to app"
                  % (exc_code & 0xFFFFFFFF, where))
            if exc_can_cont:
                try:
                    ida_dbg.continue_process()
                except Exception:
                    pass
            return 0     # never show the dialog
        return -1        # out of range: surface it (show dialog if suspended)


_autopass_hook = None


def install_addr_range_autopass(lo, hi=None):
    """Auto-pass exceptions raised within an ADDRESS range while running.
    Accepts ints, hex strings, or a single 'Range:LO-HI' string."""
    global _autopass_hook
    if isinstance(lo, str) and hi is None and ("-" in lo or ":" in lo):
        lo, hi = parse_range(lo)
    else:
        lo, hi = _as_addr(lo), _as_addr(hi)
    if _autopass_hook is not None:
        _autopass_hook.unhook()
    _autopass_hook = _AddrRangeAutoPass(lo, hi)
    _autopass_hook.hook()
    print("[pass_exceptions] address-range auto-pass installed: %X..%X" % (lo, hi))


def remove_addr_range_autopass():
    global _autopass_hook
    if _autopass_hook is not None:
        _autopass_hook.unhook()
        _autopass_hook = None
        print("[pass_exceptions] address-range auto-pass removed")


# ----------------------------------------------------------------------------
# on load: do the headline thing + bind a hotkey
# ----------------------------------------------------------------------------
_hk_ctx = None


def _hk_pass_all():
    pass_all_exceptions()
    suppress_exception_dialogs()


def _bootstrap():
    global _hk_ctx
    try:
        pass_all_exceptions()
        suppress_exception_dialogs()
    except Exception as e:
        print("[pass_exceptions] setup error: %s" % e)
    try:
        _hk_ctx = ida_kernwin.add_hotkey("Ctrl-Alt-P", _hk_pass_all)
        print("[pass_exceptions] hotkey Ctrl-Alt-P -> pass_all_exceptions()")
    except Exception as e:
        print("[pass_exceptions] could not bind hotkey: %s" % e)
    print("[pass_exceptions] ready. Commands: pass_all_exceptions(), pass_code('C0000005'), "
          "pass_range('Range:0-FFFFFFFF'), list_exceptions(), "
          "install_addr_range_autopass(lo, hi)")


_bootstrap()
