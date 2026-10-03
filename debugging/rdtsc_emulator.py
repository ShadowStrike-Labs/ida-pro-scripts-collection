# ============================================================================
#  rdtsc_emulator.py  -  IDAPython rdtsc/rdtscp timing emulator
# ----------------------------------------------------------------------------
#  Defeats timing-based anti-debug (rdtsc/rdtscp delta checks) by feeding the
#  program a controlled, monotonic timestamp counter that only advances by a
#  tiny, constant amount per read. Two consecutive reads therefore always show
#  a small delta - the "I am being single-stepped / breakpointed" signal never
#  fires, no matter how long you sit at a breakpoint.
#
#  WHY THIS CATCHES READS EVEN UNDER F9 (Run)
#  It does not rely on you single-stepping. It statically scans the executable
#  memory for every  rdtsc (0F 31)  and  rdtscp (0F 01 F9)  and installs a
#  breakpoint at each site. The breakpoints are SILENT: their condition runs a
#  Python callback that rewrites the result registers and returns False, so IDA
#  never stops - the process keeps running under F9 and every read is emulated.
#  You do not have to spot the rdtsc yourself; the scanner finds them all.
#
#  PLACEMENT (accuracy)
#  The breakpoint is placed on the instruction *after* the timer read. The real
#  rdtsc executes, then - before the value is consumed - the callback overwrites
#  EDX:EAX (and ECX for rdtscp) with the virtual counter. This avoids any
#  instruction-pointer/re-arm ambiguity and guarantees the program only ever
#  sees the emulated value. (See the note near _rd_tick for the trade-off.)
#
#  ON YOUR "BP INSIDE vs OUTSIDE the two reads" QUESTION
#    t1=rdtsc ; [BP here] ; t2=rdtsc   -> WITHOUT this script the wall clock
#      keeps advancing while you sit at the BP, so t2-t1 explodes and the check
#      trips. WITH this script both reads are emulated, so t2-t1 stays tiny.
#    t1=rdtsc ; t2=rdtsc ; [BP here]   -> if you F9 straight through the two
#      reads the CPU runs them back-to-back at full speed, so the delta is
#      already small and the check usually passes even without emulation. The
#      danger is any stop *between* the reads. This script removes the danger
#      entirely by making the delta deterministic wherever your BPs are.
#
#  MODES
#    Normal (software)  - int3 breakpoints. Simple and fast, but writes 0xCC
#      into the code, so a self-checksum or a scan for 0xCC can notice them.
#    Stealth (hardware) - hardware EXECUTE breakpoints (rdtsc_stealth() or
#      rdtsc_on(stealth=True)). No bytes are changed in the code, so code
#      integrity / 0xCC scans see nothing. IDA uses the 4 debug registers first
#      and, when you exceed them, emulates the rest with page-permission
#      changes (the message you have seen). Trade-offs: the page-emulated
#      overflow can be slower because IDA faults on page access, and the DRx
#      registers / page protections are themselves detectable by other, less
#      common checks (GetThreadContext, NtQueryVirtualMemory). It defeats the
#      code-patching tell, which is the usual one.
#
#  COMMANDS (call from the IDAPython console)
#    rdtsc_on()             scan + install SOFTWARE emulation breakpoints
#    rdtsc_stealth()        same, but HARDWARE execute breakpoints (stealth)
#    rdtsc_rescan()         scan again (after unpacking / newly mapped code)
#    rdtsc_off()            remove the emulation breakpoints
#    rdtsc_status()         mode, sites hooked, hardware count, virtual counter
#    rdtsc_config(inc=, start=, aux=)   tune the per-read increment / base / ECX
#    rdtsc_auto(on=True)    auto-rescan on library load / process start
#
#  HOTKEY: Ctrl-Alt-R -> rdtsc_on()  (software);  call rdtsc_stealth() for HW.
# ============================================================================

import ida_bytes
import ida_dbg
import ida_kernwin
import ida_segment
import idaapi
import idautils
import idc

try:
    import ida_ida
except Exception:
    ida_ida = None

BADADDR = idaapi.BADADDR
SEGPERM_EXEC = getattr(ida_segment, "SEGPERM_EXEC", 1)

# ---- configuration ---------------------------------------------------------
_RD_START = 0x0000000100000000      # initial virtual TSC
_RD_INC   = 0x100                   # per-read advance (small -> tiny deltas)
_RD_AUX   = 0x00000000              # ECX value returned by rdtscp (TSC_AUX)

# breakpoint types (idc.hpp): software int3 vs hardware execute
BPT_SOFT    = getattr(idc, "BPT_SOFT", 4)
BPT_EXEC    = getattr(idc, "BPT_EXEC", 8)          # hardware: execute
BPT_DEFAULT = getattr(idc, "BPT_DEFAULT", BPT_SOFT | BPT_EXEC)

# ---- state -----------------------------------------------------------------
_rd_tsc   = _RD_START
_rd_hits  = 0
_rd_mode  = "soft"  # "soft" = int3, "hard" = hardware execute (stealth)
_rd_sites = {}      # site_ea -> is_rdtscp
_rd_bps   = {}      # bp_ea (site_ea + len) -> site_ea
_rd_hook  = None
_rd_64    = True


# ----------------------------------------------------------------------------
# pure logic (no IDA calls) - unit-testable offline
# ----------------------------------------------------------------------------
def _rd_find(data, base):
    """Find every rdtsc/rdtscp in `data`. Returns [(ea, length, is_rdtscp)]."""
    out = []
    i, n = 0, len(data)
    while i < n - 1:
        if data[i] == 0x0F:
            if i + 2 < n and data[i + 1] == 0x01 and data[i + 2] == 0xF9:
                out.append((base + i, 3, True))     # rdtscp
                i += 3
                continue
            if data[i + 1] == 0x31:
                out.append((base + i, 2, False))    # rdtsc
                i += 2
                continue
        i += 1
    return out


def _rd_split(value):
    """64-bit counter -> (edx_high32, eax_low32)."""
    v = value & 0xFFFFFFFFFFFFFFFF
    return ((v >> 32) & 0xFFFFFFFF, v & 0xFFFFFFFF)


def _rd_advance(value, inc):
    """Next monotonic counter value."""
    return (value + inc) & 0xFFFFFFFFFFFFFFFF


def _rd_bpt_type(stealth):
    """(size, type) for the requested mode: hardware execute vs software int3.
    Hardware execute breakpoints do not write 0xCC into the code, so they
    survive code-checksum and 0xCC-scan anti-debug; IDA uses the 4 debug
    registers first and transparently emulates any overflow via page
    permissions."""
    if stealth:
        return (1, BPT_EXEC)        # hardware: execute (DRx / page-emulated)
    return (0, BPT_DEFAULT)         # software: int3


# ----------------------------------------------------------------------------
# IDA-backed helpers
# ----------------------------------------------------------------------------
def _rd_log(msg):
    print("[rdtsc] %s" % msg)


def _rd_is64():
    f = getattr(ida_ida, "inf_is_64bit", None) if ida_ida else None
    if f is not None:
        try:
            return bool(f())
        except Exception:
            pass
    gi = getattr(idaapi, "get_inf_structure", None)
    if gi is not None:
        try:
            return bool(gi().is_64bit())
        except Exception:
            pass
    return True


def _rd_dbg_ready():
    try:
        return ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK
    except Exception:
        return False


def _rd_exec_ranges():
    """(start, end) of every executable segment."""
    out = []
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg is None:
            continue
        if seg.perm & SEGPERM_EXEC:
            out.append((seg.start_ea, seg.end_ea))
    return out


# The silent-breakpoint callback. Registered as the bpt condition (elang
# Python); returning False means "do not stop", so execution continues under
# F9. It overwrites the timer result the real rdtsc just produced.
#
# Trade-off of the after-the-read placement: if unrelated code jumps directly
# onto the instruction following a timer read, the callback would fire without
# a preceding rdtsc. That is harmless (it only writes EDX:EAX, which such code
# is not reading as a timestamp). Isolated timer reads - the anti-debug case -
# are unaffected.
def _rd_tick(site_ea):
    global _rd_tsc, _rd_hits
    is_p = _rd_sites.get(site_ea, False)
    edx, eax = _rd_split(_rd_tsc)
    _rd_tsc = _rd_advance(_rd_tsc, _RD_INC)
    _rd_hits += 1
    try:
        if _rd_64:
            ida_dbg.set_reg_val("RAX", eax)     # zero-extends into RAX
            ida_dbg.set_reg_val("RDX", edx)
            if is_p:
                ida_dbg.set_reg_val("RCX", _RD_AUX)
        else:
            ida_dbg.set_reg_val("EAX", eax)
            ida_dbg.set_reg_val("EDX", edx)
            if is_p:
                ida_dbg.set_reg_val("ECX", _RD_AUX)
    except Exception as e:
        _rd_log("reg write failed at %X: %s" % (site_ea, e))
    return False        # never stop


def _rd_add_bp(site_ea, length, is_rdtscp):
    bp_ea = site_ea + length
    if bp_ea in _rd_bps:
        return False
    size, bptype = _rd_bpt_type(_rd_mode == "hard")
    # a silent breakpoint on the instruction AFTER the timer read
    ida_dbg.add_bpt(bp_ea, size, bptype)
    b = ida_dbg.bpt_t()
    if not ida_dbg.get_bpt(bp_ea, b):
        return False
    b.type = bptype                 # force soft/hardware regardless of default
    b.size = size
    b.elang = "Python"
    b.condition = "_rd_tick(0x%X)" % site_ea
    b.flags |= ida_dbg.BPT_ENABLED
    ida_dbg.update_bpt(b)
    _rd_sites[site_ea] = is_rdtscp
    _rd_bps[bp_ea] = site_ea
    return True


def _rd_scan(verbose=True):
    global _rd_64
    _rd_64 = _rd_is64()
    found = 0
    for start, end in _rd_exec_ranges():
        data = ida_bytes.get_bytes(start, end - start)
        if not data:
            continue
        for site_ea, length, is_p in _rd_find(bytes(data), start):
            if site_ea in _rd_sites:
                continue
            if _rd_add_bp(site_ea, length, is_p):
                found += 1
                if verbose:
                    _rd_log("  %s @ %X" % ("rdtscp" if is_p else "rdtsc ", site_ea))
    return found


# ----------------------------------------------------------------------------
# public commands
# ----------------------------------------------------------------------------
def rdtsc_on(stealth=False):
    """Scan executable memory and install the emulation breakpoints.
    stealth=False -> software (int3) breakpoints (normal mode).
    stealth=True  -> hardware execute breakpoints (no 0xCC in the code)."""
    global _rd_mode
    if not _rd_dbg_ready():
        _rd_log("no debug session; start/attach first (then rdtsc_on()).")
        return 0
    _rd_mode = "hard" if stealth else "soft"
    n = _rd_scan()
    hw = _rd_count_hw()
    _rd_log("emulation ON [%s]: %d new, %d total (%d hardware). inc=%#x start=%#x"
            % (_rd_mode, n, len(_rd_sites), hw, _RD_INC, _RD_START))
    if _rd_mode == "hard" and hw < len(_rd_bps):
        _rd_log("note: %d bp(s) are not hardware yet - IDA may convert or "
                "page-emulate them once the process resumes."
                % (len(_rd_bps) - hw))
    return n


def rdtsc_stealth():
    """Stealth mode: install HARDWARE execute breakpoints (no code patching)."""
    return rdtsc_on(stealth=True)


def _rd_count_hw():
    """How many of our breakpoints are currently hardware."""
    n = 0
    b = ida_dbg.bpt_t()
    for bp_ea in _rd_bps:
        if ida_dbg.get_bpt(bp_ea, b) and b.is_hwbpt():
            n += 1
    return n


def rdtsc_rescan():
    """Scan again for reads that appeared after unpacking / new mappings."""
    if not _rd_dbg_ready():
        _rd_log("no debug session.")
        return 0
    n = _rd_scan()
    _rd_log("rescan: %d new site(s); %d total." % (n, len(_rd_sites)))
    return n


def rdtsc_off():
    """Remove every emulation breakpoint this script installed."""
    for bp_ea in list(_rd_bps):
        try:
            ida_dbg.del_bpt(bp_ea)
        except Exception:
            pass
    _rd_bps.clear()
    _rd_sites.clear()
    _rd_log("emulation OFF; breakpoints removed.")


def rdtsc_status():
    """Print the number of hooked sites, hit count, and virtual counter."""
    hw = _rd_count_hw() if _rd_bps else 0
    _rd_log("mode=%s  sites=%d  hardware=%d  hits=%d  vtsc=%#x  inc=%#x  aux=%#x  (%s)"
            % (_rd_mode, len(_rd_sites), hw, _rd_hits, _rd_tsc, _RD_INC, _RD_AUX,
               "x64" if _rd_64 else "x86"))


def rdtsc_config(inc=None, start=None, aux=None):
    """Tune the per-read increment, base counter, and rdtscp ECX value."""
    global _RD_INC, _RD_START, _RD_AUX, _rd_tsc
    if inc is not None:
        _RD_INC = int(inc)
    if start is not None:
        _RD_START = int(start)
        _rd_tsc = _RD_START
    if aux is not None:
        _RD_AUX = int(aux)
    _rd_log("config: inc=%#x start=%#x aux=%#x" % (_RD_INC, _RD_START, _RD_AUX))


# ----------------------------------------------------------------------------
# auto-rescan on new code (unpackers)
# ----------------------------------------------------------------------------
class _RdHook(ida_dbg.DBG_Hooks):
    def dbg_library_load(self, pid, tid, ea, name, base, size):
        try:
            rdtsc_rescan()
        except Exception:
            pass

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        try:
            rdtsc_rescan()
        except Exception:
            pass


def rdtsc_auto(on=True):
    """Auto-rescan on library load / process start (for packed samples)."""
    global _rd_hook
    if on:
        if _rd_hook is None:
            _rd_hook = _RdHook()
            _rd_hook.hook()
        _rd_log("auto-rescan: ENABLED")
    else:
        if _rd_hook is not None:
            _rd_hook.unhook()
            _rd_hook = None
        _rd_log("auto-rescan: DISABLED")


# ----------------------------------------------------------------------------
# on load: bind hotkey + banner
# ----------------------------------------------------------------------------
_rd_hk = None


def _rd_bootstrap():
    global _rd_hk, _rd_64
    _rd_64 = _rd_is64()
    try:
        _rd_hk = ida_kernwin.add_hotkey("Ctrl-Alt-R", rdtsc_on)
    except Exception:
        pass
    _rd_log("ready. rdtsc_on() hooks every rdtsc/rdtscp with a silent "
            "breakpoint that feeds a monotonic virtual TSC (Ctrl-Alt-R); "
            "rdtsc_stealth() uses hardware breakpoints (no 0xCC in code); "
            "rdtsc_rescan() after unpacking; rdtsc_config(inc=..) to tune.")


_rd_bootstrap()
