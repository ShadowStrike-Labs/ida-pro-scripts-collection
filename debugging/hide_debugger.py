# ============================================================================
#  hide_debugger.py  -  IDAPython in-memory anti-anti-debug (PEB/TEB patcher)
# ----------------------------------------------------------------------------
#  Neutralises the PEB-based debugger tells that malware reads directly from
#  the process block, so you stop hand-editing the "Segment registers" tab to
#  find the PEB and zero the flags yourself. Works with the local Windows
#  debugger and the WinDbg backend (anything that lets IDA read/write process
#  memory while suspended).
#
#  WHAT IT PATCHES (the classic direct-memory checks)
#    PEB.BeingDebugged      (PEB+0x02)          -> 0
#    PEB.NtGlobalFlag       (x64 +0xBC/x86+0x68)-> clears FLG_HEAP_* (0x70)
#    ProcessHeap.Flags      (x64 +0x70/x86+0x40)-> clears the debug-heap bits
#    ProcessHeap.ForceFlags (x64 +0x74/x86+0x44)-> 0
#    ...and the same heap fix across every heap in PEB.ProcessHeaps.
#
#  HOW THE PEB IS FOUND
#    TEB = base of GS (x64) / FS (x86) for the current thread, read through the
#    debugger; PEB = *(TEB + 0x60 x64 / +0x30 x86). If your build cannot report
#    the segment base, pass it yourself: set_teb(addr) or set_peb(addr). Run
#    find_peb() to see what was resolved and cross-check the Segments window.
#
#  WHAT IT DOES NOT DO
#    KUSER_SHARED_DATA.KdDebuggerEnabled (0x7FFE02D4) is a read-only shared
#    page - not patchable here. Hardware-breakpoint (DRx) detection via
#    GetThreadContext and API-level checks (NtQueryInformationProcess, etc.)
#    are out of scope; use pass_exceptions.py / ScyllaHide for those. This
#    covers the direct PEB reads, which is the common manual pain point.
#
#  COMMANDS (call from the IDAPython console)
#    hide()                 patch the PEB now (process must be suspended)
#    hide_status()          print the current PEB/heap debug fields
#    find_peb()             resolve and print TEB/PEB (verification)
#    set_teb(addr) / set_peb(addr)   override auto-resolution
#    hide_auto(on=True)     re-patch automatically on process start / attach
#    hide_off()             remove the auto-patch hook
#
#  HOTKEY: Ctrl-Alt-H -> hide()
# ============================================================================

import struct

import ida_bytes
import ida_dbg
import ida_kernwin
import idaapi
import idc

try:
    import ida_ida
except Exception:                       # very old builds
    ida_ida = None

BADADDR = idaapi.BADADDR

# ---- heap/flag masks -------------------------------------------------------
FLG_HEAP_DEBUG          = 0x00000070    # NtGlobalFlag: tail/free/validate
HEAP_TAIL_CHECKING      = 0x00000020
HEAP_FREE_CHECKING      = 0x00000040
HEAP_VALIDATE_ALL       = 0x20000000
HEAP_VALIDATE_PARAMS    = 0x40000000
HEAP_DEBUG_MASK = (HEAP_TAIL_CHECKING | HEAP_FREE_CHECKING |
                   HEAP_VALIDATE_ALL | HEAP_VALIDATE_PARAMS)

# ---- caller overrides (0 = auto-resolve) -----------------------------------
_hd_teb_override = 0
_hd_peb_override = 0
_hd_hook = None


# ----------------------------------------------------------------------------
# pure logic (no IDA calls) - unit-testable offline
# ----------------------------------------------------------------------------
def _hd_offsets(is64):
    """Return the PEB/TEB/heap field offsets for the given bitness."""
    if is64:
        return {
            "ptr": 8,
            "teb_peb": 0x60,
            "being_debugged": 0x02,
            "nt_global_flag": 0xBC,
            "process_heap": 0x30,
            "num_heaps": 0xE8,
            "heaps": 0xF0,
            "heap_flags": 0x70,
            "heap_force": 0x74,
        }
    return {
        "ptr": 4,
        "teb_peb": 0x30,
        "being_debugged": 0x02,
        "nt_global_flag": 0x68,
        "process_heap": 0x18,
        "num_heaps": 0x88,
        "heaps": 0x90,
        "heap_flags": 0x40,
        "heap_force": 0x44,
    }


def _hd_clean_nt_global_flag(value):
    """Clear the heap-debug bits the loader sets under a debugger."""
    return value & ~FLG_HEAP_DEBUG


def _hd_clean_heap_flags(flags, force_flags):
    """Return (flags, force_flags) with the debug-heap bits removed."""
    return (flags & ~HEAP_DEBUG_MASK, force_flags & ~HEAP_DEBUG_MASK)


def _hd_unpack_ptr(buf, ptr_size):
    """Little-endian pointer from bytes."""
    if not buf or len(buf) < ptr_size:
        return None
    return int.from_bytes(buf[:ptr_size], "little")


# ----------------------------------------------------------------------------
# IDA-backed helpers
# ----------------------------------------------------------------------------
def _hd_log(msg):
    print("[hide_dbg] %s" % msg)


def _hd_is64():
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
    return bool(getattr(idc, "__EA64__", True))  # last resort: assume x64


def _hd_dbg_ready():
    """True only when a process is present and suspended (safe to read/write)."""
    try:
        return ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP
    except Exception:
        return False


def _hd_read(ea, n):
    b = ida_bytes.get_bytes(ea, n)
    return bytes(b) if b else b""


def _hd_read_ptr(ea, ptr_size):
    return _hd_unpack_ptr(_hd_read(ea, ptr_size), ptr_size)


def _hd_write(ea, data):
    """Write to the live process; returns bytes written (0 on failure)."""
    try:
        n = idc.write_dbg_memory(ea, data)
        return n if n else 0
    except Exception:
        try:
            return ida_dbg.write_dbg_memory(ea, data) or 0
        except Exception:
            return 0


def _hd_teb():
    if _hd_teb_override:
        return _hd_teb_override
    try:
        tid = ida_dbg.get_current_thread()
    except Exception:
        return None
    reg = "GS" if _hd_is64() else "FS"
    try:
        sel = ida_dbg.get_reg_val(reg)
    except Exception:
        sel = None
    if sel is not None:
        try:
            base = ida_dbg.internal_get_sreg_base(tid, int(sel))
            if base not in (None, 0, BADADDR):
                return base
        except Exception:
            pass
    # some backends expose the base as a pseudo-register
    for rn in (("GSBASE", "gsbase") if _hd_is64() else ("FSBASE", "fsbase")):
        try:
            v = ida_dbg.get_reg_val(rn)
            if v not in (None, 0, BADADDR):
                return v
        except Exception:
            pass
    return None


def _hd_peb():
    if _hd_peb_override:
        return _hd_peb_override
    off = _hd_offsets(_hd_is64())
    teb = _hd_teb()
    if not teb:
        return None
    return _hd_read_ptr(teb + off["teb_peb"], off["ptr"])


# ----------------------------------------------------------------------------
# public commands
# ----------------------------------------------------------------------------
def set_teb(addr):
    """Override TEB auto-resolution (accepts int or hex string)."""
    global _hd_teb_override
    _hd_teb_override = addr if isinstance(addr, int) else int(str(addr), 16)
    _hd_log("TEB override set to %X" % _hd_teb_override)


def set_peb(addr):
    """Override PEB auto-resolution (accepts int or hex string)."""
    global _hd_peb_override
    _hd_peb_override = addr if isinstance(addr, int) else int(str(addr), 16)
    _hd_log("PEB override set to %X" % _hd_peb_override)


def find_peb():
    """Resolve and print TEB/PEB so you can cross-check the Segments window."""
    if not _hd_dbg_ready():
        _hd_log("no suspended process; start/attach and break first.")
        return None
    teb, peb = _hd_teb(), _hd_peb()
    _hd_log("bitness=%s  TEB=%s  PEB=%s"
            % ("x64" if _hd_is64() else "x86",
               ("%X" % teb) if teb else "?",
               ("%X" % peb) if peb else "?"))
    return peb


def _hd_patch_heap(heap, off):
    """Clean one _HEAP's Flags/ForceFlags. Returns True if anything changed."""
    fa, ga = heap + off["heap_flags"], heap + off["heap_force"]
    flags = _hd_unpack_ptr(_hd_read(fa, 4), 4)
    force = _hd_unpack_ptr(_hd_read(ga, 4), 4)
    if flags is None or force is None:
        return False
    nf, ng = _hd_clean_heap_flags(flags, force)
    changed = False
    if nf != flags:
        _hd_write(fa, struct.pack("<I", nf))
        _hd_log("  heap %X Flags      %08X -> %08X" % (heap, flags, nf))
        changed = True
    if ng != force:
        _hd_write(ga, struct.pack("<I", ng))
        _hd_log("  heap %X ForceFlags %08X -> %08X" % (heap, force, ng))
        changed = True
    return changed


def hide():
    """Patch the PEB debugger tells in the live process (must be suspended)."""
    if not _hd_dbg_ready():
        _hd_log("no suspended process; start/attach and break first.")
        return False
    off = _hd_offsets(_hd_is64())
    peb = _hd_peb()
    if not peb:
        _hd_log("could not resolve the PEB; use set_peb(addr) (see find_peb()).")
        return False
    _hd_log("PEB @ %X (%s)" % (peb, "x64" if _hd_is64() else "x86"))

    # 1) BeingDebugged
    bd_ea = peb + off["being_debugged"]
    bd = _hd_read(bd_ea, 1)
    if bd and bd[0] != 0:
        _hd_write(bd_ea, b"\x00")
        _hd_log("  BeingDebugged  %02X -> 00" % bd[0])

    # 2) NtGlobalFlag
    ng_ea = peb + off["nt_global_flag"]
    ng = _hd_unpack_ptr(_hd_read(ng_ea, 4), 4)
    if ng is not None:
        clean = _hd_clean_nt_global_flag(ng)
        if clean != ng:
            _hd_write(ng_ea, struct.pack("<I", clean))
            _hd_log("  NtGlobalFlag   %08X -> %08X" % (ng, clean))

    # 3) ProcessHeap + every heap in ProcessHeaps
    seen = set()
    ph = _hd_read_ptr(peb + off["process_heap"], off["ptr"])
    if ph:
        seen.add(ph)
        _hd_patch_heap(ph, off)
    nheaps = _hd_unpack_ptr(_hd_read(peb + off["num_heaps"], 4), 4) or 0
    heaps_arr = _hd_read_ptr(peb + off["heaps"], off["ptr"])
    if heaps_arr and 0 < nheaps <= 256:
        for i in range(nheaps):
            h = _hd_read_ptr(heaps_arr + i * off["ptr"], off["ptr"])
            if h and h not in seen:
                seen.add(h)
                _hd_patch_heap(h, off)

    _hd_log("done. %d heap(s) checked." % len(seen))
    return True


def hide_status():
    """Print the current debugger-tell fields without changing them."""
    if not _hd_dbg_ready():
        _hd_log("no suspended process; start/attach and break first.")
        return
    off = _hd_offsets(_hd_is64())
    peb = _hd_peb()
    if not peb:
        _hd_log("could not resolve the PEB; use set_peb(addr).")
        return
    bd = _hd_read(peb + off["being_debugged"], 1)
    ng = _hd_unpack_ptr(_hd_read(peb + off["nt_global_flag"], 4), 4)
    _hd_log("PEB %X  BeingDebugged=%s  NtGlobalFlag=%s"
            % (peb,
               ("%02X" % bd[0]) if bd else "?",
               ("%08X" % ng) if ng is not None else "?"))
    ph = _hd_read_ptr(peb + off["process_heap"], off["ptr"])
    if ph:
        f = _hd_unpack_ptr(_hd_read(ph + off["heap_flags"], 4), 4)
        g = _hd_unpack_ptr(_hd_read(ph + off["heap_force"], 4), 4)
        _hd_log("ProcessHeap %X  Flags=%s  ForceFlags=%s"
                % (ph,
                   ("%08X" % f) if f is not None else "?",
                   ("%08X" % g) if g is not None else "?"))


# ----------------------------------------------------------------------------
# auto-patch on process start / attach
# ----------------------------------------------------------------------------
class _HideHook(ida_dbg.DBG_Hooks):
    def dbg_process_start(self, pid, tid, ea, name, base, size):
        try:
            hide()
        except Exception as e:
            _hd_log("auto-patch error: %s" % e)

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        try:
            hide()
        except Exception as e:
            _hd_log("auto-patch error: %s" % e)


def hide_auto(on=True):
    """Re-patch the PEB automatically on process start / attach."""
    global _hd_hook
    if on:
        if _hd_hook is None:
            _hd_hook = _HideHook()
            _hd_hook.hook()
        _hd_log("auto-patch on process start/attach: ENABLED")
    else:
        hide_off()


def hide_off():
    """Remove the auto-patch hook."""
    global _hd_hook
    if _hd_hook is not None:
        _hd_hook.unhook()
        _hd_hook = None
    _hd_log("auto-patch: DISABLED")


# ----------------------------------------------------------------------------
# on load: bind hotkey + banner
# ----------------------------------------------------------------------------
_hd_hk = None


def _hd_bootstrap():
    global _hd_hk
    try:
        _hd_hk = ida_kernwin.add_hotkey("Ctrl-Alt-H", hide)
    except Exception:
        pass
    _hd_log("ready. hide() patches PEB.BeingDebugged/NtGlobalFlag + heap flags "
            "in the live process (Ctrl-Alt-H); hide_auto() re-patches on start; "
            "find_peb()/hide_status() inspect; set_peb(addr) overrides.")


_hd_bootstrap()
