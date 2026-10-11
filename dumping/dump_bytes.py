# dump_bytes.py
#
# Export a range of bytes from an IDA database as a Python list literal
# ready to paste into an external script.
#
# Starting address is taken from the current cursor position in IDA.
# Ending address is prompted via a dialog, or passed as a function argument.
#
# Install:
#   File -> Script file... -> dump_bytes.py
#   (or drop into IDA's plugins/ folder to load on startup)
#
# Three ways to invoke:
#   1. Hotkey Ctrl+Shift+D anywhere in disassembly or hex view.
#   2. Right-click a line -> "Dump bytes to Python list".
#   3. Python prompt: dump_range(start=0x..., end=0x..., var_name="my_bytes")
#
# End address input accepts:
#   - A hex or decimal address, e.g. 0x7FF6D001418C
#   - +N for a byte count starting at the cursor, e.g. +16
#
# Works on any item size in the database (db, dw, dd, dq, aligned, undef).
# get_bytes() reads the raw memory bytes regardless of how IDA has typed them.

import ida_bytes
import ida_kernwin
import idaapi
import idc


ACTION_ID    = "DumpBytes:ToPythonList"
ACTION_LABEL = "Dump bytes to Python list"
HOTKEY       = "Ctrl+Shift+D"
WRAP         = 16                 # items per line in the output
MAX_WARN     = 1024 * 1024        # warn if the user asks for more than 1 MB


# ---------------- formatting ----------------

def _format_python_list(start, end, data, var_name):
    """Format a bytes blob as a Python list literal with a header comment."""
    length = len(data)
    items  = [f"0x{b:02X}" for b in data]

    rows = []
    for i in range(0, len(items), WRAP):
        rows.append("    " + ", ".join(items[i:i + WRAP]) + ",")
    if rows:
        rows[-1] = rows[-1].rstrip(",")

    header = f"# {length} bytes from {start:#x} to {end:#x}"
    body   = f"{var_name} = [\n" + "\n".join(rows) + "\n]"
    return header + "\n" + body


def _default_var_name(ea):
    """Pick a variable name based on the segment the EA lives in."""
    seg = idc.get_segm_name(ea) or ""
    base = seg.lstrip(".").lower()
    if not base:
        base = "data"
    return base + "_bytes"


# ---------------- clipboard ----------------

def _try_clipboard(text):
    """Best-effort clipboard copy via whichever Qt binding IDA is using.
       Returns True if the copy succeeded, False otherwise."""
    for mod_name in ("PyQt5.QtWidgets", "PySide6.QtWidgets", "PySide2.QtWidgets"):
        try:
            mod = __import__(mod_name, fromlist=["QApplication"])
            app = mod.QApplication.instance()
            if app is not None:
                app.clipboard().setText(text)
                return True
        except Exception:
            continue
    return False


# ---------------- core function ----------------

def dump_range(start=None, end=None, var_name=None, copy=True, show=True):
    """Dump bytes from start to end (inclusive) as a Python list literal.

    Args:
        start:    starting EA. If None, uses the current cursor position.
        end:      ending EA, inclusive. If None, the user is prompted.
        var_name: variable name in the output. If None, derived from the segment.
        copy:     also push the result to the clipboard.
        show:     print the result to the Output Window.

    Returns:
        The formatted string, or None if cancelled or an error occurred.
    """
    if start is None:
        start = idc.here()

    if end is None:
        default = f"{start + 15:#x}"
        prompt  = (f"Start: {start:#x}\n"
                   f"Enter end address, or +N for a byte count:")
        resp = ida_kernwin.ask_str(default, 0, prompt)
        if resp is None:
            return None
        resp = resp.strip()
        try:
            if resp.startswith("+"):
                count = int(resp[1:], 0)
                if count <= 0:
                    print(f"[dump_bytes] count must be positive: {count}")
                    return None
                end = start + count - 1
            else:
                end = int(resp, 0)
        except ValueError:
            print(f"[dump_bytes] could not parse end: {resp!r}")
            return None

    if end < start:
        print(f"[dump_bytes] end {end:#x} is before start {start:#x}")
        return None

    length = end - start + 1
    if length > MAX_WARN:
        if ida_kernwin.ask_yn(0,
                f"HIDECANCEL\nDump {length} bytes? That is unusually large.") != 1:
            return None

    data = ida_bytes.get_bytes(start, length)
    if data is None:
        print(f"[dump_bytes] failed to read {length} bytes at {start:#x}")
        return None

    if var_name is None:
        var_name = _default_var_name(start)

    output = _format_python_list(start, end, data, var_name)

    if show:
        print(output)
    if copy and _try_clipboard(output):
        print(f"[dump_bytes] {length} bytes copied to clipboard")

    return output


# ---------------- IDA integration ----------------

class _DumpBytesHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        dump_range()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# Build the set of widgets to attach the context-menu entry to.
# Done at import time with getattr() so missing constants in different
# IDA builds do not break the hook.
_POPUP_WIDGETS = tuple(
    getattr(idaapi, name)
    for name in ("BWN_DISASM", "BWN_HEXVIEW", "BWN_DUMP")
    if hasattr(idaapi, name)
)


class _DumpBytesHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) in _POPUP_WIDGETS:
            idaapi.attach_action_to_popup(widget, popup, ACTION_ID, None)


_hooks = None


def install():
    """Register the action, hotkey and right-click entry.
       Safe to call multiple times (idempotent)."""
    global _hooks

    idaapi.unregister_action(ACTION_ID)
    desc = idaapi.action_desc_t(
        ACTION_ID,
        ACTION_LABEL,
        _DumpBytesHandler(),
        HOTKEY,
        "Export a byte range as a Python list for use in external scripts",
        -1,
    )
    if not idaapi.register_action(desc):
        print("[dump_bytes] could not register action")
        return

    if _hooks is not None:
        _hooks.unhook()
    _hooks = _DumpBytesHooks()
    _hooks.hook()

    print(f"[dump_bytes] ready. Hotkey {HOTKEY} or right-click -> '{ACTION_LABEL}'")


def uninstall():
    """Remove the action, hotkey and right-click entry."""
    global _hooks
    if _hooks is not None:
        _hooks.unhook()
        _hooks = None
    idaapi.unregister_action(ACTION_ID)
    print("[dump_bytes] unregistered")


# Auto-install when the script is executed via File -> Script file...
install()
