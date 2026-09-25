# ============================================================================
#  author_strings.py - isolate the strings written by the binary's author
# ----------------------------------------------------------------------------
#  IDA's Strings view lists every literal in the image: the C runtime, the STL,
#  RTTI type descriptors, statically linked libraries, and - buried among the
#  thousands - the handful the author actually wrote (prompts, messages, keys,
#  format strings). This separates the author's strings from the library noise.
#
#  How the decision is made (provenance first, content second)
#    * PROVENANCE. Every string's cross-references are examined. A reference
#      from a function IDA recognises as library code (FLIRT FUNC_LIB, thunks,
#      or a C++/CRT-mangled name) is a library reference; a reference from any
#      other function is a user reference. A string reached from user code is
#      attributed to the author. This is the reliable signal, because FLIRT
#      identifies the runtime/STL and the author's own code is never matched.
#    * CONTENT BACKSTOP. A conservative, high-precision set of runtime/STL/RTTI
#      fingerprints (mangled names, `bad allocation`, `Runtime Error!`, vftable
#      markers, api-ms-win-*, compiler build paths, ...) removes library strings
#      that are unreferenced or reached only through data tables. The list only
#      matches text that is unmistakably library, so author strings are kept.
#    * ARTIFACTS. Build artifacts that identify the author - PDB paths, assert
#      __FILE__ source paths - are surfaced in their own category rather than
#      discarded, since they often name the project or developer.
#
#  Verdicts: AUTHOR, ARTIFACT (shown by default), LIBRARY, UNREF, NOISE.
#
#  Console interface
#    author_strings(show_all=False)   scan and open a jump-list of author (and
#                                      artifact) strings; show_all lists every
#                                      verdict for auditing
#    strings_report(show_all=False)   same as text in the Output window
#    find(substr, scope="author")     substring search; scope author|all
#    explain(target)                  why one string was classified as it is
#                                      (target = ea/hex, or index in last scan)
#    coverage()                       FLIRT library-function coverage (trust)
#
#  Options on author_strings/strings_report:
#    min_len=4, include_unref=False, segments=None (e.g. [".rdata", ".data"])
#
#  Hotkey
#    Ctrl-Alt-A   author_strings() over the whole image
# ============================================================================

import re

import ida_bytes
import ida_funcs
import ida_kernwin
import idautils
import idc
import idaapi

_AS_TAG = "[authstr]"

FUNC_LIB = getattr(idaapi, "FUNC_LIB", 0x00000004)
FUNC_THUNK = getattr(idaapi, "FUNC_THUNK", 0x00000080)

# verdict -> (label, BGR line colour, shown-by-default)
_AS_META = {
    "AUTHOR":   ("author", 0xC0FFC0, True),
    "ARTIFACT": ("artifact", 0xC0F0FF, True),
    "LIBRARY":  ("library", 0xE0E0E0, False),
    "UNREF":    ("unref", 0xF0E0C0, False),
    "NOISE":    ("noise", 0xD0D0D0, False),
}

# ---- high-precision library/runtime content fingerprints -------------------
_AS_LIB_SUBSTR = (
    "This program cannot be run in DOS mode",
    "bad allocation", "bad array new length", "bad_alloc", "bad_cast",
    "bad_typeid", "bad exception", "bad_function_call", "bad_weak_ptr",
    "vector too long", "string too long", "list too long", "deque too long",
    "map/set too long", "unordered_map/set too long",
    "invalid string position", "invalid vector<bool> subscript",
    "cannot seek vector iterator", "cannot decrement",
    "ios_base::badbit set", "ios_base::failbit set", "ios_base::eofbit set",
    "bad locale name", "locale::facet", "locale::_Addfac",
    "Unknown exception", "pure virtual function call",
    "Runtime Error!", "Microsoft Visual C++ Runtime Library",
    "This application has requested the Runtime",
    "not enough space for", "abort() has been called",
    "CRT not initialized", "unable to initialize heap",
    "floating point support not loaded",
    "MSIL code from this assembly",
    "Stack around the variable", "stack cookie",
    "api-ms-win-", "ext-ms-win-", "ucrtbase", "vcruntime", "VCRUNTIME",
    "mscoree.dll", "MSVCP", "MSVCR",
)
# unmistakable library name/path fragments (case-insensitive)
_AS_LIB_SUBSTR_CI = (
    "\\vctools\\", "minkernel\\crts", "onecore\\", "\\crt\\src\\",
    "\\vc\\tools\\msvc\\", "d:\\a01\\", "d:\\a\\_work\\", "\\agent\\_work\\",
    "program files\\microsoft visual studio",
)
# compiler-generated backtick names and RTTI markers
_AS_LIB_TICK = (
    "`vftable'", "`vbtable'", "`rtti", "`typeid", "`dynamic",
    "`scalar deleting", "`vector deleting", "`local static",
    "`anonymous namespace'", "`copy constructor closure",
    "`eh vector", "`managed vector", "`vcall'", "`local vftable'",
)
_AS_MANGLED = re.compile(r"\?\?[_$0-9A-Za-z]|\.\?A[VUW]|^\?[A-Za-z_].*@@")

_AS_ARTIFACT_SRC = re.compile(r"\.(pdb|cpp|cxx|cc|c|hpp|hxx|h)$", re.IGNORECASE)


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _as_log(msg):
    print("%s %s" % (_AS_TAG, msg))


def _as_addr(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip().lower().replace("0x", ""), 16)
        except ValueError:
            return None
    return None


def _as_printable_ratio(s):
    if not s:
        return 0.0
    ok = sum(1 for c in s if 0x20 <= ord(c) < 0x7F or c in "\t\r\n")
    return ok / len(s)


# ----------------------------------------------------------------------------
# pure classifiers (content only; no IDA state - unit-testable offline)
# ----------------------------------------------------------------------------
def _as_is_noise(s, min_len):
    t = (s or "").strip("\x00\r\n\t ")
    if len(t) < min_len:
        return True
    if _as_printable_ratio(t) < 0.85:
        return True
    if len(set(t)) <= 1:                       # e.g. "@@@@@@", "        "
        return True
    return False


def _as_looks_library(s):
    if not s:
        return False, ""
    if _AS_MANGLED.search(s):
        return True, "C++ mangled / RTTI name"
    for frag in _AS_LIB_TICK:
        if frag in s:
            return True, "compiler-generated symbol (%s)" % frag
    for frag in _AS_LIB_SUBSTR:
        if frag in s:
            return True, "runtime/STL fingerprint (%r)" % frag
    low = s.lower()
    for frag in _AS_LIB_SUBSTR_CI:
        if frag in low:
            return True, "compiler build path (%r)" % frag
    return False, ""


def _as_is_artifact(s):
    if not s:
        return False, ""
    if _AS_ARTIFACT_SRC.search(s.strip()):
        low = s.lower()
        if low.endswith(".pdb"):
            return True, "PDB path (names the project/build)"
        return True, "source file path (assert/__FILE__)"
    low = s.lower()
    if "\\source\\repos\\" in low or "\\documents\\" in low:
        return True, "developer source path"
    return False, ""


def _as_name_is_lib(name):
    """Heuristic: does a function NAME look like CRT/STL/compiler code?"""
    if not name:
        return False
    if "@@" in name or name.startswith("??"):
        return True
    low = name.lower()
    prefixes = ("__scrt", "__acrt", "__crt", "_crt", "__security", "_rtc_",
                "_xlen", "_xbad", "__std_", "std::", "_mtx", "_thrd", "_cnd",
                "__isa_", "__guard", "_guard_", "__gshandler", "__c_specific",
                "operator new", "operator delete", "type_info", "_cxxthrow",
                "__castguard", "__vcrt", "__acrt_", "_woutput", "_output_l",
                "_findpesection", "_validateimagebase", "__report_gsfailure")
    return low.startswith(prefixes)


def _as_classify(content, refs, min_len):
    """refs = (user, lib, thunk, data). Returns (verdict, reason)."""
    user, lib, thunk, data = refs
    if _as_is_noise(content, min_len):
        return "NOISE", "too short or not printable"
    islib, why = _as_looks_library(content)
    if islib:
        return "LIBRARY", why
    if user > 0:
        return "AUTHOR", "referenced by user code"
    isart, awhy = _as_is_artifact(content)
    if isart:
        return "ARTIFACT", awhy
    if lib > 0 or thunk > 0:
        return "LIBRARY", "referenced only by library code"
    return "UNREF", "no code reference"


# ----------------------------------------------------------------------------
# IDA-backed provenance
# ----------------------------------------------------------------------------
def _as_func_name(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    return ida_funcs.get_func_name(f.start_ea)


def _as_func_kind(ea):
    """Classify the function containing `ea`: 'user' | 'lib' | 'thunk' | None."""
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    flags = f.flags
    if flags & FUNC_THUNK:
        return "thunk"
    if flags & FUNC_LIB:
        return "lib"
    if _as_name_is_lib(ida_funcs.get_func_name(f.start_ea) or ""):
        return "lib"
    return "user"


def _as_refs(ea):
    """Tally references to `ea`. Data (pointer-table) references are followed
    one level, so a string reached through an author pointer array still counts
    as user-referenced. Returns (user, lib, thunk, data, sample_referrer)."""
    user = lib = thunk = data = 0
    sample = None
    for xr in idautils.XrefsTo(ea, 0):
        kind = _as_func_kind(xr.frm)
        if kind == "user":
            user += 1
            sample = sample or _as_func_name(xr.frm)
        elif kind == "lib":
            lib += 1
        elif kind == "thunk":
            thunk += 1
        else:
            data += 1
            for xr2 in idautils.XrefsTo(xr.frm, 0):   # one level up the pointer
                k2 = _as_func_kind(xr2.frm)
                if k2 == "user":
                    user += 1
                    sample = sample or _as_func_name(xr2.frm)
                elif k2 == "lib":
                    lib += 1
                elif k2 == "thunk":
                    thunk += 1
    return user, lib, thunk, data, sample


def _as_text(s):
    try:
        t = str(s)
    except Exception:
        t = ""
    return t.rstrip("\x00")


def _as_seg(ea):
    return idc.get_segm_name(ea) or "?"


# ----------------------------------------------------------------------------
# collection
# ----------------------------------------------------------------------------
def coverage():
    """Report FLIRT library-function coverage - how much to trust provenance."""
    total = libf = 0
    for fea in idautils.Functions():
        total += 1
        f = ida_funcs.get_func(fea)
        if f and ((f.flags & FUNC_LIB) or
                  _as_name_is_lib(ida_funcs.get_func_name(fea) or "")):
            libf += 1
    pct = (100.0 * libf / total) if total else 0.0
    _as_log("FLIRT/library coverage: %d of %d function(s) marked library (%.1f%%)"
            % (libf, total, pct))
    if libf == 0:
        _as_log("  no library functions recognised - apply signatures for best "
                "precision (the content backstop still filters classic runtime "
                "strings). Options > ... or let auto-analysis finish.")
    return libf, total


def _as_collect(min_len=4, include_unref=False, segments=None):
    seglist = None
    if segments:
        seglist = set(s.lower().lstrip(".") for s in segments)
    rows = []
    try:
        items = idautils.Strings()
    except Exception as exc:
        _as_log("could not enumerate strings: %s" % exc)
        return rows
    for s in items:
        ea = s.ea
        seg = _as_seg(ea)
        if seglist is not None and seg.lower().lstrip(".") not in seglist:
            continue
        content = _as_text(s)
        refs = _as_refs(ea)
        verdict, reason = _as_classify(content, refs[:4], min_len)
        rows.append({"ea": ea, "seg": seg, "verdict": verdict,
                     "content": content, "refs": refs[:4],
                     "referrer": refs[4], "reason": reason})
    return rows


# ----------------------------------------------------------------------------
# reporting + chooser
# ----------------------------------------------------------------------------
_as_last_rows = []


def _as_refs_str(refs):
    u, l, t, d = refs
    return "u%d l%d t%d d%d" % (u, l, t, d)


def _as_summary(rows):
    from collections import Counter
    c = Counter(r["verdict"] for r in rows)
    _as_log("%d string(s): %d author, %d artifact, %d library, %d unref, %d noise"
            % (len(rows), c["AUTHOR"], c["ARTIFACT"], c["LIBRARY"],
               c["UNREF"], c["NOISE"]))
    return c


class _AsChooser(ida_kernwin.Choose):
    def __init__(self, title, rows):
        cols = [["Address", ida_kernwin.Choose.CHCOL_HEX | 14],
                ["Segment", 10], ["Verdict", 9], ["Refs", 14],
                ["String", 70], ["Referrer", 22]]
        ida_kernwin.Choose.__init__(self, title, cols,
                                    flags=ida_kernwin.Choose.CH_RESTORE)
        self.rows = rows
        self.items = [[
            "%X" % r["ea"], r["seg"], _AS_META[r["verdict"]][0],
            _as_refs_str(r["refs"]),
            (r["content"][:70].replace("\n", "\\n").replace("\r", "\\r")),
            r["referrer"] or "-",
        ] for r in rows]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetLineAttr(self, n):
        if 0 <= n < len(self.rows):
            return [_AS_META[self.rows[n]["verdict"]][1], 0]
        return None

    def OnSelectLine(self, n):
        idx = n[0] if isinstance(n, (list, tuple)) else n
        if idx is not None and 0 <= idx < len(self.rows):
            ida_kernwin.jumpto(self.rows[idx]["ea"])
        nc = getattr(ida_kernwin.Choose, "NOTHING_CHANGED", None)
        return (nc,) if nc is not None else None


def _as_shown(rows, show_all, include_unref):
    if show_all:
        return rows
    keep = {"AUTHOR", "ARTIFACT"}
    if include_unref:
        keep.add("UNREF")
    return [r for r in rows if r["verdict"] in keep]


def author_strings(show_all=False, min_len=4, include_unref=False,
                   segments=None):
    """Scan the image and open a jump-list of the author's strings.
    show_all lists every verdict; include_unref adds unreferenced strings;
    segments restricts the scan (e.g. segments=['.rdata'])."""
    global _as_last_rows
    rows = _as_collect(min_len, include_unref, segments)
    if not rows:
        _as_log("no strings found (check IDA's string detection settings).")
        return None
    _as_last_rows = rows
    _as_summary(rows)
    shown = _as_shown(rows, show_all, include_unref)
    if not shown:
        _as_log("no author strings surfaced. Try author_strings(show_all=True) "
                "to audit, or include_unref=True.")
        return None
    _AsChooser("Author strings%s" % (" (all)" if show_all else ""), shown).Show()
    _as_log("showing %d of %d string(s). explain(ea) for the reasoning; "
            "coverage() for FLIRT trust." % (len(shown), len(rows)))
    return None


def strings_report(show_all=False, min_len=4, include_unref=False,
                   segments=None):
    """Text version of author_strings() for the Output window."""
    global _as_last_rows
    rows = _as_collect(min_len, include_unref, segments)
    if not rows:
        _as_log("no strings found.")
        return None
    _as_last_rows = rows
    _as_summary(rows)
    for r in _as_shown(rows, show_all, include_unref):
        _as_log("  %-9s %-10s %-14s %012X  %s"
                % (_AS_META[r["verdict"]][0], r["seg"], _as_refs_str(r["refs"]),
                   r["ea"], r["content"][:90].replace("\n", "\\n")))
    return None


def find(substr, scope="author"):
    """Substring search (case-insensitive). scope = 'author' | 'all'."""
    if not _as_last_rows:
        _as_collect_into_cache()
    q = str(substr).lower()
    pool = _as_last_rows if scope == "all" else \
        [r for r in _as_last_rows if r["verdict"] in ("AUTHOR", "ARTIFACT")]
    hits = [r for r in pool if q in r["content"].lower()]
    _as_log("%d match(es) for %r in %s strings:" % (len(hits), substr, scope))
    for r in hits:
        _as_log("  %012X  [%s]  %s"
                % (r["ea"], _AS_META[r["verdict"]][0], r["content"][:90]))
    return None


def _as_collect_into_cache():
    global _as_last_rows
    _as_last_rows = _as_collect()


def explain(target):
    """Explain the classification of one string (ea/hex, or last-scan index)."""
    row = None
    if isinstance(target, int) and 0 <= target < len(_as_last_rows) \
            and _as_addr(target) not in [r["ea"] for r in _as_last_rows]:
        row = _as_last_rows[target]
    if row is None:
        ea = _as_addr(target)
        row = next((r for r in _as_last_rows if r["ea"] == ea), None)
        if row is None and ea is not None:
            content = _as_text(next((s for s in idautils.Strings() if s.ea == ea), ""))
            refs = _as_refs(ea)
            v, why = _as_classify(content, refs[:4], 4)
            row = {"ea": ea, "seg": _as_seg(ea), "verdict": v, "content": content,
                   "refs": refs[:4], "referrer": refs[4], "reason": why}
    if row is None:
        _as_log("no string at %r (run author_strings() first)" % (target,))
        return None
    u, l, t, d = row["refs"]
    _as_log("%012X  [%s]  seg=%s" % (row["ea"], _AS_META[row["verdict"]][0], row["seg"]))
    _as_log("  content : %r" % row["content"][:120])
    _as_log("  refs    : user=%d library=%d thunk=%d data=%d  (referrer: %s)"
            % (u, l, t, d, row["referrer"] or "-"))
    _as_log("  reason  : %s" % row["reason"])
    return None


# ----------------------------------------------------------------------------
# bootstrap
# ----------------------------------------------------------------------------
_as_hotkey = None


def _as_bootstrap():
    global _as_hotkey
    try:
        _as_hotkey = ida_kernwin.add_hotkey("Ctrl-Alt-A", author_strings)
    except Exception as exc:
        _as_log("could not bind hotkey: %s" % exc)
    _as_log("ready. author_strings() lists the author's strings (Ctrl-Alt-A); "
            "author_strings(show_all=True) audits every verdict; find(sub) "
            "searches; explain(ea) shows the reasoning; coverage() reports "
            "FLIRT trust.")


_as_bootstrap()
