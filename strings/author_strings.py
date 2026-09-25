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
#  Toolchains
#    C/C++ (MSVC and GCC/Clang), Go, Rust and .NET AOT are handled. Managed and
#    namespaced toolchains (Go/Rust/.NET) are auto-detected and attributed by
#    package/crate/namespace: the author's code is package `main` (Go), the
#    binary's own crate (Rust), or the app namespace (.NET); everything else is
#    library. When the author crate/namespace cannot be auto-identified, nothing
#    is labelled author until you name it - set_author_packages('<name>') - so a
#    library string is never shown as the author's. toolchain() and coverage()
#    report what was detected. Note: with no symbols (stripped/pure assembly)
#    provenance falls back to FLIRT, and statically linked, unsignatured code
#    cannot be told apart from author code - audit those with show_all=True.
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
import ida_segment
import idautils
import idc
import idaapi

_AS_TAG = "[authstr]"

FUNC_LIB = getattr(idaapi, "FUNC_LIB", 0x00000004)
FUNC_THUNK = getattr(idaapi, "FUNC_THUNK", 0x00000080)

# ---- toolchain support -----------------------------------------------------
#  Provenance is language-aware. Managed / namespaced toolchains embed the
#  producing package/namespace in every symbol, so the author's code can be
#  named exactly and everything else (runtime, standard library, bundled deps)
#  treated as library:
#    * Go        author = package `main`      (runtime.*, fmt.*, os.* = library)
#    * Rust      author = the binary's crate  (core::/alloc::/std:: = library)
#    * .NET AOT  author = the app namespace    (System.*/Microsoft.* = library)
#    * C/C++     no namespace - FLIRT FUNC_LIB + mangled/CRT/STL content decide
#    * assembly  no symbols - fall back to FLIRT + "must have a real referrer"
#  For Rust/.NET the author crate/namespace is auto-detected from the entry
#  symbol; when that is not possible the AUTHOR set stays empty (nothing is
#  mislabelled) and coverage() tells you to name it with set_author_packages().
_AS_AUTHOR_PKGS = None                    # None = auto; else a set of ns heads
_AS_AUTHOR_AUTO = None                    # cached auto-detected author ns set
_AS_GO_MODE = None                        # back-compat override for Go detection
_AS_TC = None                             # cached detected toolchain
_AS_DUMMY_PREFIX = ("sub_", "loc_", "unk_", "nullsub_", "j_", "def_",
                    "__imp_", "unknown_libname", "byte_", "off_", "qword_",
                    "dword_", "word_", "flt_", "dbl_", "stru_", "asc_")

# runtime namespace heads that are never the author (lower-case)
_AS_RUST_STD = frozenset({
    "core", "std", "alloc", "hashbrown", "compiler_builtins", "panic_unwind",
    "panic_abort", "backtrace", "addr2line", "gimli", "miniz_oxide", "object",
    "rustc_demangle", "libc", "adler", "adler2", "memchr", "cfg_if", "unwind",
    "proc_macro", "test", "rustc_std_workspace_core", "std_detect",
    "allocator_api2",
})
_AS_DOTNET_LIB = frozenset({
    "system", "microsoft", "internal", "interop", "s_p_corelib",
    "system_private_corelib", "il", "windows", "mscorlib",
})

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
    # ---- Rust runtime / libstd fingerprints ----
    "/rustc/", "library/core/src", "library/std/src", "library/alloc/src",
    "called `Option::unwrap()`", "called `Result::unwrap()`",
    "RUST_BACKTRACE", "internal error: entered unreachable code",
    "index out of bounds: the len is", "attempt to add with overflow",
    "attempt to subtract with overflow", "attempt to multiply with overflow",
    "already borrowed", "already mutably borrowed",
    "misaligned pointer dereference", "cargo/registry",
    # ---- .NET runtime fingerprints ----
    "System.Private.CoreLib", "Object reference not set to an instance",
    "Index was outside the bounds of the array",
    "Attempted to divide by zero",
    "The runtime has encountered a fatal error",
    # ---- GNU / libstdc++ fingerprints ----
    "terminate called", "pure virtual method called", "basic_string::_M_",
    "vector::_M_", "std::__throw", "GLIBCXX", "libstdc++",
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
    """Heuristic: does a function NAME look like CRT/STL/compiler code?
    Covers both MSVC and Itanium (GCC/Clang) C++ runtimes."""
    if not name:
        return False
    if "@@" in name or name.startswith("??"):        # MSVC mangling
        return True
    low = name.lower()
    if low.startswith(("_znst", "_zn", "_zst", "_zik", "_zik0",
                        "__cxa_", "__cxx", "_unwind_", "__gnu_cxx",
                        "__gxx_", "_global__sub")):   # Itanium C++ / libgcc
        return True
    prefixes = ("__scrt", "__acrt", "__crt", "_crt", "__security", "_rtc_",
                "_xlen", "_xbad", "__std_", "std::", "_mtx", "_thrd", "_cnd",
                "__isa_", "__guard", "_guard_", "__gshandler", "__c_specific",
                "operator new", "operator delete", "type_info", "_cxxthrow",
                "__castguard", "__vcrt", "__acrt_", "_woutput", "_output_l",
                "_findpesection", "_validateimagebase", "__report_gsfailure",
                "__libc_", "__pthread_", "_dl_", "__tunable")
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


def _as_is_go():
    """Back-compat: True when the detected toolchain is Go."""
    return _as_toolchain() == "go"


def _as_toolchain():
    """Detect the producing toolchain (cached): 'go' | 'rust' | 'dotnet' |
    'msvc' | 'gnu' | 'unknown'. Override with set_toolchain()."""
    global _AS_TC
    if _AS_TC is not None:
        return _AS_TC
    if _AS_GO_MODE is True:
        _AS_TC = "go"
        return _AS_TC
    segs = set()
    try:
        for i in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(i)
            if s:
                segs.add((ida_segment.get_segm_name(s) or "").lower())
    except Exception:
        pass
    if segs & {".gopclntab", ".go.buildinfo", ".typelink", ".itablink"}:
        _AS_TC = "go"
        return _AS_TC
    if segs & {".managedcode", "hydrated", ".managed"}:
        _AS_TC = "dotnet"
        return _AS_TC

    go = rust = dotnet = gnu = msvc = 0
    seen = 0
    for fea in idautils.Functions():
        nm = ida_funcs.get_func_name(fea) or ""
        low = nm.lower()
        if nm.startswith(("runtime.", "runtime_")) or ".goroutine" in low:
            go += 1
        if nm.startswith(("S_P_CoreLib", "System_Private_CoreLib")) \
                or "rhpnewfast" in low or low.startswith(("system_", "system.")):
            dotnet += 1
        if ("_zn" in low and ("4core" in low or "3std" in low or "5alloc" in low
                              or "17h" in low)) or nm.startswith("_R") \
                or low.startswith(("core::", "std::", "alloc::")):
            rust += 1
        if low.startswith(("_znst", "_zst", "__cxa_", "__gnu_cxx")):
            gnu += 1
        if nm.startswith("??") or "@@" in nm:
            msvc += 1
        seen += 1
        if seen > 4000:
            break
    scores = {"go": go, "dotnet": dotnet, "rust": rust, "gnu": gnu, "msvc": msvc}
    best = max(scores, key=scores.get)
    _AS_TC = best if scores[best] > 0 else "unknown"
    return _AS_TC


def _as_go_pkg(name):
    """Go package head from an (IDA-sanitised) symbol, or None.
    'runtime.mallocgc' -> 'runtime'; 'fmt._ptr_pp.doPrintf' -> 'fmt';
    'internal_cpu.doinit' -> 'internal_cpu'; 'main._ptr_T.m' -> 'main'."""
    if not name or name.startswith(_AS_DUMMY_PREFIX):
        return None
    head = name.split(".", 1)[0] if "." in name else name.split("_", 1)[0]
    head = head.split("_ptr_", 1)[0]
    return head or None


def _as_rust_head(name):
    """Rust crate head from a demangled or legacy-mangled symbol, or None."""
    if not name or name.startswith(_AS_DUMMY_PREFIX):
        return None
    if "::" in name:
        head = name.split("::", 1)[0].lstrip("<").strip()
        if " as " in head:                    # '<T as core::fmt::Debug>' -> core
            head = head.split(" as ", 1)[1].strip()
        return head or None
    if name.startswith("_ZN"):                # legacy: _ZN4core3fmt... -> core
        i = 3
        j = i
        while j < len(name) and name[j].isdigit():
            j += 1
        if j > i:
            ln = int(name[i:j])
            comp = name[j:j + ln]
            return comp or None
    return None                               # v0 (_R...) unresolved -> library


def _as_dotnet_head(name):
    """.NET namespace head, or None. NativeAOT encodes the '.' namespace
    separator as '_' and the method separator as '__', so the top-level
    namespace is the token before the first single underscore."""
    if not name or name.startswith(_AS_DUMMY_PREFIX):
        return None
    if name.startswith(("S_P_CoreLib", "System_Private_CoreLib")):
        return "system"
    for sep in ("::", "."):
        if sep in name:
            return name.split(sep, 1)[0] or None
    if "_" in name:
        return name.split("_", 1)[0] or None
    return name or None


def _as_ns_head(name, tc):
    if tc == "go":
        return _as_go_pkg(name)
    if tc == "rust":
        return _as_rust_head(name)
    if tc == "dotnet":
        return _as_dotnet_head(name)
    return None


def _as_known_lib_ns(head, tc):
    if head is None:
        return False
    h = head.lower()
    if tc == "rust":
        return h in _AS_RUST_STD
    if tc == "dotnet":
        return h in _AS_DOTNET_LIB
    if tc == "go":
        return h != "main"
    return False


def _as_author_ns():
    """The set of namespace heads treated as author code for the current
    toolchain. User-set value wins; otherwise auto-detected and cached."""
    global _AS_AUTHOR_AUTO
    if _AS_AUTHOR_PKGS is not None:
        return _AS_AUTHOR_PKGS
    tc = _as_toolchain()
    if tc == "go":
        return {"main"}
    if tc not in ("rust", "dotnet"):
        return set()
    if _AS_AUTHOR_AUTO is not None:
        return _AS_AUTHOR_AUTO
    _AS_AUTHOR_AUTO = _as_detect_author_ns(tc)
    return _AS_AUTHOR_AUTO


def _as_detect_author_ns(tc):
    """Best-effort: the namespace of the entry symbol (crate::main / *.Main)
    that is not a known runtime namespace."""
    found = set()
    seen = 0
    for fea in idautils.Functions():
        nm = ida_funcs.get_func_name(fea) or ""
        low = nm.lower()
        is_entry = (low.endswith("::main") or low.endswith(".main")
                    or low.endswith("__main") or "::main::" in low
                    or low.endswith("_main") or "program__main" in low
                    or low.endswith(".main()"))
        if is_entry:
            head = _as_ns_head(nm, tc)
            if head and not _as_known_lib_ns(head, tc):
                found.add(head.lower())
        seen += 1
        if seen > 6000:
            break
    return found


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
    name = ida_funcs.get_func_name(f.start_ea) or ""
    tc = _as_toolchain()
    if tc in ("go", "rust", "dotnet"):
        head = _as_ns_head(name, tc)
        if head is None:
            # unnamed / stub: bias to library for namespaced toolchains so a
            # runtime stub can never surface as author (except Go, where author
            # code is always package-qualified and stubs are rare runtime asm).
            return "user" if tc == "go" else "lib"
        return "user" if head.lower() in _as_author_ns() else "lib"
    if _as_name_is_lib(name):
        return "lib"
    return "user"


def set_author_packages(*names):
    """Set the namespace head(s) treated as author code (Go package, Rust crate,
    or .NET namespace). Example: set_author_packages('main'), or
    set_author_packages('crackme') for a Rust crate. Call with no arguments to
    return to auto-detection."""
    global _AS_AUTHOR_PKGS, _AS_AUTHOR_AUTO
    _AS_AUTHOR_AUTO = None
    _AS_AUTHOR_PKGS = set(n.lower() for n in names) if names else None
    _as_log("author namespaces: %s"
            % (", ".join(sorted(_AS_AUTHOR_PKGS)) if _AS_AUTHOR_PKGS else "auto"))
    return _AS_AUTHOR_PKGS


def set_toolchain(tc):
    """Force the toolchain ('go'|'rust'|'dotnet'|'msvc'|'gnu'|'unknown'), or
    None to re-enable auto-detection."""
    global _AS_TC, _AS_AUTHOR_AUTO
    _AS_TC = tc
    _AS_AUTHOR_AUTO = None
    _as_log("toolchain = %s" % (tc or "auto"))
    return _AS_TC


def set_go_mode(on):
    """Back-compat: force Go mode on/off (None re-enables auto-detection)."""
    global _AS_GO_MODE, _AS_TC
    _AS_GO_MODE = on
    _AS_TC = None
    _as_log("Go mode = %s" % ("auto" if on is None else on))
    return _AS_GO_MODE


def toolchain():
    """Report the detected toolchain and the author namespace(s) in use."""
    tc = _as_toolchain()
    auth = _as_author_ns()
    _as_log("toolchain: %s   author namespace(s): %s"
            % (tc, ", ".join(sorted(auth)) if auth else
               "(none - set with set_author_packages)"))
    return tc


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
    """Report how confidently provenance can attribute code, per toolchain."""
    tc = _as_toolchain()
    if tc in ("go", "rust", "dotnet"):
        authns = _as_author_ns()
        total = author = lib = named = 0
        for fea in idautils.Functions():
            total += 1
            head = _as_ns_head(ida_funcs.get_func_name(fea) or "", tc)
            if head is None:
                continue
            named += 1
            if head.lower() in authns:
                author += 1
            else:
                lib += 1
        _as_log("%s binary: %d function(s), %d namespaced; %d in author {%s}, "
                "%d in library/other."
                % (tc, total, named, author,
                   ", ".join(sorted(authns)) if authns else "-", lib))
        if author == 0:
            _as_log("  no functions in the author namespace. Name it explicitly: "
                    "set_author_packages('<crate_or_namespace>'); toolchain() "
                    "and author_strings(show_all=True) help identify it.")
        return author, total
    total = libf = 0
    for fea in idautils.Functions():
        total += 1
        f = ida_funcs.get_func(fea)
        if f and ((f.flags & FUNC_LIB) or
                  _as_name_is_lib(ida_funcs.get_func_name(fea) or "")):
            libf += 1
    pct = (100.0 * libf / total) if total else 0.0
    _as_log("toolchain=%s. FLIRT/library coverage: %d of %d function(s) marked "
            "library (%.1f%%)" % (tc, libf, total, pct))
    if libf == 0:
        _as_log("  no library functions recognised - apply signatures for best "
                "precision (the content backstop still filters classic runtime "
                "strings). Let auto-analysis finish, or add signatures.")
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
            "show_all=True audits every verdict; find(sub) searches; explain(ea) "
            "shows the reasoning; toolchain()/coverage() report detection. "
            "Handles C/C++, Go, Rust, .NET AOT; set_author_packages('<name>') "
            "if the author crate/namespace is not auto-found.")


_as_bootstrap()
