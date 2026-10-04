# -*- coding: utf-8 -*-
"""
dll_loader_stub_generator.py
============================

IDAPython utility that generates a minimal, dependency-free 64-bit loader
executable for the DLL that is currently open in IDA.

The generated stub does up to three things:

    1. Call ``LoadLibraryExW`` on the absolute path of the target DLL.
    2. Optionally break (``int3``) right after the load so the debugger stops
       with the DLL mapped at a known base.
    3. Block indefinitely with ``Sleep(INFINITE)`` so the process stays alive
       and the DLL remains mapped for inspection.

Two load modes (see ``generate_loader_for_current_dll``):

    * run_dllmain=True  (default) - normal load; the loader runs the DLL's
      DllMain and TLS callbacks. Use this for self-unpacking samples whose OEP
      is reached through DllMain.
    * run_dllmain=False           - LoadLibraryExW with
      DONT_RESOLVE_DLL_REFERENCES: the DLL is mapped but DllMain is NOT called
      and imports are NOT resolved. Use this when a normal load HANGS - a DLL
      whose DllMain waits for its original loader (shared sections, a specific
      parent, a mutex/event, a C2 callback) never returns from LoadLibrary. You
      then set breakpoints and invoke DllMain / an export yourself.

Using this stub as the debugger "application" lets you debug a DLL through the
Windows loader without relying on ``rundll32.exe`` or IDA's built-in loader
stub, and without having to guess an exported ordinal.

NOTE on memory dumps: a DLL dumped from memory (e.g. a reflectively-injected
payload) is usually section-aligned on disk and may not load via LoadLibrary at
all. The generator warns when the input looks like a raw memory image; realign
it to file form first, or analyse it under its original loader.

Typical workflow
-----------------
    1. Open the target DLL in IDA.
    2. Run this script (File > Script file... / Alt+F7).
    3. A ``<dllname>_<random>.exe`` file is written next to the DLL.
    4. Debugger > Select debugger > Local Windows debugger.
    5. Debugger > Process options... > set "Application" to the generated .exe
       (the script also attempts to do this automatically, best-effort).
    6. Enable "Suspend on library load/unload", start debugging, then set a
       breakpoint on the DLL entry point to catch the original entry point
       (OEP) of self-unpacking samples.

Design notes
------------
    * The stub is fully position independent: the code uses RIP-relative
      addressing and the import tables use RVAs only, so it maps correctly at
      any base. It is nevertheless marked ``RELOCS_STRIPPED`` and given a fixed
      preferred base for deterministic loading.
    * Anti-anti-debug (e.g. ScyllaHide) is orthogonal to this tool. If the
      sample employs anti-debugging, configure ScyllaHide separately in IDA.

The module can also be executed outside IDA for self-testing:

    python dll_loader_stub_generator.py <dll_path> <output_exe>

Author  : ShadowStrike-Labs
License : MIT
"""

import os
import random
import struct

try:
    import ida_nalt
    import ida_kernwin
    import ida_dbg

    _IN_IDA = True
except ImportError:  # allows the PE builder to be reused/tested outside IDA
    _IN_IDA = False


# --------------------------------------------------------------------------- #
# PE / COFF constants
# --------------------------------------------------------------------------- #
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
IMAGE_BASE = 0x140000000

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B
IMAGE_SUBSYSTEM_WINDOWS_CUI = 0x0003
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

INFINITE = 0xFFFFFFFF

# LoadLibraryEx flags
DONT_RESOLVE_DLL_REFERENCES = 0x00000001  # map only: no DllMain, no imports

_LOG_TAG = "[loader-stub]"


def _align(value, alignment):
    """Round *value* up to the next multiple of *alignment*."""
    return (value + alignment - 1) & ~(alignment - 1)


def _pe_looks_memory_aligned(data):
    """Heuristic: does this PE look like a raw memory image (section-aligned on
    disk) rather than a normal on-disk file? Such images frequently fail to
    load through LoadLibrary. Returns (is_dump, reason)."""
    try:
        if data[:2] != b"MZ":
            return (False, "")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return (False, "")
        coff = e_lfanew + 4
        num_sec = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        sect_align = struct.unpack_from("<I", data, opt + 32)[0]
        file_align = struct.unpack_from("<I", data, opt + 36)[0]
        if sect_align and file_align and sect_align == file_align:
            return (True, "FileAlignment == SectionAlignment (%#x)" % file_align)
        sec_tbl = opt + opt_size
        for i in range(min(num_sec, 96)):
            sh = sec_tbl + i * 40
            if sh + 40 > len(data):
                break
            vaddr = struct.unpack_from("<I", data, sh + 12)[0]
            praw = struct.unpack_from("<I", data, sh + 20)[0]
            if vaddr >= max(sect_align, 0x1000) and praw == vaddr:
                return (True, "section raw pointer == RVA (%#x)" % vaddr)
        return (False, "")
    except Exception:
        return (False, "")


# --------------------------------------------------------------------------- #
# PE builder
# --------------------------------------------------------------------------- #
def build_loader_pe(dll_path, run_dllmain=True, break_after_load=False):
    """Return the bytes of a 64-bit console executable that loads *dll_path*.

    Imports ``LoadLibraryExW`` and ``Sleep`` from ``kernel32.dll`` and calls
    ``LoadLibraryExW(dll_path, NULL, flags)`` followed by a ``Sleep(INFINITE)``
    parking loop.

        run_dllmain=True   -> flags = 0 (normal load; DllMain and TLS run).
        run_dllmain=False  -> flags = DONT_RESOLVE_DLL_REFERENCES (map only; no
                              DllMain, no import resolution). Use when a normal
                              load hangs inside the DLL's entry routine.
        break_after_load   -> emit an ``int3`` right after the load so the
                              debugger stops with the DLL mapped (debugger only).
    """
    text_rva = SECTION_ALIGNMENT * 1   # 0x1000
    rdata_rva = SECTION_ALIGNMENT * 2  # 0x2000

    # ----- .rdata layout: import directory, thunks and strings ----------- #
    imports = [b"LoadLibraryExW", b"Sleep"]  # order defines IAT/ILT slots

    def _padded(blob):
        return blob + (b"\x00" if len(blob) & 1 else b"")

    cursor = 0
    idt_off = cursor
    cursor += 2 * 20                                  # 2 x IMAGE_IMPORT_DESCRIPTOR
    ilt_off = cursor
    cursor += (len(imports) + 1) * 8                  # ILT thunks + NULL
    iat_off = cursor
    cursor += (len(imports) + 1) * 8                  # IAT thunks + NULL

    hint_name_offs = []
    for name in imports:
        hint_name_offs.append(cursor)
        cursor += len(_padded(struct.pack("<H", 0) + name + b"\x00"))

    dllname_off = cursor
    dllname_blob = _padded(b"kernel32.dll\x00")
    cursor += len(dllname_blob)

    path_off = cursor
    path_blob = dll_path.encode("utf-16-le") + b"\x00\x00"
    cursor += len(path_blob)

    rdata_size = cursor

    def to_rva(local_off):
        return rdata_rva + local_off

    rdata = bytearray(rdata_size)

    # IMAGE_IMPORT_DESCRIPTOR[0] -> kernel32.dll
    struct.pack_into(
        "<IIIII", rdata, idt_off,
        to_rva(ilt_off),      # OriginalFirstThunk (ILT)
        0,                    # TimeDateStamp
        0,                    # ForwarderChain
        to_rva(dllname_off),  # Name
        to_rva(iat_off),      # FirstThunk (IAT)
    )
    # IMAGE_IMPORT_DESCRIPTOR[1] is the all-zero terminator (already zeroed).

    # Import Lookup Table and Import Address Table (identical on disk).
    for index, hn_off in enumerate(hint_name_offs):
        thunk = to_rva(hn_off)
        struct.pack_into("<Q", rdata, ilt_off + index * 8, thunk)
        struct.pack_into("<Q", rdata, iat_off + index * 8, thunk)

    # IMAGE_IMPORT_BY_NAME entries.
    for name, hn_off in zip(imports, hint_name_offs):
        blob = _padded(struct.pack("<H", 0) + name + b"\x00")
        rdata[hn_off:hn_off + len(blob)] = blob

    rdata[dllname_off:dllname_off + len(dllname_blob)] = dllname_blob
    rdata[path_off:path_off + len(path_blob)] = path_blob

    # ----- .text: position-independent stub ------------------------------ #
    path_rva = to_rva(path_off)
    iat_loadlibraryex_rva = to_rva(iat_off + 0 * 8)
    iat_sleep_rva = to_rva(iat_off + 1 * 8)
    flags = 0 if run_dllmain else DONT_RESOLVE_DLL_REFERENCES

    code = bytearray()

    def emit(data):
        code.extend(data)

    def rip_disp32(target_rva):
        # Displacement is relative to the RVA of the *next* instruction, i.e.
        # the current position plus the 4-byte displacement itself.
        return struct.pack("<i", target_rva - (text_rva + len(code) + 4))

    emit(b"\x48\x83\xEC\x28")            # sub rsp, 0x28   (shadow space + align)
    emit(b"\x48\x8D\x0D")                # lea rcx, [rip+dll_path]
    emit(rip_disp32(path_rva))
    emit(b"\x31\xD2")                    # xor edx, edx    (hFile = NULL)
    emit(b"\x41\xB8" + struct.pack("<I", flags))  # mov r8d, flags
    emit(b"\xFF\x15")                    # call [rip+LoadLibraryExW]
    emit(rip_disp32(iat_loadlibraryex_rva))
    if break_after_load:
        emit(b"\xCC")                    # int3 (debugger stops here; DLL mapped)

    loop_rva = text_rva + len(code)
    emit(b"\xB9" + struct.pack("<I", INFINITE))  # mov ecx, INFINITE
    emit(b"\xFF\x15")                    # call [rip+Sleep]
    emit(rip_disp32(iat_sleep_rva))
    next_rva = text_rva + len(code) + 2  # size of the jmp rel8 that follows
    emit(b"\xEB" + struct.pack("<b", loop_rva - next_rva))  # jmp loop

    code_size = len(code)

    # ----- section sizes and file offsets -------------------------------- #
    text_raw = _align(code_size, FILE_ALIGNMENT)
    rdata_raw = _align(rdata_size, FILE_ALIGNMENT)

    size_of_headers = _align(0x40 + 4 + 20 + 240 + 2 * 40, FILE_ALIGNMENT)
    text_ptr = size_of_headers
    rdata_ptr = text_ptr + text_raw
    size_of_image = _align(rdata_rva + rdata_size, SECTION_ALIGNMENT)

    # ----- DOS header ---------------------------------------------------- #
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew -> NT headers

    # ----- COFF file header ---------------------------------------------- #
    file_header = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_AMD64,
        2,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        240,     # SizeOfOptionalHeader
        (IMAGE_FILE_EXECUTABLE_IMAGE
         | IMAGE_FILE_LARGE_ADDRESS_AWARE
         | IMAGE_FILE_RELOCS_STRIPPED),
    )

    # ----- optional header (PE32+) --------------------------------------- #
    opt = b""
    opt += struct.pack("<H", IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    opt += struct.pack("<BB", 14, 0)                 # linker version
    opt += struct.pack("<I", text_raw)               # SizeOfCode
    opt += struct.pack("<I", rdata_raw)              # SizeOfInitializedData
    opt += struct.pack("<I", 0)                      # SizeOfUninitializedData
    opt += struct.pack("<I", text_rva)               # AddressOfEntryPoint
    opt += struct.pack("<I", text_rva)               # BaseOfCode
    opt += struct.pack("<Q", IMAGE_BASE)             # ImageBase
    opt += struct.pack("<I", SECTION_ALIGNMENT)      # SectionAlignment
    opt += struct.pack("<I", FILE_ALIGNMENT)         # FileAlignment
    opt += struct.pack("<HH", 6, 0)                  # OS version
    opt += struct.pack("<HH", 0, 0)                  # image version
    opt += struct.pack("<HH", 6, 0)                  # subsystem version
    opt += struct.pack("<I", 0)                      # Win32VersionValue
    opt += struct.pack("<I", size_of_image)          # SizeOfImage
    opt += struct.pack("<I", size_of_headers)        # SizeOfHeaders
    opt += struct.pack("<I", 0)                      # CheckSum
    opt += struct.pack("<H", IMAGE_SUBSYSTEM_WINDOWS_CUI)
    opt += struct.pack("<H", IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    opt += struct.pack("<Q", 0x100000)               # SizeOfStackReserve
    opt += struct.pack("<Q", 0x1000)                 # SizeOfStackCommit
    opt += struct.pack("<Q", 0x100000)               # SizeOfHeapReserve
    opt += struct.pack("<Q", 0x1000)                 # SizeOfHeapCommit
    opt += struct.pack("<I", 0)                      # LoaderFlags
    opt += struct.pack("<I", IMAGE_NUMBEROF_DIRECTORY_ENTRIES)

    directories = [(0, 0)] * IMAGE_NUMBEROF_DIRECTORY_ENTRIES
    directories[IMAGE_DIRECTORY_ENTRY_IMPORT] = (to_rva(idt_off), 2 * 20)
    directories[IMAGE_DIRECTORY_ENTRY_IAT] = (to_rva(iat_off), (len(imports) + 1) * 8)
    for va, size in directories:
        opt += struct.pack("<II", va, size)

    assert len(opt) == 240, "optional header must be 240 bytes, got %d" % len(opt)

    # ----- section headers ----------------------------------------------- #
    def section_header(name, vsize, vaddr, raw_size, raw_ptr, characteristics):
        return struct.pack(
            "<8sIIIIIIHHI",
            name,
            vsize,
            vaddr,
            raw_size,
            raw_ptr,
            0,  # PointerToRelocations
            0,  # PointerToLinenumbers
            0,  # NumberOfRelocations
            0,  # NumberOfLinenumbers
            characteristics,
        )

    text_hdr = section_header(
        b".text", code_size, text_rva, text_raw, text_ptr,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )
    rdata_hdr = section_header(
        b".rdata", rdata_size, rdata_rva, rdata_raw, rdata_ptr,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    )

    # ----- assemble the image -------------------------------------------- #
    headers = bytearray(size_of_headers)
    headers[0:0x40] = dos
    pos = 0x40
    headers[pos:pos + 4] = b"PE\x00\x00"; pos += 4
    headers[pos:pos + 20] = file_header; pos += 20
    headers[pos:pos + 240] = opt; pos += 240
    headers[pos:pos + 40] = text_hdr; pos += 40
    headers[pos:pos + 40] = rdata_hdr; pos += 40

    text_section = bytearray(text_raw)
    text_section[0:code_size] = code
    rdata_section = bytearray(rdata_raw)
    rdata_section[0:rdata_size] = rdata

    return bytes(headers) + bytes(text_section) + bytes(rdata_section)


# --------------------------------------------------------------------------- #
# IDA integration
# --------------------------------------------------------------------------- #
def _unique_loader_path(dll_dir, dll_stem):
    """Return a collision-free ``<stem>_<random>.exe`` path in *dll_dir*."""
    for _ in range(64):
        candidate = os.path.join(
            dll_dir, "%s_%08d.exe" % (dll_stem, random.randint(0, 99999999))
        )
        if not os.path.exists(candidate):
            return candidate
    raise RuntimeError("Unable to allocate a unique loader file name.")


def _try_configure_debugger(loader_path):
    """Best-effort configuration of IDA's local Windows debugger.

    Every failure here is non-fatal; the manual steps still work.
    """
    try:
        ida_dbg.load_debugger("win32", False)
    except Exception as exc:  # noqa: BLE001 - diagnostic only
        print("%s Could not auto-select the debugger: %s" % (_LOG_TAG, exc))

    sdir = os.path.dirname(loader_path)
    attempts = (
        lambda: ida_dbg.set_process_options(loader_path, "", sdir, "", 0, 0),
        lambda: ida_dbg.set_process_options(loader_path, "", sdir),
    )
    for attempt in attempts:
        try:
            attempt()
            print("%s Debugger 'Application' set to the loader EXE." % _LOG_TAG)
            return True
        except Exception:
            continue
    print("%s Set the debugger 'Application' manually (see steps below)." % _LOG_TAG)
    return False


def generate_loader_for_current_dll(auto_configure_debugger=True,
                                    run_dllmain=True, break_after_load=True):
    """Generate a loader EXE for the DLL currently open in IDA.

    run_dllmain=False maps the DLL WITHOUT running DllMain (use when a normal
    load hangs); break_after_load emits an int3 right after the load. Returns
    the path to the generated executable, or ``None`` on failure.
    """
    dll_path = ida_nalt.get_input_file_path()
    if not dll_path or not os.path.isfile(dll_path):
        ida_kernwin.warning(
            "Could not resolve the input file path.\n"
            "Make sure the target DLL is loaded in IDA."
        )
        return None

    if not dll_path.lower().endswith(".dll"):
        print("%s Warning: input file does not have a .dll extension; "
              "continuing anyway." % _LOG_TAG)

    # warn if the input looks like a raw memory dump (reflective payloads)
    try:
        with open(dll_path, "rb") as fh:
            head = fh.read(0x1000)
        is_dump, why = _pe_looks_memory_aligned(head)
    except Exception:
        is_dump, why = (False, "")
    if is_dump:
        print("%s WARNING: '%s' looks like a raw memory image (%s)."
              % (_LOG_TAG, os.path.basename(dll_path), why))
        print("%s          LoadLibrary may fail or misbehave on a memory dump; "
              "realign it to file form or debug it under the original loader."
              % _LOG_TAG)

    dll_dir = os.path.dirname(dll_path)
    dll_stem = os.path.splitext(os.path.basename(dll_path))[0]
    loader_path = _unique_loader_path(dll_dir, dll_stem)

    pe_bytes = build_loader_pe(dll_path, run_dllmain=run_dllmain,
                               break_after_load=break_after_load)
    with open(loader_path, "wb") as handle:
        handle.write(pe_bytes)

    mode = ("normal (DllMain + TLS run)" if run_dllmain
            else "map-only (no DllMain, imports unresolved)")
    print("%s Target DLL : %s" % (_LOG_TAG, dll_path))
    print("%s Loader EXE : %s (%d bytes)" % (_LOG_TAG, loader_path, len(pe_bytes)))
    print("%s Mode       : %s%s" % (_LOG_TAG, mode,
                                    "; int3 after load" if break_after_load else ""))

    if auto_configure_debugger:
        _try_configure_debugger(loader_path)

    print("%s Next steps:" % _LOG_TAG)
    print("    1. Debugger > Select debugger > Local Windows debugger.")
    print("    2. Debugger > Process options... > Application = the loader EXE above.")
    print("    3. Enable 'Suspend on library load/unload' to break when the DLL maps.")
    print("    4. Start debugging and set a breakpoint on the DLL entry point (OEP).")
    print("    5. If the stub HANGS, DllMain is blocking - regenerate with")
    print("       generate_safe_loader_for_current_dll() to map without DllMain.")
    return loader_path


def generate_safe_loader_for_current_dll(auto_configure_debugger=True):
    """Loader that MAPS the DLL without running DllMain (for samples whose
    DllMain hangs). Breaks right after the load so you can set breakpoints and
    drive DllMain / an export yourself."""
    return generate_loader_for_current_dll(
        auto_configure_debugger=auto_configure_debugger,
        run_dllmain=False, break_after_load=True)


def main():
    if _IN_IDA:
        generate_loader_for_current_dll()
        return

    import sys

    if len(sys.argv) not in (3, 4):
        print("Run inside IDA, or for self-testing:")
        print("    python %s <dll_path> <output_exe> [safe]"
              % os.path.basename(__file__))
        sys.exit(2)

    target = os.path.abspath(sys.argv[1])
    output = sys.argv[2]
    run_dllmain = not (len(sys.argv) == 4 and sys.argv[3].lower() == "safe")
    with open(output, "wb") as handle:
        handle.write(build_loader_pe(target, run_dllmain=run_dllmain,
                                     break_after_load=not run_dllmain))
    print("Wrote loader: %s (%s)"
          % (output, "normal" if run_dllmain else "map-only"))


if __name__ == "__main__":
    main()
