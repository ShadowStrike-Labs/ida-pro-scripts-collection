# ============================================================================
#  blob_dumper.py  -  IDAPython: carve Windows binary containers out of memory
# ----------------------------------------------------------------------------
#  Primary target is the Portable Executable: pointed at any address whose
#  first bytes are the MZ signature (4D 5A ...) - a decrypted/unpacked payload
#  in the debugger, a PE embedded in a data blob, a manually-mapped module -
#  the tool will:
#
#     1. Parse the DOS + PE + optional headers straight out of memory.
#     2. Work out how big the thing is *by itself*:
#          - SizeOfImage from the optional header (a mapped image), or
#          - max(PointerToRawData + SizeOfRawData) across the section table
#            (a raw on-disk image sitting in memory).
#        If SizeOfImage looks insane it is recomputed from the section table.
#     3. Read the whole region (chunked + gap-tolerant; unreadable bytes are
#        zero-filled and counted, so a stray unmapped page never aborts a dump).
#     4. Rebuild the section table when dumping a mapped image so the file is
#        openable on disk (PointerToRawData <- VirtualAddress, SizeOfRawData <-
#        aligned VirtualSize).  "raw" mode writes bytes verbatim instead.
#     5. Pick the extension from the headers (.dll / .sys / .exe) and drop the
#        file NEXT TO the analyzed input file (falling back to the IDB folder).
#        Managed assemblies (.NET) are detected via the CLI header (data
#        directory 14) and labelled as ".NET" in the report; the file keeps
#        its native .dll/.exe extension.
#
#  6. OPTIONALLY rebuild the import table (fix_imports=True) - the pe-sieve
#     /imp equivalent: resolve every IAT slot against the modules mapped in the
#     live debug session, synthesize a fresh import directory and append it as a
#     new section.  Without this the dump is already perfect for static RE; with
#     it the file is meant to load.  (Scylla / pe-sieve remain fine too.)
#
#  Beyond PE, the tool also carves non-PE containers commonly found embedded
#  in Windows binaries, memory dumps and shellcode blobs. For each format the
#  size is derived from the stream itself (no out-of-band guessing):
#     ZIP (via EOCD),  7z (SignatureHeader),  gzip (DEFLATE stream),
#     PDF (last %%EOF),  PNG (IEND),  BMP (bfSize + strict DIB check),
#     CAB (cbCabinet),  RAR4 (block walk to ENDARC_HEAD).
#  RAR5 is signature-detected; its size requires manual input (size=N).
#
#  COMMANDS (from the IDAPython console)
#    PE path:
#      dump_pe()                dump the PE at the cursor (auto layout detect)
#      dump_pe(0x140000000)     dump the PE at an explicit base
#      dump_pe(ea, mode="raw")  force raw/on-disk layout (no section fixups)
#      dump_pe(ea, mode="virtual")   force mapped->file reconstruction
#      dump_pe(ea, ext=".sys")  force the output extension
#      dump_pe_prompt()         ask for the address in a dialog (hex)
#      scan_for_pe()            list every MZ/PE candidate in the address space
#      dump_all_pe()            dump every candidate scan_for_pe() finds
#      pe_info(ea)              print the header summary only, dump nothing
#      save_region(ea, size)    raw blob dump of `size` bytes (no PE parsing)
#      dump_pe(ea, fix_imports=True)  dump + rebuild imports (needs a debugger)
#      list_imports(ea)         resolve + print the IAT, write nothing
#      rebuild_imports_in_file(path)  add imports to an already-dumped file
#
#    non-PE containers:
#      blob_info(ea)            identify + size-probe the container at ea
#      dump_blob(ea)            carve the container at ea (auto-detect kind)
#      dump_blob(ea, kind=..., size=N)   force kind / override size
#      scan_for_blobs()         scan every segment + overlay for every format
#      dump_all_blobs()         scan + carve every finding (seg + file-space)
#      scan_for_zip() / scan_for_7z() / scan_for_gzip() / scan_for_pdf() /
#      scan_for_png() / scan_for_bmp() / scan_for_cab() / scan_for_rar()
#      list_blob_kinds()        print the supported formats
#
#    overlay / off-image (bytes NOT loaded as IDA segments):
#      The scanners above also walk the input file's overlay (bytes past the
#      last section on disk) and any inter-section gaps, so appended droppers,
#      SFX wrappers and signed-binary overlays are found. Findings carry a
#      source tag:
#          scan_for_pe()    -> [(source, locator), ...]
#          scan_for_blobs() -> [(source, locator, kind, ext, size, detail), ...]
#        source="seg"  -> locator is an EA (use dump_pe/dump_blob)
#        source="file" -> locator is a byte offset in the input file; carve
#                         with dump_pe_from_file(offset) or
#                         dump_blob_from_file(offset[, kind=..., size=N])
#      dump_all_pe() and dump_all_blobs() dispatch automatically.
#
#  HOTKEY:  Ctrl-Alt-D  ->  dump_pe() at the current cursor.
#
#  Verified API: ida_bytes.get_bytes(ea, size) reads the *current* view (live
#  memory while debugging, DB bytes otherwise); ida_nalt.get_input_file_path()
#  / idc.get_idb_path() give the output folder; ida_kernwin.ask_str for input.
# ============================================================================

import os
import struct
import warnings

import ida_bytes
import ida_kernwin
import ida_nalt
import ida_segment
import idc

try:
    import idaapi
    BADADDR = idaapi.BADADDR
except Exception:                       # pragma: no cover - IDA always has this
    BADADDR = 0xFFFFFFFFFFFFFFFF

# ------------------------------- customization ------------------------------
DEFAULT_MODE      = "auto"     # "auto" | "virtual" | "raw"  (see header)
FIX_SECTION_TABLE = True       # in virtual mode, repoint sections to their VAs
OPEN_FOLDER_AFTER = False       # pop the output folder in Explorer when done
MAX_SANE_IMAGE    = 0x10000000 # 256 MB: above this SizeOfImage is distrusted
SCAN_STEP         = 0x1000     # granularity for scan_for_pe() within a segment
VERBOSE           = True       # echo the header report to the output window

# ---- import reconstruction (the pe-sieve /imp equivalent) ----
FIX_IMPORTS       = False      # rebuild the import table after dumping; needs a
                               # live debug session (module exports must be read)
IMPORT_SECTION    = ".krew"    # name of the appended import-directory section
MIN_IAT_RUN       = 2          # blind IAT scan: ignore pointer runs shorter than
                               # this (raise it if you see false positives)
# ----------------------------------------------------------------------------

# ---- PE / COFF constants ----
_MZ = b"MZ"
_PE_SIG = 0x00004550                      # "PE\0\0"
MAGIC_PE32 = 0x10B
MAGIC_PE32PLUS = 0x20B

IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_SYSTEM = 0x1000                # rarely set, but honored if present
IMAGE_SUBSYSTEM_NATIVE = 1                # drivers (.sys) live here

_MACHINES = {
    0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64",
    0x01C0: "ARM", 0x01C4: "ARMNT", 0x0200: "IA64", 0x5032: "RISCV32",
    0x5064: "RISCV64",
}
_SUBSYSTEMS = {
    0: "unknown", 1: "native", 2: "windows_gui", 3: "windows_cui",
    5: "os2_cui", 7: "posix_cui", 9: "windows_ce_gui", 10: "efi_application",
    11: "efi_boot_service_driver", 12: "efi_runtime_driver", 13: "efi_rom",
    14: "xbox", 16: "windows_boot_application",
}

_SCN_CODE = 0x00000020
_SCN_EXEC = 0x20000000
_SCN_READ = 0x40000000
_SCN_WRITE = 0x80000000
_SCN_INIT_DATA = 0x00000040

# data-directory indices (IMAGE_DIRECTORY_ENTRY_*)
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_BOUND = 11
DIR_IAT = 12
DIR_COM_DESCRIPTOR = 14          # CLI header: non-zero -> .NET assembly

_ORD_FLAG64 = 0x8000000000000000
_ORD_FLAG32 = 0x80000000

_TAG = "[blob_dumper]"


# ----------------------------------------------------------------------------
# low-level helpers
# ----------------------------------------------------------------------------
def _log(msg):
    if VERBOSE:
        print("%s %s" % (_TAG, msg))


def _align_up(value, alignment):
    if alignment <= 0:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def _read_region(ea, size):
    """Read `size` bytes starting at `ea`, tolerating unreadable pages.

    Returns (bytearray, missing_byte_count).  Unreadable bytes are left as 0.
    A binary-split keeps a large unmapped hole from degrading into a per-byte
    crawl: readable spans come back whole, only the hole is zero-filled.
    """
    data = bytearray(size)
    missing = [0]

    def rec(off, n):
        if n <= 0:
            return
        chunk = ida_bytes.get_bytes(ea + off, n)
        if chunk is not None and len(chunk) == n:
            data[off:off + n] = chunk
            return
        if n == 1:
            missing[0] += 1
            return
        half = n // 2
        rec(off, half)
        rec(off + half, n - half)

    rec(0, size)
    return data, missing[0]


def _u16(buf, off):
    if off + 2 > len(buf):
        return 0
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    if off + 4 > len(buf):
        return 0
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    if off + 8 > len(buf):
        return 0
    return struct.unpack_from("<Q", buf, off)[0]


def _probe_nonzero(ea, length):
    """Count non-zero bytes in a short window (for layout auto-detection)."""
    b = ida_bytes.get_bytes(ea, length)
    if not b:
        return 0
    return sum(1 for x in bytearray(b) if x)


# ----------------------------------------------------------------------------
# header parsing
# ----------------------------------------------------------------------------
class PEHeader(object):
    """Everything we need out of the DOS/PE/optional headers + section table."""

    def __init__(self):
        self.base = 0
        self.is_64 = False
        self.magic = 0
        self.machine = 0
        self.machine_name = "?"
        self.num_sections = 0
        self.characteristics = 0
        self.subsystem = 0
        self.subsystem_name = "?"
        self.entry_rva = 0
        self.image_base = 0
        self.section_alignment = 0x1000
        self.file_alignment = 0x200
        self.size_of_image = 0
        self.size_of_headers = 0
        self.opt_header_size = 0
        self.sectbl_off = 0                # file/RVA offset of the section table
        self.pe_off = 0                    # e_lfanew
        self.coff_off = 0                  # start of the COFF file header
        self.opt_off = 0                   # start of the optional header
        self.dd_off = 0                    # start of the data-directory array
        self.num_rva = 0                   # NumberOfRvaAndSizes
        self.is_dotnet = False             # CLI header present (COM descriptor)
        self.sections = []                 # list of dicts

    @property
    def is_dll(self):
        return bool(self.characteristics & IMAGE_FILE_DLL)

    @property
    def is_driver(self):
        # Native subsystem is the reliable driver tell; the SYSTEM file flag is
        # a weaker secondary signal that some drivers also carry.
        return (self.subsystem == IMAGE_SUBSYSTEM_NATIVE
                or bool(self.characteristics & IMAGE_FILE_SYSTEM))

    def default_ext(self):
        if self.is_driver:
            return ".sys"
        if self.is_dll:
            return ".dll"
        return ".exe"

    def raw_extent(self):
        """Largest PointerToRawData + SizeOfRawData across sections."""
        end = self.size_of_headers
        for s in self.sections:
            if s["praw"] and s["srawsize"]:
                end = max(end, s["praw"] + s["srawsize"])
        return end

    def computed_image_size(self):
        """SizeOfImage recomputed from the section table (fallback)."""
        end = _align_up(self.size_of_headers, self.section_alignment)
        for s in self.sections:
            span = max(s["vsize"], s["srawsize"])
            end = max(end, _align_up(s["va"] + span, self.section_alignment))
        return end


def _default_mem(ea, size):
    """Default byte reader: the live IDA view at `ea` (zero-filled if unmapped)."""
    data, _ = _read_region(ea, size)
    return bytes(data)


def parse_pe_header(base, mem=None):
    """Parse the PE at `base`. Returns PEHeader or None.

    `mem(ea, size) -> bytes` overrides how bytes are fetched (defaults to the
    live IDA view). Pass a buffer-backed reader with base=0 to parse a PE that
    already lives in a Python bytes object (e.g. a dumped file on disk).
    """
    mem = mem or _default_mem
    # DOS header: just enough to find e_lfanew.
    dos = mem(base, 0x40)
    if bytes(dos[:2]) != _MZ:
        _log("no MZ at %X (found %02X %02X)" % (base, dos[0], dos[1]))
        return None
    e_lfanew = _u32(dos, 0x3C)
    if e_lfanew == 0 or e_lfanew > 0x10000000:
        _log("bogus e_lfanew (%#x) at %X" % (e_lfanew, base))
        return None

    # Read a header window big enough for DOS stub + PE + optional + sections.
    # 0x400 covers the fixed part; extend once section count is known.
    window = _align_up(e_lfanew + 0x400, 0x400)
    hdr = mem(base, window)

    if _u32(hdr, e_lfanew) != _PE_SIG:
        _log("no PE signature at %X+%#x" % (base, e_lfanew))
        return None

    coff = e_lfanew + 4
    pe = PEHeader()
    pe.base = base
    pe.machine = _u16(hdr, coff + 0)
    pe.machine_name = _MACHINES.get(pe.machine, "0x%X" % pe.machine)
    pe.num_sections = _u16(hdr, coff + 2)
    pe.opt_header_size = _u16(hdr, coff + 16)
    pe.characteristics = _u16(hdr, coff + 18)

    if pe.num_sections == 0 or pe.num_sections > 96:
        _log("suspicious NumberOfSections=%d at %X" % (pe.num_sections, base))
        # keep going: some hand-built PEs are odd; we clamp reads later.

    opt = coff + 20
    pe.magic = _u16(hdr, opt + 0)
    pe.is_64 = (pe.magic == MAGIC_PE32PLUS)
    pe.entry_rva = _u32(hdr, opt + 16)
    # SectionAlignment/FileAlignment/SizeOfImage/SizeOfHeaders/Subsystem sit at
    # the SAME optional-header offsets for PE32 and PE32+ (the ImageBase/
    # BaseOfData divergence realigns by +32).
    pe.section_alignment = _u32(hdr, opt + 32) or 0x1000
    pe.file_alignment = _u32(hdr, opt + 36) or 0x200
    pe.size_of_image = _u32(hdr, opt + 56)
    pe.size_of_headers = _u32(hdr, opt + 60)
    pe.subsystem = _u16(hdr, opt + 68)
    pe.subsystem_name = _SUBSYSTEMS.get(pe.subsystem, "0x%X" % pe.subsystem)
    pe.image_base = _u64(hdr, opt + 24) if pe.is_64 else _u32(hdr, opt + 28)

    # offsets reused when rewriting headers (import fix / section append)
    pe.pe_off = e_lfanew
    pe.coff_off = coff
    pe.opt_off = opt
    pe.dd_off = opt + (112 if pe.is_64 else 96)
    pe.num_rva = _u32(hdr, (opt + 108) if pe.is_64 else (opt + 92))

    # .NET: non-zero CLI header data directory indicates a managed assembly.
    if pe.num_rva > DIR_COM_DESCRIPTOR:
        com_rva = _u32(hdr, pe.dd_off + DIR_COM_DESCRIPTOR * 8)
        com_size = _u32(hdr, pe.dd_off + DIR_COM_DESCRIPTOR * 8 + 4)
        pe.is_dotnet = bool(com_rva) and bool(com_size)

    # Section table follows the optional header (robust: don't assume by magic).
    pe.sectbl_off = coff + 20 + pe.opt_header_size
    need = pe.sectbl_off + pe.num_sections * 40
    if need > len(hdr):
        hdr = mem(base, _align_up(need, 0x400))

    for i in range(pe.num_sections):
        so = pe.sectbl_off + i * 40
        if so + 40 > len(hdr):
            break
        name = bytes(hdr[so:so + 8]).rstrip(b"\x00")
        try:
            name = name.decode("latin-1")
        except Exception:
            name = repr(name)
        pe.sections.append({
            "index": i,
            "name": name,
            "vsize": _u32(hdr, so + 8),
            "va": _u32(hdr, so + 12),
            "srawsize": _u32(hdr, so + 16),
            "praw": _u32(hdr, so + 20),
            "chars": _u32(hdr, so + 36),
            "hdr_off": so,              # offset of this section header in the image
        })
    return pe


# ----------------------------------------------------------------------------
# layout detection
# ----------------------------------------------------------------------------
def _detect_layout(pe):
    """Decide 'virtual' (mapped image) vs 'raw' (on-disk image in memory).

    Transparent heuristic - the decision and its evidence are always logged.
    """
    meaningful = [s for s in pe.sections
                  if s["vsize"] > 0 and s["va"] >= pe.size_of_headers
                  and s["praw"] and s["praw"] != s["va"]]
    if not meaningful:
        return "virtual", "raw pointers equal VAs (or no measurable section)"

    va_score = raw_score = 0
    for s in meaningful:
        n = min(0x80, s["vsize"])
        mid = s["vsize"] // 3
        va_hit = _probe_nonzero(pe.base + s["va"] + mid, n)
        raw_hit = _probe_nonzero(pe.base + s["praw"] + mid, n)
        if va_hit > raw_hit:
            va_score += 1
        elif raw_hit > va_hit:
            raw_score += 1
    why = "probe VA=%d raw=%d over %d section(s)" % (va_score, raw_score, len(meaningful))
    if raw_score > va_score:
        return "raw", why
    return "virtual", why


# ----------------------------------------------------------------------------
# output path
# ----------------------------------------------------------------------------
def _output_dir():
    inp = ida_nalt.get_input_file_path() or ""
    d = os.path.dirname(inp)
    if d and os.path.isdir(d):
        return d, inp
    idb = idc.get_idb_path() or ""
    d = os.path.dirname(idb)
    if d and os.path.isdir(d):
        return d, (inp or idb)
    return os.getcwd(), (inp or idb)


def _unique_path(path):
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    for i in range(1, 1000):
        cand = "%s_%d%s" % (root, i, ext)
        if not os.path.exists(cand):
            return cand
    return path


def _build_output_path(pe, ext):
    out_dir, src = _output_dir()
    stem = os.path.splitext(os.path.basename(src or "dump"))[0] or "dump"
    name = "%s_dumped_%X%s" % (stem, pe.base, ext)
    return _unique_path(os.path.join(out_dir, name))


# ----------------------------------------------------------------------------
# file-space helpers  (bytes NOT mapped as IDA segments)
# ----------------------------------------------------------------------------
#  When IDA loads a PE, only its sections become segments. The overlay (bytes
#  past the last section's PointerToRawData + SizeOfRawData on disk) is not
#  mapped and ida_bytes.get_bytes cannot see it, so the segment-only scanners
#  miss PEs and archives appended there - a common installer / dropper / SFX
#  layout. The helpers below read the input file from disk and expose the
#  portions NOT covered by any loaded section (overlay + inter-section gaps),
#  so the scanners can walk the uncovered bytes alongside the live view.
# ----------------------------------------------------------------------------
_FILE_CACHE = {"path": None, "data": None}


def _input_file_bytes():
    """Return (bytes, path) for the current IDA input file (cached by path).
    Returns (None, None) when the input is unavailable (no path, remote-only
    load, deleted, unreadable, etc.)."""
    try:
        path = ida_nalt.get_input_file_path()
    except Exception:
        return None, None
    if not path or not os.path.isfile(path):
        return None, None
    if _FILE_CACHE["path"] != path or _FILE_CACHE["data"] is None:
        try:
            with open(path, "rb") as fh:
                _FILE_CACHE["data"] = fh.read()
                _FILE_CACHE["path"] = path
        except Exception as e:
            _log("could not read input file %s: %s" % (path, e))
            _FILE_CACHE["data"] = None
            _FILE_CACHE["path"] = None
    return _FILE_CACHE["data"], _FILE_CACHE["path"]


def _file_reader(data):
    """Build a reader(offset, n) -> bytes over `data`. The offset argument is
    treated as an absolute offset into `data` so parse_pe_header(base=offset,
    mem=reader) parses an embedded PE at that offset correctly."""
    def _r(offset, n):
        if offset is None or offset < 0 or offset >= len(data):
            return b""
        return bytes(data[offset:offset + n])
    return _r


def _pe_section_covered_ranges(data):
    """Return the file-offset ranges a loaded PE's headers + sections occupy
    on disk. For a non-PE or malformed PE input, returns []. Used by
    _pe_overlay_ranges to compute the complement (uncovered bytes)."""
    if len(data) < 0x40 or data[:2] != _MZ:
        return []
    e_lfanew = _u32(data, 0x3C)
    if e_lfanew + 24 > len(data) or _u32(data, e_lfanew) != _PE_SIG:
        return []
    coff = e_lfanew + 4
    num_sec = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    size_of_headers = _u32(data, opt + 60)
    ranges = []
    if 0 < size_of_headers <= len(data):
        ranges.append((0, size_of_headers))
    sec_tbl = coff + 20 + opt_size
    for i in range(min(num_sec, 96)):
        so = sec_tbl + i * 40
        if so + 40 > len(data):
            break
        praw = _u32(data, so + 20)
        rsize = _u32(data, so + 16)
        if praw and rsize:
            end = min(praw + rsize, len(data))
            ranges.append((praw, end))
    return ranges


def _pe_overlay_ranges(data):
    """Return the file-offset ranges NOT covered by loaded PE sections, as
    [(offset, length), ...]. For a non-PE input the whole file is one range.
    Primary use: scanning the overlay + inter-section gaps for embeds."""
    covered = _pe_section_covered_ranges(data)
    if not covered:
        return [(0, len(data))]
    covered.sort()
    merged = []
    for s, e in covered:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append([s, e])
    gaps = []
    cursor = 0
    for s, e in merged:
        if cursor < s:
            gaps.append((cursor, s - cursor))
        cursor = max(cursor, e)
    if cursor < len(data):
        gaps.append((cursor, len(data) - cursor))
    return gaps


def _build_blob_output_path_file(offset, kind, ext):
    out_dir, src = _output_dir()
    stem = os.path.splitext(os.path.basename(src or "dump"))[0] or "dump"
    name = "%s_overlay_%X_%s%s" % (stem, offset, kind, ext)
    return _unique_path(os.path.join(out_dir, name))


# ----------------------------------------------------------------------------
# section-table rebuild (virtual -> file)
# ----------------------------------------------------------------------------
def _rebuild_sections(image, pe):
    """Repoint each section header so the mapped image is valid on disk:
    PointerToRawData <- VirtualAddress, SizeOfRawData <- aligned VirtualSize."""
    changed = 0
    size = len(image)
    for s in pe.sections:
        if s["va"] == 0 and s["vsize"] == 0:
            continue
        eff = s["vsize"] if s["vsize"] else s["srawsize"]
        new_praw = s["va"]
        new_rsize = _align_up(eff, pe.file_alignment)
        if new_praw + new_rsize > size:                 # clamp to what we read
            new_rsize = max(0, size - new_praw)
        so = s["hdr_off"]
        if so + 40 <= size:
            struct.pack_into("<I", image, so + 16, new_rsize & 0xFFFFFFFF)
            struct.pack_into("<I", image, so + 20, new_praw & 0xFFFFFFFF)
            changed += 1
    _log("rebuilt %d section header(s) for on-disk layout" % changed)
    return changed


# ----------------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------------
def _fmt_chars(c):
    flags = []
    if c & _SCN_CODE:
        flags.append("CODE")
    if c & _SCN_READ:
        flags.append("R")
    if c & _SCN_WRITE:
        flags.append("W")
    if c & _SCN_EXEC:
        flags.append("X")
    return "".join(f if f in ("R", "W", "X") else f + " " for f in flags) or "-"


def print_report(pe, chosen_mode=None):
    kind = pe.default_ext()[1:].upper()
    tag = ".NET assembly" if pe.is_dotnet else kind
    print("%s ---- PE @ %X ----" % (_TAG, pe.base))
    print("%s   arch=%s  magic=%s  type=%s  subsystem=%s"
          % (_TAG, pe.machine_name,
             "PE32+" if pe.is_64 else "PE32", tag, pe.subsystem_name))
    print("%s   ImageBase=%X  EntryRVA=%X  ->  EP@VA %X"
          % (_TAG, pe.image_base, pe.entry_rva, pe.base + pe.entry_rva))
    print("%s   SizeOfImage=%#x  SizeOfHeaders=%#x  SectAlign=%#x  FileAlign=%#x"
          % (_TAG, pe.size_of_image, pe.size_of_headers,
             pe.section_alignment, pe.file_alignment))
    if chosen_mode:
        print("%s   dump mode = %s" % (_TAG, chosen_mode))
    print("%s   %-8s %-10s %-10s %-10s %-10s %s"
          % (_TAG, "name", "VirtAddr", "VirtSize", "RawPtr", "RawSize", "flags"))
    for s in pe.sections:
        print("%s   %-8s %-10X %-10X %-10X %-10X %s"
              % (_TAG, s["name"][:8], s["va"], s["vsize"],
                 s["praw"], s["srawsize"], _fmt_chars(s["chars"])))


# ----------------------------------------------------------------------------
# import reconstruction  (the pe-sieve /imp equivalent)
# ----------------------------------------------------------------------------
#  A memory dump's IAT holds *resolved* pointers - the real VAs of the imported
#  APIs. To make the file loadable again we, for each IAT slot, work out which
#  module + export it points at, then synthesize a fresh import directory
#  (descriptors + INT/ILT + hint-name table + DLL name strings) and append it as
#  a new section, repointing the data directory at it. FirstThunk is left aimed
#  at the ORIGINAL IAT so existing call sites keep working; the Windows loader
#  refills those slots from the names we rebuilt.
#
#  This needs a live debug session so the dependent modules are mapped and their
#  export tables are readable. Statically it will simply find nothing to do.
# ----------------------------------------------------------------------------
def _img_ptr(image, rva, ptrsize):
    if rva < 0 or rva + ptrsize > len(image):
        return None
    if ptrsize == 8:
        return struct.unpack_from("<Q", image, rva)[0]
    return struct.unpack_from("<I", image, rva)[0]


def _c_string(mem, ea, limit=512):
    out = bytearray()
    got = 0
    while got < limit:
        chunk = mem(ea + got, 32)
        if not chunk:
            break
        for ch in bytearray(chunk):
            if ch == 0:
                return out.decode("latin-1", "replace")
            out.append(ch)
        got += 32
    return out.decode("latin-1", "replace")


def _short_dll(name):
    return os.path.basename(name or "") or (name or "?")


def _enumerate_modules():
    """List loaded modules (base/size/name). Meaningful during debugging."""
    mods = []
    try:
        import idautils
        for m in idautils.Modules():
            mods.append({"name": m.name, "base": m.base, "size": m.size})
    except Exception as e:
        _log("module enumeration failed: %s" % e)
    return mods


def _build_export_index(mod, mem):
    """VA -> (export_name or None, ordinal) for one loaded module."""
    base = mod["base"]
    dos = mem(base, 0x40)
    if not dos or dos[:2] != _MZ:
        return {}
    e = _u32(dos, 0x3C)
    hdr = mem(base, e + 0x108)
    if not hdr or _u32(hdr, e) != _PE_SIG:
        return {}
    opt = e + 24
    is64 = _u16(hdr, opt) == MAGIC_PE32PLUS
    dd = opt + (112 if is64 else 96)
    exp_rva = _u32(hdr, dd + DIR_EXPORT * 8)
    exp_size = _u32(hdr, dd + DIR_EXPORT * 8 + 4)
    if not exp_rva:
        return {}
    ed = mem(base + exp_rva, 40)
    if not ed or len(ed) < 40:
        return {}
    ord_base = _u32(ed, 16)
    nfun = _u32(ed, 20)
    nnam = _u32(ed, 24)
    a_fun = _u32(ed, 28)
    a_nam = _u32(ed, 32)
    a_ord = _u32(ed, 36)
    if nfun == 0 or nfun > 0x20000:
        return {}
    eat = mem(base + a_fun, nfun * 4) or b""
    names = (mem(base + a_nam, nnam * 4) if a_nam else b"") or b""
    ords = (mem(base + a_ord, nnam * 2) if a_ord else b"") or b""
    idx_name = {}
    for i in range(nnam):
        if (i + 1) * 4 > len(names) or (i + 1) * 2 > len(ords):
            break
        idx_name[_u16(ords, i * 2)] = _c_string(mem, base + _u32(names, i * 4))
    lo, hi = base + exp_rva, base + exp_rva + exp_size
    out = {}
    for i in range(nfun):
        if (i + 1) * 4 > len(eat):
            break
        frva = _u32(eat, i * 4)
        if not frva:
            continue
        va = base + frva
        if lo <= va < hi:                   # forwarder string -> skip
            continue
        out[va] = (idx_name.get(i), ord_base + i)
    return out


def _module_index(modules, mem):
    idx = []
    for m in modules:
        idx.append((m["base"], m["base"] + int(m.get("size", 0) or 0),
                    _short_dll(m["name"]), _build_export_index(m, mem)))
    return idx


def _resolve_ptr(ptr, idx):
    for (b, e, name, emap) in idx:
        if b <= ptr < e:
            hit = emap.get(ptr)
            if hit:
                return (name, hit[0], hit[1])
            return (name, None, None)       # inside a module, export unknown
    return None


def _discover_iat_groups(image, pe, idx, iat_rva=None, iat_size=None,
                         min_run=None):
    """Locate IAT slots and split them into per-DLL descriptor groups.

    Returns (groups, ptrsize). Each group is:
      {"dll", "first_thunk_rva", "entries": [(name_or_None, ordinal), ...]}
    A group is broken whenever the DLL changes or the slots stop being
    contiguous, so each maps cleanly onto one IMAGE_IMPORT_DESCRIPTOR.
    """
    ps = 8 if pe.is_64 else 4
    min_run = MIN_IAT_RUN if min_run is None else min_run
    groups = []

    def flush(run):
        cur = None
        nxt = None
        for (rva, res) in run:
            dll = res[0]
            if cur is None or dll != cur["dll"] or rva != nxt:
                cur = {"dll": dll, "first_thunk_rva": rva, "entries": []}
                groups.append(cur)
            cur["entries"].append((res[1], res[2]))
            nxt = rva + ps

    if iat_rva is not None:
        count = (iat_size // ps) if iat_size else 8192
        run = []
        for k in range(count):
            ptr = _img_ptr(image, iat_rva + k * ps, ps)
            res = _resolve_ptr(ptr, idx) if ptr else None
            if res:
                run.append((iat_rva + k * ps, res))
            elif not iat_size:              # unbounded: stop at the first gap
                break
        flush(run)
    else:
        run = []
        rva = pe.size_of_headers & ~(ps - 1)
        last = len(image) - ps
        while rva <= last:
            ptr = _img_ptr(image, rva, ps)
            res = _resolve_ptr(ptr, idx) if ptr else None
            if res:
                run.append((rva, res))
            else:
                if len(run) >= min_run:
                    flush(run)
                run = []
            rva += ps
        if len(run) >= min_run:
            flush(run)
    return groups, ps


def _build_import_blob(new_rva, groups, ps):
    """Serialize descriptors + ILTs + hint/name + DLL-names starting at new_rva.
    Returns (blob, idt_size, (iat_rva, iat_size))."""
    ord_flag = _ORD_FLAG64 if ps == 8 else _ORD_FLAG32
    n = len(groups)
    idt_size = (n + 1) * 20
    cursor = idt_size

    ilt_off = []
    for g in groups:
        ilt_off.append(cursor)
        cursor += (len(g["entries"]) + 1) * ps

    hn_off = {}
    for gi, g in enumerate(groups):
        for ei, (nm, ordv) in enumerate(g["entries"]):
            if nm is None:
                continue
            hn_off[(gi, ei)] = cursor
            blob = struct.pack("<H", 0) + nm.encode("latin-1", "replace") + b"\x00"
            if len(blob) & 1:
                blob += b"\x00"
            cursor += len(blob)

    dll_off = []
    for g in groups:
        dll_off.append(cursor)
        nm = g["dll"].encode("latin-1", "replace") + b"\x00"
        if len(nm) & 1:
            nm += b"\x00"
        cursor += len(nm)

    buf = bytearray(cursor)
    iat_lo = min(g["first_thunk_rva"] for g in groups)
    iat_hi = max(g["first_thunk_rva"] + len(g["entries"]) * ps for g in groups)

    for gi, g in enumerate(groups):
        struct.pack_into("<IIIII", buf, gi * 20,
                         new_rva + ilt_off[gi],      # OriginalFirstThunk (ILT)
                         0, 0,
                         new_rva + dll_off[gi],       # Name
                         g["first_thunk_rva"])        # FirstThunk (original IAT)

    for gi, g in enumerate(groups):
        base_off = ilt_off[gi]
        for ei, (nm, ordv) in enumerate(g["entries"]):
            if nm is None:
                val = ord_flag | (ordv & 0xFFFF)
            else:
                val = new_rva + hn_off[(gi, ei)]
            if ps == 8:
                struct.pack_into("<Q", buf, base_off + ei * ps, val)
            else:
                struct.pack_into("<I", buf, base_off + ei * ps, val & 0xFFFFFFFF)

    for gi, g in enumerate(groups):
        for ei, (nm, ordv) in enumerate(g["entries"]):
            if nm is None:
                continue
            o = hn_off[(gi, ei)]
            enc = nm.encode("latin-1", "replace")
            buf[o:o + 2 + len(enc) + 1] = struct.pack("<H", 0) + enc + b"\x00"

    for gi, g in enumerate(groups):
        o = dll_off[gi]
        enc = g["dll"].encode("latin-1", "replace") + b"\x00"
        buf[o:o + len(enc)] = enc

    return buf, idt_size, (iat_lo, iat_hi - iat_lo)


def _set_dir(image, pe, index, rva, size):
    off = pe.dd_off + index * 8
    if index < pe.num_rva and off + 8 <= len(image):
        struct.pack_into("<II", image, off, rva & 0xFFFFFFFF, size & 0xFFFFFFFF)
        return True
    return False


def _apply_import_section(image, pe, blob, new_rva, idt_size, iat_dir,
                          section_name):
    """Append `blob` as a new section and repoint the import/IAT directories."""
    file_align = pe.file_alignment or 0x200
    sec_align = pe.section_alignment or 0x1000

    raw_ptr = _align_up(len(image), file_align)
    if len(image) < raw_ptr:
        image += b"\x00" * (raw_ptr - len(image))
    raw_size = _align_up(len(blob), file_align)
    image += bytes(blob) + b"\x00" * (raw_size - len(blob))
    vsize = len(blob)

    # room for one more 40-byte section header inside the header area?
    new_sh = pe.sectbl_off + pe.num_sections * 40
    if new_sh + 40 > pe.size_of_headers:
        return None, ("no room for a new section header (SizeOfHeaders=%#x)"
                      % pe.size_of_headers)
    if new_sh + 40 > len(image):
        return None, "header area not present in the dump"

    name = section_name.encode("latin-1", "replace")[:8].ljust(8, b"\x00")
    chars = _SCN_INIT_DATA | _SCN_READ | _SCN_WRITE
    struct.pack_into("<8sIIIIIIHHI", image, new_sh,
                     name, vsize, new_rva, raw_size, raw_ptr,
                     0, 0, 0, 0, chars)

    struct.pack_into("<H", image, pe.coff_off + 2, (pe.num_sections + 1) & 0xFFFF)
    struct.pack_into("<I", image, pe.opt_off + 56,
                     _align_up(new_rva + vsize, sec_align) & 0xFFFFFFFF)

    _set_dir(image, pe, DIR_IMPORT, new_rva, idt_size)
    _set_dir(image, pe, DIR_IAT, iat_dir[0], iat_dir[1])
    _set_dir(image, pe, DIR_BOUND, 0, 0)     # kill any stale bound-import dir
    return image, None


def rebuild_imports_for_image(image, pe, modules, mem, iat_rva=None,
                              iat_size=None, section_name=None):
    """Core, IDA-independent import rebuild. Returns (image_bytearray, report)."""
    section_name = section_name or IMPORT_SECTION
    image = bytearray(image)
    idx = _module_index(modules, mem)
    groups, ps = _discover_iat_groups(image, pe, idx, iat_rva, iat_size)
    funcs = sum(len(g["entries"]) for g in groups)
    if not groups:
        return image, {"ok": False, "error": "no IAT located",
                       "dlls": 0, "funcs": 0}

    new_rva = _align_up(max(pe.size_of_image, pe.computed_image_size()),
                        pe.section_alignment or 0x1000)
    blob, idt_size, iat_dir = _build_import_blob(new_rva, groups, ps)
    out, err = _apply_import_section(image, pe, blob, new_rva, idt_size,
                                     iat_dir, section_name)
    if err:
        return image, {"ok": False, "error": err,
                       "dlls": len(groups), "funcs": funcs}
    return out, {"ok": True, "dlls": len(groups), "funcs": funcs,
                 "new_rva": new_rva,
                 "groups": [(g["dll"], len(g["entries"])) for g in groups]}


def _fix_imports_ida(image, pe, iat_rva, iat_size, section_name):
    mods = _enumerate_modules()
    if not mods:
        _log("import fix: no loaded modules found - start a debug session first")
        return None, {"ok": False, "error": "no modules (need a live debugger)"}
    return rebuild_imports_for_image(
        image, pe, mods, lambda ea, size: ida_bytes.get_bytes(ea, size),
        iat_rva, iat_size, section_name)


def list_imports(ea=None, iat_rva=None, iat_size=None):
    """Resolve and print the IAT for the PE at `ea` without writing anything.
    Great for confirming the IAT location before a fix_imports dump."""
    base = _resolve_base(ea)
    if base is None:
        return None
    pe = parse_pe_header(base)
    if pe is None:
        _log("no PE at %X" % base)
        return None
    size = (pe.size_of_image
            if pe.size_of_headers < pe.size_of_image <= MAX_SANE_IMAGE
            else pe.computed_image_size())
    image, _ = _read_region(base, size)
    mods = _enumerate_modules()
    if not mods:
        _log("no modules (need a debug session) - cannot resolve imports")
        return None
    idx = _module_index(mods, lambda a, s: ida_bytes.get_bytes(a, s))
    groups, ps = _discover_iat_groups(image, pe, idx, iat_rva, iat_size)
    total = sum(len(g["entries"]) for g in groups)
    _log("IAT: %d function(s) across %d group(s) [ptr=%d]"
         % (total, len(groups), ps))
    for g in groups:
        _log("  %-24s @RVA %#x  (%d)"
             % (g["dll"], g["first_thunk_rva"], len(g["entries"])))
        for (nm, ordv) in g["entries"]:
            _log("     %s" % (nm if nm else "#%d" % ordv))
    return groups


def rebuild_imports_in_file(path, iat_rva=None, iat_size=None,
                            section_name=None):
    """Post-process an ALREADY-dumped file: resolve its IAT against the modules
    loaded in THIS debug session and write `<name>_imp<ext>` beside it."""
    with open(path, "rb") as fh:
        buf = bytearray(fh.read())
    reader = lambda ea, size: bytes(buf[ea:ea + size]).ljust(size, b"\x00")
    pe = parse_pe_header(0, mem=reader)
    if pe is None:
        _log("could not parse %s as a PE" % path)
        return None
    mods = _enumerate_modules()
    if not mods:
        _log("no modules (need the same live session that produced the dump)")
        return None
    out, rep = rebuild_imports_for_image(
        buf, pe, mods, lambda ea, size: ida_bytes.get_bytes(ea, size),
        iat_rva, iat_size, section_name)
    if not rep.get("ok"):
        _log("import rebuild failed: %s" % rep.get("error"))
        return None
    root, ext = os.path.splitext(path)
    out_path = _unique_path(root + "_imp" + ext)
    with open(out_path, "wb") as fh:
        fh.write(bytes(out))
    _log("rebuilt %d import(s) across %d DLL(s) -> %s"
         % (rep["funcs"], rep["dlls"], out_path))
    return out_path


# ----------------------------------------------------------------------------
# main entry points
# ----------------------------------------------------------------------------
def pe_info(ea=None):
    """Parse and print the PE header at `ea` (default cursor). No file written."""
    ea = _resolve_base(ea)
    if ea is None:
        return None
    pe = parse_pe_header(ea)
    if pe is None:
        _log("no valid PE at %X" % ea)
        return None
    print_report(pe)
    return pe


def dump_pe(ea=None, mode=None, ext=None, out_path=None,
            fix_imports=None, oep=None, iat_rva=None, iat_size=None):
    """Dump the PE at `ea` (default: cursor) to a file next to the input.

    mode : "auto" (default) | "virtual" | "raw"
    ext  : force output extension (".exe"/".dll"/".sys"/...) - else auto
    out_path : full override path for the output file
    fix_imports : rebuild the import table (default: FIX_IMPORTS). Needs a live
        debug session; forces virtual layout. Pin the IAT with iat_rva/iat_size
        (RVAs into the image) if the blind scan misses it.
    oep : override AddressOfEntryPoint. Accepts an absolute VA or a bare RVA.
    Returns the written path, or None on failure.
    """
    ea = _resolve_base(ea)
    if ea is None:
        return None

    pe = parse_pe_header(ea)
    if pe is None:
        _log("no valid PE at %X - point me at the MZ (4D 5A ..)" % ea)
        return None

    mode = (mode or DEFAULT_MODE).lower()
    if mode == "auto":
        mode, why = _detect_layout(pe)
        _log("auto layout -> %s  (%s)" % (mode, why))
    if mode not in ("virtual", "raw"):
        _log("unknown mode %r; using virtual" % mode)
        mode = "virtual"

    do_imp = FIX_IMPORTS if fix_imports is None else bool(fix_imports)
    if do_imp and mode == "raw":
        _log("import fix needs RVA layout; switching mode raw -> virtual")
        mode = "virtual"

    # ---- decide how many bytes belong to this PE ----
    if mode == "virtual":
        size = pe.size_of_image
        if size <= pe.size_of_headers or size > MAX_SANE_IMAGE:
            fixed = pe.computed_image_size()
            _log("SizeOfImage=%#x rejected; recomputed %#x from sections"
                 % (size, fixed))
            size = fixed
        else:
            size = _align_up(size, pe.section_alignment)
    else:  # raw
        size = pe.raw_extent()
        if size <= pe.size_of_headers or size > MAX_SANE_IMAGE:
            _log("raw extent %#x looks wrong; falling back to SizeOfImage" % size)
            size = min(max(pe.size_of_image, pe.size_of_headers), MAX_SANE_IMAGE)
    if size <= 0:
        _log("could not determine a sane size; aborting")
        return None

    # ---- read the whole thing ----
    image, missing = _read_region(ea, size)
    _log("read %#x bytes from %X (%d unreadable, zero-filled)"
         % (size, ea, missing))
    if missing:
        pct = 100.0 * missing / size
        _log("WARNING: %.2f%% of the region was unreadable. If this is a live "
             "dump, make sure the pages are committed/mapped." % pct)

    # ---- section fixups for a mapped image ----
    if mode == "virtual" and FIX_SECTION_TABLE:
        _rebuild_sections(image, pe)

    # ---- rebuild imports (optional; needs a live debug session) ----
    imp_report = None
    if do_imp:
        fixed, imp_report = _fix_imports_ida(image, pe, iat_rva, iat_size,
                                             IMPORT_SECTION)
        if fixed is not None:
            image = fixed

    # ---- optional entry-point override ----
    if oep is not None:
        _patch_oep(image, pe, oep)

    # ---- choose extension + path ----
    if ext is None:
        ext = pe.default_ext()
    elif not ext.startswith("."):
        ext = "." + ext
    path = out_path or _build_output_path(pe, ext)

    # ---- write ----
    try:
        with open(path, "wb") as fh:
            fh.write(bytes(image))
    except Exception as e:
        _log("write failed: %s" % e)
        ida_kernwin.warning("%s could not write:\n%s\n%s" % (_TAG, path, e))
        return None

    print_report(pe, chosen_mode=mode)
    _log("SAVED %d bytes -> %s" % (len(image), path))
    if missing == 0:
        _log("clean dump (no unreadable bytes).")
    if do_imp:
        if imp_report and imp_report.get("ok"):
            _log("imports: rebuilt %d function(s) across %d DLL(s) into '%s'; "
                 "SizeOfImage grown. Should load - verify in a PE tool."
                 % (imp_report["funcs"], imp_report["dlls"], IMPORT_SECTION))
            for dll, cnt in imp_report.get("groups", [])[:40]:
                _log("   %-24s %d" % (dll, cnt))
        else:
            why = imp_report.get("error") if imp_report else "no report"
            _log("imports: NOT rebuilt (%s). Dump is still fine for static RE; "
                 "for a runnable file rebuild during a live session with a valid "
                 "IAT (see list_imports())." % why)
    else:
        _log("note: imports NOT rebuilt (fix_imports=False). Call with "
             "fix_imports=True in a debug session, or use Scylla/pe-sieve.")

    if OPEN_FOLDER_AFTER:
        _reveal(path)
    return path


def dump_pe_prompt():
    """Ask for a base address in a dialog (hex) and dump it."""
    default = "%X" % idc.get_screen_ea()
    s = ida_kernwin.ask_str(default, 0, "PE base address (hex, MZ location):")
    if not s:
        return None
    s = s.strip().lower().replace("0x", "")
    try:
        ea = int(s, 16)
    except ValueError:
        _log("not a hex address: %r" % s)
        return None
    return dump_pe(ea)


def save_region(ea, size, name=None):
    """Raw blob dump of `size` bytes at `ea` (no PE parsing). QoL escape hatch."""
    if isinstance(size, str):
        size = int(size, 16)
    data, missing = _read_region(ea, size)
    out_dir, src = _output_dir()
    stem = os.path.splitext(os.path.basename(src or "dump"))[0] or "dump"
    fname = name or ("%s_blob_%X_%X.bin" % (stem, ea, size))
    path = _unique_path(os.path.join(out_dir, fname))
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    _log("saved blob %#x bytes (%d unreadable) -> %s" % (size, missing, path))
    return path


# ----------------------------------------------------------------------------
# scanning helpers
# ----------------------------------------------------------------------------
def _get_segment(i):
    """Fetch segment #i without the IDA 9.x DeprecationWarning. Uses
    get_segment_info_by_num() when available, otherwise falls back to
    getnseg() with the warning silenced."""
    fn = getattr(ida_segment, "get_segment_info_by_num", None)
    if fn is not None:
        return fn(i)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ida_segment.getnseg(i)


def _iter_segments():
    n = ida_segment.get_segm_qty()
    for i in range(n):
        seg = _get_segment(i)
        if seg:
            yield seg


def scan_for_pe(verbose=True):
    """Walk every segment on SCAN_STEP boundaries and MZ+PE-verify each hit.
    Also walk the input file's overlay and inter-section gaps (bytes NOT
    loaded as IDA segments) so embedded droppers / SFX payloads are caught.

    Returns a list of 2-tuples (source, locator):
      source="seg"  -> locator is an effective address
      source="file" -> locator is a byte offset into the input file
    Use dump_pe(ea) for seg findings and dump_pe_from_file(offset) for file
    findings (dump_all_pe() dispatches on source automatically)."""
    found = []
    seen_seg = set()
    seen_file = set()

    # 1. loaded segments (the live view)
    for seg in _iter_segments():
        ea = seg.start_ea
        ea = _align_up(ea, SCAN_STEP) if SCAN_STEP > 1 else ea
        while ea < seg.end_ea:
            sig = ida_bytes.get_bytes(ea, 2)
            if sig == _MZ and ea not in seen_seg:
                pe = parse_pe_header(ea)
                if pe is not None:
                    found.append(("seg", ea))
                    seen_seg.add(ea)
                    if verbose:
                        _log("PE candidate (seg)  @ %012X   %s %s  SizeOfImage=%#x"
                             % (ea, pe.machine_name, pe.default_ext(),
                                pe.size_of_image))
            ea += SCAN_STEP

    # 2. file-space: overlay + inter-section gaps (not visible to the view)
    data, _path = _input_file_bytes()
    if data:
        reader = _file_reader(data)
        for off, length in _pe_overlay_ranges(data):
            if length < 0x40:
                continue
            pos = off
            end = off + length
            while pos < end:
                i = data.find(_MZ, pos, end)
                if i < 0 or i + 0x40 > end:
                    break
                pos = i + 2
                if i in seen_file:
                    continue
                pe = parse_pe_header(i, mem=reader)
                if pe is not None:
                    found.append(("file", i))
                    seen_file.add(i)
                    if verbose:
                        _log("PE candidate (file) @ FILE+%08X  %s %s  SizeOfImage=%#x"
                             % (i, pe.machine_name, pe.default_ext(),
                                pe.size_of_image))

    if verbose:
        _log("scan complete: %d PE candidate(s)" % len(found))
    return found


def dump_all_pe(mode=None):
    """Dump every candidate scan_for_pe() finds (both loaded and overlay).
    Returns the list of written paths."""
    paths = []
    for source, loc in scan_for_pe(verbose=True):
        if source == "seg":
            p = dump_pe(loc, mode=mode)
        else:          # "file"
            p = dump_pe_from_file(loc)
        if p:
            paths.append(p)
    _log("dumped %d file(s)" % len(paths))
    return paths


def dump_pe_from_file(offset, ext=None, out_path=None, file_path=None):
    """Dump a PE embedded at file offset `offset` in the input file (overlay
    or an inter-section gap). The PE is written in RAW layout (bytes verbatim
    from the on-disk file, which is already in file layout).

    Pass file_path=... to point at a different file than the current IDA input.
    """
    if file_path:
        try:
            with open(file_path, "rb") as fh:
                data = fh.read()
        except Exception as e:
            _log("open failed: %s" % e)
            return None
    else:
        data, _path = _input_file_bytes()
        if not data:
            _log("no input file available for file-space dump")
            return None
    if isinstance(offset, str):
        offset = int(offset.strip().lower().replace("0x", ""), 16)
    if offset + 0x40 > len(data) or data[offset:offset + 2] != _MZ:
        _log("no MZ at FILE+%X" % offset)
        return None
    reader = _file_reader(data)
    pe = parse_pe_header(offset, mem=reader)
    if pe is None:
        _log("no valid PE at FILE+%X" % offset)
        return None
    size = pe.raw_extent()
    if size <= 0:
        size = min(len(data) - offset, _BLOB_MAX)
    if offset + size > len(data):
        _log("overlay PE extends past end-of-file; clamping (%d -> %d)"
             % (size, len(data) - offset))
        size = len(data) - offset
    image = bytes(data[offset:offset + size])
    if ext is None:
        ext = pe.default_ext()
    elif not ext.startswith("."):
        ext = "." + ext
    path = out_path or _build_blob_output_path_file(offset, "pe", ext)
    try:
        with open(path, "wb") as fh:
            fh.write(image)
    except Exception as e:
        _log("write failed: %s" % e)
        return None
    tag = ".NET" if pe.is_dotnet else pe.default_ext()[1:].upper()
    _log("PE %s @ FILE+%X  %s  size=%#x" % (tag, offset, pe.machine_name, size))
    _log("SAVED %d bytes -> %s" % (size, path))
    if OPEN_FOLDER_AFTER:
        _reveal(path)
    return path


# ============================================================================
#  generic blob carvers  -  non-PE containers commonly found on Windows
# ----------------------------------------------------------------------------
#  Each handler contributes a signature (used by the scanner) and a probe
#  function that computes the exact size of the blob from its bytes. Only
#  formats whose size is derivable from the stream itself are supported with
#  "exact" confidence; formats where the size requires out-of-band knowledge
#  are documented as signature-only.
#
#  Probe signature:
#      probe(reader, offset) -> (size:int, detail:str) | None
#      reader(ea, size) -> bytes          # fetches bytes starting at ea
#      offset                             # absolute ea where the signature starts
#  Returning None means the probe is NOT confident; the scanner drops such
#  hits. For signature-only extraction use dump_blob(ea, kind=..., size=N).
# ============================================================================

try:
    import zlib as _zlib
    _HAVE_ZLIB = True
except Exception:                            # pragma: no cover
    _HAVE_ZLIB = False

_BLOB_MAX = 1 * 1024 * 1024 * 1024           # 1 GB per-blob cap (sanity)
_BLOB_SCAN_STEP = 0x100000                   # chunk size for the memory scanner


class _BlobHandler(object):
    __slots__ = ("name", "ext", "sig", "min_bytes", "probe")

    def __init__(self, name, ext, sig, min_bytes, probe):
        self.name = name
        self.ext = ext
        self.sig = sig
        self.min_bytes = min_bytes
        self.probe = probe


def _probe_zip(reader, offset):
    """ZIP (deterministic): find the last EOCD and return start-to-end size."""
    SIG_EOCD = b"PK\x05\x06"
    first = reader(offset, 30) or b""
    if len(first) < 30 or first[:4] != b"PK\x03\x04":
        return None
    MAX = min(_BLOB_MAX, 256 * 1024 * 1024)
    buf = bytes(first)
    while len(buf) < MAX:
        more = reader(offset + len(buf),
                      min(MAX - len(buf), 8 * 1024 * 1024)) or b""
        if not more:
            break
        buf += more
        if len(more) < 8 * 1024 * 1024:
            break
    if not buf:
        return None
    last = buf.rfind(SIG_EOCD)
    if last < 0 or last + 22 > len(buf):
        return None
    comment_len = int.from_bytes(buf[last + 20:last + 22], "little")
    cd_size = int.from_bytes(buf[last + 12:last + 16], "little")
    cd_offset = int.from_bytes(buf[last + 16:last + 20], "little")
    total = last + 22 + comment_len
    if total > len(buf):
        return None
    # Plausibility: central-directory record must sit before the EOCD.
    if cd_offset + cd_size > last and cd_offset != 0xFFFFFFFF:
        return None
    return total, "ZIP (EOCD @ +%d, CD @ +%d, size=%d)" % (last, cd_offset,
                                                           cd_size)


def _probe_7z(reader, offset):
    """7z (deterministic): SignatureHeader @ 0, next_header_offset+size."""
    hdr = reader(offset, 32) or b""
    if len(hdr) < 32 or hdr[:6] != b"7z\xbc\xaf\x27\x1c":
        return None
    next_off = int.from_bytes(hdr[12:20], "little")
    next_size = int.from_bytes(hdr[20:28], "little")
    total = 32 + next_off + next_size
    if not (32 <= total <= _BLOB_MAX):
        return None
    return total, "7z (next_hdr @ +%d, size=%d)" % (32 + next_off, next_size)


def _probe_gzip(reader, offset):
    """gzip (deterministic via zlib): decompress the stream to find its end."""
    if not _HAVE_ZLIB:
        return None
    hdr = reader(offset, 10) or b""
    if len(hdr) < 10 or hdr[:3] != b"\x1f\x8b\x08":
        return None
    d = _zlib.decompressobj(wbits=31)        # 31 = gzip header + DEFLATE
    consumed = 0
    STEP = 4 * 1024 * 1024
    while consumed < _BLOB_MAX:
        chunk = reader(offset + consumed, STEP) or b""
        if not chunk:
            break
        try:
            d.decompress(chunk)
        except Exception:
            return None
        if d.eof:
            unused = len(d.unused_data) if d.unused_data else 0
            size = consumed + len(chunk) - unused
            return size, "gzip (DEFLATE stream, %d compressed bytes)" % size
        consumed += len(chunk)
        if len(chunk) < STEP:
            break
    return None


def _probe_pdf(reader, offset):
    """PDF (scan): header + last %%EOF (handles incremental updates)."""
    MAX = min(_BLOB_MAX, 128 * 1024 * 1024)
    buf = reader(offset, min(MAX, 8 * 1024 * 1024)) or b""
    if len(buf) < 5 or buf[:5] != b"%PDF-":
        return None
    while len(buf) < MAX:
        more = reader(offset + len(buf),
                      min(MAX - len(buf), 8 * 1024 * 1024)) or b""
        if not more:
            break
        buf += more
        if len(more) < 8 * 1024 * 1024:
            break
    last = buf.rfind(b"%%EOF")
    if last < 0:
        return None
    end = last + 5
    if end < len(buf) and buf[end] == 0x0D:
        end += 1
    if end < len(buf) and buf[end] == 0x0A:
        end += 1
    return end, "PDF (%%EOF @ +%d)" % last


def _probe_png(reader, offset):
    """PNG (deterministic): walk chunks until the IEND marker."""
    hdr = reader(offset, 8) or b""
    if hdr != b"\x89PNG\r\n\x1a\n":
        return None
    pos = 8
    while pos < _BLOB_MAX:
        ch = reader(offset + pos, 8) or b""
        if len(ch) < 8:
            return None
        length = int.from_bytes(ch[:4], "big")
        ctype = ch[4:8]
        if length > _BLOB_MAX:               # bogus chunk length
            return None
        pos += 4 + 4 + length + 4            # size + type + data + CRC
        if ctype == b"IEND":
            return pos, "PNG (IEND @ +%d)" % (pos - 12)
    return None


def _probe_bmp(reader, offset):
    """BMP (strict): BM signature + plausible bfSize, bfOffBits, DIB size."""
    hdr = reader(offset, 18) or b""
    if len(hdr) < 18 or hdr[:2] != b"BM":
        return None
    bf_size = int.from_bytes(hdr[2:6], "little")
    bf_off = int.from_bytes(hdr[10:14], "little")
    bi_size = int.from_bytes(hdr[14:18], "little")
    # BM is a weak 2-byte signature: strict plausibility prunes false positives.
    if not (54 <= bf_size <= 500 * 1024 * 1024):
        return None
    if not (26 <= bf_off <= bf_size):
        return None
    if bi_size not in (12, 40, 52, 56, 64, 108, 124):   # standard DIB headers
        return None
    return bf_size, "BMP (bfSize=%d, bfOffBits=%d)" % (bf_size, bf_off)


def _probe_cab(reader, offset):
    """CAB (deterministic): cbCabinet field at offset +8."""
    hdr = reader(offset, 36) or b""
    if len(hdr) < 36 or hdr[:4] != b"MSCF":
        return None
    cb_cabinet = int.from_bytes(hdr[8:12], "little")
    cfolder_count = int.from_bytes(hdr[26:28], "little")
    cfile_count = int.from_bytes(hdr[28:30], "little")
    if not (36 <= cb_cabinet <= _BLOB_MAX):
        return None
    return cb_cabinet, ("CAB (cbCabinet=%d, folders=%d, files=%d)"
                        % (cb_cabinet, cfolder_count, cfile_count))


def _probe_rar4(reader, offset):
    """RAR4 (block walker): find the ENDARC_HEAD terminator block."""
    sig = reader(offset, 7) or b""
    if sig != b"Rar!\x1a\x07\x00":
        return None
    pos = 7
    while pos < _BLOB_MAX:
        block = reader(offset + pos, 11) or b""
        if len(block) < 7:
            return None
        head_type = block[2]
        head_flags = int.from_bytes(block[3:5], "little")
        head_size = int.from_bytes(block[5:7], "little")
        if head_size == 0:
            return None                     # bogus/truncated header
        add_size = 0
        if (head_flags & 0x8000) and len(block) >= 11:
            add_size = int.from_bytes(block[7:11], "little")
        block_total = head_size + add_size
        pos += block_total
        if head_type == 0x7B:               # ENDARC_HEAD (end of archive)
            return pos, "RAR4 (end marker @ +%d)" % (pos - block_total)
    return None


def _probe_rar5(reader, offset):
    """RAR5 uses vint-encoded block headers; size not implemented. The scanner
    records nothing for RAR5; use dump_blob(ea, kind='rar', size=N) manually."""
    return None


_BLOB_HANDLERS = [
    _BlobHandler("zip",  ".zip", b"PK\x03\x04",             30, _probe_zip),
    _BlobHandler("7z",   ".7z",  b"7z\xbc\xaf\x27\x1c",     32, _probe_7z),
    _BlobHandler("gzip", ".gz",  b"\x1f\x8b\x08",           18, _probe_gzip),
    _BlobHandler("pdf",  ".pdf", b"%PDF-",                  32, _probe_pdf),
    _BlobHandler("png",  ".png", b"\x89PNG\r\n\x1a\n",      16, _probe_png),
    _BlobHandler("bmp",  ".bmp", b"BM",                     54, _probe_bmp),
    _BlobHandler("cab",  ".cab", b"MSCF",                   36, _probe_cab),
    _BlobHandler("rar4", ".rar", b"Rar!\x1a\x07\x00",       11, _probe_rar4),
    _BlobHandler("rar5", ".rar", b"Rar!\x1a\x07\x01\x00",   12, _probe_rar5),
]

_BLOB_HANDLERS_BY_NAME = {h.name: h for h in _BLOB_HANDLERS}


def _view_reader(ea, n):
    """Byte reader bound to the current IDA view (live memory while debugging,
    DB bytes otherwise). Zero-length result on failure."""
    b = ida_bytes.get_bytes(ea, n)
    return bytes(b) if b else b""


def _normalize_blob_cats(cats):
    """Return None (all) or a set of handler names. Accepts None, 'all', a
    string ('zip'), or an iterable of strings."""
    if cats is None or cats == "all":
        return None
    if isinstance(cats, str):
        cats = (cats,)
    want = set()
    for c in cats:
        c = c.lower()
        if c in _BLOB_HANDLERS_BY_NAME:
            want.add(c)
        elif c == "rar":
            want.update(("rar4", "rar5"))
        else:
            _log("unknown blob kind %r (see list_blob_kinds())" % c)
    return want or None


def list_blob_kinds():
    """Print the supported non-PE containers and whether they are deterministic."""
    print("%s supported blob kinds:" % _TAG)
    for h in _BLOB_HANDLERS:
        confidence = "signature only" if h.name == "rar5" else "exact size"
        print("%s   %-6s %s   (%s)" % (_TAG, h.name, h.ext, confidence))


def _build_blob_output_path(ea, kind, ext):
    out_dir, src = _output_dir()
    stem = os.path.splitext(os.path.basename(src or "dump"))[0] or "dump"
    name = "%s_dumped_%X_%s%s" % (stem, ea, kind, ext)
    return _unique_path(os.path.join(out_dir, name))


def _detect_blob_at(ea, cats=None):
    """Match every candidate handler at `ea` and return the first that reports
    an exact size: (handler, size, detail) or None."""
    want = _normalize_blob_cats(cats)
    candidates = [h for h in _BLOB_HANDLERS if want is None or h.name in want]
    for h in candidates:
        head = _view_reader(ea, len(h.sig))
        if head != h.sig:
            continue
        res = h.probe(_view_reader, ea)
        if res:
            size, detail = res
            return h, size, detail
    return None


def blob_info(ea=None, kind=None):
    """Identify the container at `ea` (default cursor) and print the probe
    result (size + detail) without writing a file."""
    if ea is None:
        ea = idc.get_screen_ea()
    if isinstance(ea, str):
        ea = int(ea.strip().lower().replace("0x", ""), 16)
    cats = (kind,) if kind else None
    hit = _detect_blob_at(ea, cats=cats)
    if not hit:
        _log("no recognised container signature at %X (see list_blob_kinds())"
             % ea)
        return None
    h, size, detail = hit
    _log("%s @ %X  size=%#x  %s" % (h.name, ea, size, detail))
    return {"kind": h.name, "ext": h.ext, "ea": ea, "size": size,
            "detail": detail}


def scan_for_blobs(cats=None, verbose=True):
    """Walk every segment and the input file's overlay / inter-section gaps,
    running every blob probe at every signature match.

    Returns a list of 6-tuples:
        (source, locator, kind, ext, size, detail)
      source="seg"  -> locator is an effective address (in the IDA view)
      source="file" -> locator is a byte offset in the input file
    Only findings whose size could be determined exactly are returned.
    """
    want = _normalize_blob_cats(cats)
    handlers = [h for h in _BLOB_HANDLERS if want is None or h.name in want]
    if not handlers:
        _log("scan_for_blobs: no handlers for cats=%r" % cats)
        return []
    found = []
    seen = set()
    max_sig = max((len(h.sig) for h in handlers), default=0)

    # 1. loaded segments (the live view)
    for seg in _iter_segments():
        start, end = seg.start_ea, seg.end_ea
        ea = start
        prev_tail = b""
        while ea < end:
            n = min(_BLOB_SCAN_STEP, end - ea)
            got = ida_bytes.get_bytes(ea, n) or b""
            if not got:
                prev_tail = b""
                ea += n
                continue
            combined = prev_tail + bytes(got)
            tail_base = ea - len(prev_tail)
            for h in handlers:
                pos = 0
                while True:
                    i = combined.find(h.sig, pos)
                    if i < 0:
                        break
                    pos = i + 1
                    abs_ea = tail_base + i
                    key = ("seg", abs_ea, h.name)
                    if key in seen:
                        continue
                    seen.add(key)
                    res = h.probe(_view_reader, abs_ea)
                    if not res:
                        continue
                    size, detail = res
                    found.append(("seg", abs_ea, h.name, h.ext, size, detail))
                    if verbose:
                        _log("%-5s @ %012X   size=%#x  %s"
                             % (h.name, abs_ea, size, detail))
            prev_tail = combined[-max_sig:] if max_sig else b""
            ea += n

    # 2. file-space: overlay + inter-section gaps (not visible to the view)
    data, _path = _input_file_bytes()
    if data:
        reader = _file_reader(data)
        for off, length in _pe_overlay_ranges(data):
            if length < max_sig:
                continue
            region_end = off + length
            for h in handlers:
                pos = off
                while pos < region_end:
                    i = data.find(h.sig, pos, region_end)
                    if i < 0:
                        break
                    pos = i + 1
                    key = ("file", i, h.name)
                    if key in seen:
                        continue
                    seen.add(key)
                    res = h.probe(reader, i)
                    if not res:
                        continue
                    size, detail = res
                    found.append(("file", i, h.name, h.ext, size, detail))
                    if verbose:
                        _log("%-5s @ FILE+%08X  size=%#x  %s"
                             % (h.name, i, size, detail))

    if verbose:
        _log("scan complete: %d blob(s)" % len(found))
    return found


def dump_blob_from_file(offset, kind=None, size=None, out_path=None,
                        file_path=None):
    """Carve a blob from the input file at `offset` (bytes-in-file, not an
    effective address). Pass kind= to force a format or size= to override the
    probed size. file_path= points at a file other than the current input."""
    if file_path:
        try:
            with open(file_path, "rb") as fh:
                data = fh.read()
        except Exception as e:
            _log("open failed: %s" % e)
            return None
    else:
        data, _path = _input_file_bytes()
        if not data:
            _log("no input file available for file-space dump")
            return None
    if isinstance(offset, str):
        offset = int(offset.strip().lower().replace("0x", ""), 16)
    if offset < 0 or offset >= len(data):
        _log("offset FILE+%X is outside the file (size=%#x)"
             % (offset, len(data)))
        return None
    reader = _file_reader(data)
    kind_name = None
    ext = None
    detail = None
    if kind:
        h = _BLOB_HANDLERS_BY_NAME.get(kind.lower())
        if h is None:
            _log("unknown blob kind %r (see list_blob_kinds())" % kind)
            return None
        kind_name = h.name
        ext = h.ext
        if size is None:
            res = h.probe(reader, offset)
            if res:
                size, detail = res
    else:
        hit = None
        for h in _BLOB_HANDLERS:
            head = reader(offset, len(h.sig))
            if head != h.sig:
                continue
            res = h.probe(reader, offset)
            if res:
                hit = (h, res[0], res[1])
                break
        if hit is None:
            if size is None:
                _log("no recognised container at FILE+%X; pass kind= / size="
                     % offset)
                return None
        else:
            h, probed_size, detail = hit
            kind_name = h.name
            ext = h.ext
            if size is None:
                size = probed_size
    if size is None or size <= 0:
        _log("could not determine a size for FILE+%X; pass size=N" % offset)
        return None
    if offset + size > len(data):
        _log("blob extends past end-of-file; clamping (%d -> %d)"
             % (size, len(data) - offset))
        size = len(data) - offset
    if size > _BLOB_MAX:
        _log("size %#x exceeds the %d GB sanity cap"
             % (size, _BLOB_MAX // (1024 ** 3)))
        return None
    label = kind_name or "raw"
    ext = ext or ".bin"
    path = out_path or _build_blob_output_path_file(offset, label, ext)
    try:
        with open(path, "wb") as fh:
            fh.write(bytes(data[offset:offset + size]))
    except Exception as e:
        _log("write failed: %s" % e)
        return None
    if detail:
        _log("%s @ FILE+%X  size=%#x  %s" % (label, offset, size, detail))
    _log("SAVED %d bytes -> %s" % (size, path))
    if OPEN_FOLDER_AFTER:
        _reveal(path)
    return path


def dump_all_blobs(cats=None):
    """Scan for every blob (segments + overlay) and dump each finding.
    Returns the list of written paths."""
    paths = []
    for source, loc, kind, _ext, size, _detail in scan_for_blobs(
            cats=cats, verbose=True):
        if source == "seg":
            p = dump_blob(loc, kind=kind, size=size)
        else:              # "file"
            p = dump_blob_from_file(loc, kind=kind, size=size)
        if p:
            paths.append(p)
    _log("dumped %d blob(s)" % len(paths))
    return paths


def dump_blob(ea=None, kind=None, size=None, out_path=None):
    """Carve the blob at `ea` (default cursor) to disk.

    Auto-detects the format from the signature at `ea`. Pass kind=... to force
    one (useful for signature-only formats like RAR5 or SFX archives), and
    size=N to override the probed size (or supply it when none can be
    probed). Returns the written path, or None on failure.
    """
    if ea is None:
        ea = idc.get_screen_ea()
    if isinstance(ea, str):
        ea = int(ea.strip().lower().replace("0x", ""), 16)
    if ea == BADADDR or ea is None:
        _log("no address")
        return None

    kind_name = None
    ext = None
    detail = None
    if kind:
        h = _BLOB_HANDLERS_BY_NAME.get(kind.lower())
        if h is None:
            _log("unknown blob kind %r (see list_blob_kinds())" % kind)
            return None
        kind_name = h.name
        ext = h.ext
        if size is None:
            res = h.probe(_view_reader, ea)
            if res:
                size, detail = res
    else:
        hit = _detect_blob_at(ea)
        if hit is None:
            if size is None:
                _log("no recognised container at %X; pass kind=..., size=... "
                     "to force a carve (see list_blob_kinds())." % ea)
                return None
            # size given with no kind: treat as a raw blob.
            return save_region(ea, size)
        h, probed_size, detail = hit
        kind_name = h.name
        ext = h.ext
        size = size if size is not None else probed_size

    if size is None or size <= 0:
        _log("could not determine a size for %s @ %X; pass size=N" %
             (kind_name, ea))
        return None
    if size > _BLOB_MAX:
        _log("size %#x exceeds the %d GB sanity cap"
             % (size, _BLOB_MAX // (1024 ** 3)))
        return None

    data, missing = _read_region(ea, size)
    if missing:
        _log("WARNING: %d/%d bytes were unreadable and zero-filled."
             % (missing, size))

    path = out_path or _build_blob_output_path(ea, kind_name, ext)
    try:
        with open(path, "wb") as fh:
            fh.write(bytes(data))
    except Exception as e:
        _log("write failed: %s" % e)
        return None
    if detail:
        _log("%s @ %X  size=%#x  %s" % (kind_name, ea, size, detail))
    _log("SAVED %d bytes -> %s" % (size, path))
    if OPEN_FOLDER_AFTER:
        _reveal(path)
    return path




# per-format convenience scanners (symmetry with scan_for_pe())
def scan_for_zip(verbose=True):  return scan_for_blobs("zip",  verbose=verbose)
def scan_for_7z(verbose=True):   return scan_for_blobs("7z",   verbose=verbose)
def scan_for_gzip(verbose=True): return scan_for_blobs("gzip", verbose=verbose)
def scan_for_pdf(verbose=True):  return scan_for_blobs("pdf",  verbose=verbose)
def scan_for_png(verbose=True):  return scan_for_blobs("png",  verbose=verbose)
def scan_for_bmp(verbose=True):  return scan_for_blobs("bmp",  verbose=verbose)
def scan_for_cab(verbose=True):  return scan_for_blobs("cab",  verbose=verbose)
def scan_for_rar(verbose=True):  return scan_for_blobs("rar",  verbose=verbose)


# ----------------------------------------------------------------------------
# misc
# ----------------------------------------------------------------------------
def _resolve_base(ea):
    """Resolve the working base address, auto-scanning backward for MZ if the
    given/cursor address is not exactly on the header."""
    if ea is None:
        ea = idc.get_screen_ea()
    if isinstance(ea, str):
        ea = int(ea.strip().lower().replace("0x", ""), 16)
    if ea == BADADDR or ea is None:
        _log("no address")
        return None
    # already on MZ?
    if ida_bytes.get_bytes(ea, 2) == _MZ:
        return ea
    # scan backward a bit (page-aligned) - handy when the cursor is inside the
    # payload rather than exactly on the MZ.
    probe = ea & ~0xF
    for _ in range(0x4000):                 # up to ~256 KB back on 16-byte steps
        if ida_bytes.get_bytes(probe, 2) == _MZ:
            hdr = parse_pe_header(probe)
            if hdr is not None:
                _log("cursor %X not on MZ; using nearest header @ %X" % (ea, probe))
                return probe
        if probe < 0x10:
            break
        probe -= 0x10
    _log("no MZ at or before %X; pass the exact base to dump_pe(ea)" % ea)
    return ea       # let parse fail loudly with a clear message


def _patch_oep(image, pe, oep):
    """Override AddressOfEntryPoint. `oep` may be an absolute VA or a bare RVA."""
    rva = (oep - pe.base) if oep >= pe.base else oep
    if pe.opt_off + 20 <= len(image):
        struct.pack_into("<I", image, pe.opt_off + 16, rva & 0xFFFFFFFF)
        _log("set AddressOfEntryPoint -> RVA %#x" % rva)
    else:
        _log("could not patch OEP (optional header truncated in the dump)")


def _reveal(path):
    try:
        if os.name == "nt":
            os.startfile(os.path.dirname(path))    # noqa: S606 - user-invoked
    except Exception:
        pass


# ----------------------------------------------------------------------------
# bootstrap
# ----------------------------------------------------------------------------
_hotkey = None


def _bootstrap():
    global _hotkey
    try:
        _hotkey = ida_kernwin.add_hotkey("Ctrl-Alt-D", dump_pe)
        _log("hotkey Ctrl-Alt-D -> dump_pe() at cursor")
    except Exception as e:
        _log("could not bind hotkey: %s" % e)
    _log("ready. dump_pe() / dump_pe(0xBASE[,fix_imports=True]) / dump_pe_prompt() "
         "/ scan_for_pe() / dump_all_pe() / pe_info(ea) / list_imports(ea) / "
         "rebuild_imports_in_file(path) / save_region(ea,size). "
         "Blobs: dump_blob(ea) / blob_info(ea) / scan_for_blobs() / "
         "dump_all_blobs() / list_blob_kinds() "
         "(ZIP, 7z, gzip, PDF, PNG, BMP, CAB, RAR4; RAR5 signature-only). "
         "Overlay / off-image: scanners also walk the input file's overlay + "
         "inter-section gaps; dump_pe_from_file(offset) and "
         "dump_blob_from_file(offset) carve those findings. "
         "Modes: auto|virtual|raw. Output goes next to the analyzed file.")


_bootstrap()
