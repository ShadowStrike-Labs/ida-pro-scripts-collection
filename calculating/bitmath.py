"""
bitmath.py - interactive bit-twiddling helpers for reverse engineering.

The IDA "?" quick-calculator (backed by the IDC interpreter) handles
^ & | << >> ~, but has no rotate operator and no arithmetic-shift or
byte-swap helpers. This module fills that gap for crypto / hash / VM work
where rotations and fixed-width math are constant.

Pure Python, no IDA API required, so it runs anywhere:
  * IDA Python console (bottom CLI switched to Python)
  * idapythonrc.py       -> helpers auto-load into every database
  * a normal Python REPL

Load it inside IDA by adding one line to your idapythonrc.py
(%APPDATA%\\Hex-Rays\\IDA Pro\\idapythonrc.py):
    exec(open(r"C:\\path\\to\\bitmath.py").read())

Default width is 32 bits. Pass bits=64 (or 8 / 16), or use the
width-suffixed wrappers (ror64, rol32, ...). SipHash, for example, is
all 64-bit rotations -> use ror64 / rol64.

Examples:
    show(0xD6F2CDC1)                          # multi-radix + ascii view
    hex(ror(0xD6F2CDC1, 5))
    hex(rol64(0x0123456789ABCDEF, 13))
    hex(xor(0x41, 0x11))                      # -> 0x50
    hex(bswap32(0xDEADBEEF))                  # -> 0xEFBEADDE
    to_ascii(0x7465646279746573, 64, "big")   # SipHash IV word -> 'tedbytes'
    help_bitmath()
"""

DEFAULT_BITS = 32


def _mask(bits):
    return (1 << bits) - 1


# ---- rotations -------------------------------------------------------------
def rol(x, n, bits=DEFAULT_BITS):
    """Rotate left within a `bits`-wide register."""
    m = _mask(bits)
    x &= m
    n %= bits
    return ((x << n) | (x >> (bits - n))) & m


def ror(x, n, bits=DEFAULT_BITS):
    """Rotate right within a `bits`-wide register."""
    m = _mask(bits)
    x &= m
    n %= bits
    return ((x >> n) | (x << (bits - n))) & m


def rol8(x, n):  return rol(x, n, 8)
def ror8(x, n):  return ror(x, n, 8)
def rol16(x, n): return rol(x, n, 16)
def ror16(x, n): return ror(x, n, 16)
def rol32(x, n): return rol(x, n, 32)
def ror32(x, n): return ror(x, n, 32)
def rol64(x, n): return rol(x, n, 64)
def ror64(x, n): return ror(x, n, 64)


# ---- boolean / bitwise (variadic) ------------------------------------------
def bxor(*vals):
    """XOR of all arguments."""
    r = 0
    for v in vals:
        r ^= v
    return r
xor = bxor  # alias


def band(*vals):
    """AND of all arguments."""
    if not vals:
        return 0
    r = vals[0]
    for v in vals[1:]:
        r &= v
    return r


def bor(*vals):
    """OR of all arguments."""
    r = 0
    for v in vals:
        r |= v
    return r


def bnot(x, bits=DEFAULT_BITS):
    """Bitwise NOT within `bits`."""
    return (~x) & _mask(bits)


# ---- shifts ----------------------------------------------------------------
def shl(x, n, bits=DEFAULT_BITS):
    """Logical shift left."""
    return (x << n) & _mask(bits)


def shr(x, n, bits=DEFAULT_BITS):
    """Logical (unsigned) shift right."""
    return (x & _mask(bits)) >> n


def sar(x, n, bits=DEFAULT_BITS):
    """Arithmetic (sign-preserving) shift right."""
    return (sxt(x, bits) >> n) & _mask(bits)


# ---- width / sign / endianness ---------------------------------------------
def sxt(x, bits=DEFAULT_BITS):
    """Sign-extend a `bits`-wide value to a signed Python int."""
    x &= _mask(bits)
    if x & (1 << (bits - 1)):
        x -= (1 << bits)
    return x


def zxt(x, bits=DEFAULT_BITS):
    """Zero-extend / truncate to `bits`."""
    return x & _mask(bits)


def bswap(x, bits=DEFAULT_BITS):
    """Reverse byte order (endianness flip)."""
    nbytes = bits // 8
    return int.from_bytes((x & _mask(bits)).to_bytes(nbytes, "little"), "big")


def bswap16(x): return bswap(x, 16)
def bswap32(x): return bswap(x, 32)
def bswap64(x): return bswap(x, 64)


# ---- single-bit helpers ----------------------------------------------------
def getbit(x, i): return (x >> i) & 1
def setbit(x, i): return x | (1 << i)
def clrbit(x, i): return x & ~(1 << i)
def togbit(x, i): return x ^ (1 << i)
def popcount(x):  return bin(x).count("1")
def parity(x):    return bin(x).count("1") & 1


# ---- text conversions ------------------------------------------------------
def to_ascii(x, bits=DEFAULT_BITS, order="little"):
    """Interpret a value's bytes as text. Use order="big" to read magic
    constants the way they are written in hex (e.g. SipHash IV words)."""
    return (x & _mask(bits)).to_bytes(bits // 8, order).decode("latin-1")


def from_ascii(s, order="little"):
    """Pack a short string into an integer (matches how constants are stored)."""
    return int.from_bytes(s.encode("latin-1"), order)


# ---- the calculator the "?" box won't give you -----------------------------
def show(x, bits=DEFAULT_BITS):
    """Print a value in every useful representation at once."""
    m = _mask(bits)
    x &= m
    nbytes = bits // 8
    le = x.to_bytes(nbytes, "little")
    be = x.to_bytes(nbytes, "big")
    txt = lambda bs: "".join(chr(b) if 32 <= b < 127 else "." for b in bs)
    print("hex : 0x%0*X" % (nbytes * 2, x))
    print("dec : %d  (signed %d)" % (x, sxt(x, bits)))
    print("bin : {:0{w}b}".format(x, w=bits))
    print("oct : 0o%o" % x)
    print("bytes LE: %-24s ascii LE: %s" % (le.hex(" "), txt(le)))
    print("bytes BE: %-24s ascii BE: %s" % (be.hex(" "), txt(be)))


def help_bitmath():
    print(__doc__)


if __name__ == "__main__":
    # quick self-check when run standalone
    assert ror(rol(0xDEADBEEF, 7), 7) == 0xDEADBEEF
    assert xor(0x41, 0x11) == 0x50
    assert bswap32(0xDEADBEEF) == 0xEFBEADDE
    assert to_ascii(0x7465646279746573, 64, "big") == "tedbytes"
    assert sar(0x80000000, 4) == 0xF8000000
    assert popcount(0xFF) == 8
    print("bitmath self-check OK")
    show(0xD6F2CDC1)
