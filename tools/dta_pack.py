#!/usr/bin/env python3
"""DTA Packer: packs a folder into a Hidden & Dangerous 2 .dta archive.

Run without arguments for the window; with arguments it packs from the command line:

    python dta_pack.py                                   (window)
    python dta_pack.py MyMod PatchX02.dta --key PatchX02.dta
    python dta_pack.py MyMod Test.dta --key 0x12345678:0x9ABCDEF0 --store
    python dta_pack.py MyMod Plain.dta --key blank
    python dta_pack.py MyMod PatchX02.dta --compression lz4
    python dta_pack.py MyMod PatchX02.dta --compression lz4hc --level 12

Every file under the folder is stored under its path relative to the folder, with
backslashes ("Tables\\items.sav"), which is the name the game asks rw_data.dll for.

The archives are written in the ISD1 format, as read by rw_data.dll (see the rw_data
port, docs/rw_data_functions.md, section 3). All integers are little endian; "encrypted"
means XORed with the 64-bit key, byte i of each piece with key byte i % 8, each piece from
its own start.

    archive  "ISD1", then 20 encrypted bytes: file count, table offset, table size,
             Checksum16 of the table as stored, Checksum16 of these 24 bytes (decrypted,
             this field zeroed). The files follow back to back, the table ends the archive.
    file     0x20-byte header (encrypted): u32 stored size of the whole entry, u32 Windows
             attributes, FILETIME, u32 size, u32 block count, u32 Checksum16 of the header
             (decrypted, this field zeroed), u16 name length | 0x8000 (whole blocks are
             encrypted), u16 Checksum16 chained over the decrypted name, the size table and
             the stored type table. Then the name (encrypted, original case), u32 per block
             (stored size | Checksum16 of the stored block << 16, not encrypted), u8 per
             block its type (encrypted), and the blocks (encrypted).
             A file identical to an earlier one (same size, CRC-32 and SHA-256) has no
             blocks of its own: its header, name and block tables (a copy of the first
             file's) are written after the last file, and its table entry's block offset
             points at the first file's blocks. The reader takes the blocks from that
             offset, so this needs no change to the format.
    blocks   each decodes to 32 KB (the last one to the rest). Type 1 is an LZSS stream
             whose first byte is the type, type 2 an LZ4 block (the reference's block
             format, no size header; written by the LZ4 and the LZ4 HC compressors alike),
             type 0 stores the bytes as they are. A block that does not get smaller is
             stored. An empty file has one empty stored block.
    table    0x1C bytes per file, sorted by hash, encrypted as one piece: hash (name length
             << 16 | 16-bit sum of the upper-case name), header offset, offset of the first
             block, the last 16 characters of the upper-case name (zero padded).

The fields the reader ignores are filled like in the game's own archives: in all 68,968
files of the retail archives the first header field is the entry's stored size, the second
holds Windows file attributes (0x20, 0x21 or 0x80), and every file has the 0x8000 flag.

LZ4 blocks are read only by the rw_data port: the original rw_data.dll takes type 2 for
stored data, so an archive packed with LZ4 or LZ4 HC needs the port. LZSS (the default)
works with both. LZ4 HC (levels 3..12, default 9) packs slower than LZ4 but smaller; both
decode at the same speed.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import multiprocessing
import os
import queue
import struct
import sys
import threading
import time
import zlib

BLOCK_SIZE = 0x8000            # decoded size of a block
CHUNK_BLOCKS = 32              # blocks per compression job (1 MB)
MAX_NAME_LENGTH = 259          # the original rw_data.dll reads names into 264-byte buffers
MAX_ARCHIVE_SIZE = 0x7FFFFFFF  # offsets go through SetFilePointer as signed 32-bit values
CHECKSUM_SEED = 0xFF
NAME_ENCRYPTED_BLOCKS = 0x8000
FILETIME_UNIX_EPOCH = 116444736000000000   # 1970-01-01 in 100 ns units since 1601
ATTRIBUTE_MASK = 0x27          # read-only, hidden, system, archive
ATTRIBUTE_NORMAL = 0x80
BLOCK_STORED = 0
BLOCK_LZSS = 1
BLOCK_LZ4 = 2                  # read only by the rw_data port

# Compression methods: name -> description (the window's list and --compression).
COMPRESSION_METHODS = {
    "lzss": "LZSS, like the game's archives (any rw_data.dll)",
    "lz4": "LZ4 (needs the rw_data.dll port)",
    "lz4hc": "LZ4 HC, smaller and slower to pack (needs the port)",
    "none": "None (stored)",
}

# The keys of MountDataArchives (game 0x006dba30), in the order the game searches the
# archives. PatchX02, PatchX03 and Maps_C are mounted when present but are not part of the
# retail game. Every Lang<language>.dta uses the LangEnglish key.
GAME_KEYS = [
    ("PatchX03.dta", 0xA0A0A0A4, 0xA0A0A0A0, "Searched first. Not part of the retail game: free for mods."),
    ("PatchX02.dta", 0xA0A0A0A3, 0xA0A0A0A0, "Searched second. Not part of the retail game: free for mods."),
    ("PatchX01.dta", 0xA0A0A0A2, 0xA0A0A0A0, "Official patch archive (holds Tables\\items.sav)."),
    ("SabreSquadron.dta", 0xA0A0A0A1, 0xA0A0A0A0, "Sabre Squadron expansion archive."),
    ("LangEnglish.dta", 0xA0A0A0A0, 0xA0A0A0A0, "Language archive. Every Lang<language>.dta uses this key."),
    ("Patch.dta", 0x5D805270, 0x10ACB252, "Patch archive of the base game."),
    ("Models.dta", 0x5D805259, 0x10ACB252, "Base game archive."),
    ("Missions.dta", 0x7654A3F0, 0x22BCDA98, "Base game archive."),
    ("Maps.dta", 0xB438D0A5, 0xF26527FA, "Base game archive."),
    ("Sounds.dta", 0x4FE85106, 0x8D2965CA, "Base game archive."),
    ("Scripts.dta", 0x0AB4E72D, 0xCF761298, "Base game archive."),
    ("Others.dta", 0xEA85902A, 0x65F7AB23, "Base game archive."),
    ("Maps_C.dta", 0xB038D0A0, 0xE26520FA, "Searched after the base archives. Not part of the retail game."),
    ("Maps_U.dta", 0xB038D1A1, 0xF26520FA, "Base game archive, searched last."),
]


class PackError(Exception):
    """A problem with the input or the output that stops packing."""


class PackCancelled(Exception):
    pass


# Cipher and checksum -------------------------------------------------------------------

def make_key(low: int, high: int) -> int:
    return (high & 0xFFFFFFFF) << 32 | (low & 0xFFFFFFFF)


_keystreams: dict = {}


def xor_key(data: bytes, key: int) -> bytes:
    """Encrypts (or decrypts) one piece: byte i ^= key byte i % 8."""
    size = len(data)
    if size == 0 or key == 0:
        return bytes(data)
    stream = _keystreams.get(key)
    if stream is None or len(stream) < size:
        stream = key.to_bytes(8, "little") * ((max(size, BLOCK_SIZE) + 7) // 8)
        _keystreams[key] = stream
    mixed = int.from_bytes(data, "little") ^ int.from_bytes(stream[:size], "little")
    return mixed.to_bytes(size, "little")


def checksum16(data: bytes, seed: int = CHECKSUM_SEED) -> int:
    """rw_data's Checksum16."""
    s = seed
    for b in data:
        s = ((s + b) & 0xFFFF) ^ (b ^ 0xFF)
    return s


# LZSS ----------------------------------------------------------------------------------
#
# Stream: byte 0 = 1, then groups of 16 items, each group preceded by a big-endian flag
# word read from its top bit. Flag 0: a literal byte. Flag 1: DDDDDDDD DDDDLLLL copies
# L + 3 bytes from D bytes back (D = 1..4095), or with D = 0 the four bytes 00 0H LL BB
# repeat byte BB HLL + 16 times. Copies run byte by byte, so they may overlap.

WINDOW = 4095
MIN_MATCH = 3
MAX_MATCH = 18
MIN_RUN = 16
MAX_RUN = 0xFFF + MIN_RUN
CHAIN_DEPTH = 16
_RUN_PREFIX = [bytes((b,)) * MIN_RUN for b in range(256)]


def lzss_compress(data: bytes) -> bytes | None:
    """Compresses one block. Returns the stream (starting with the type byte 1), or None
    when it would not be smaller than the data stored as it is."""
    size = len(data)
    if size < 8 or len(zlib.compress(data, 1)) > size - size // 32:
        return None   # (almost) incompressible: not worth the slow search
    out = bytearray(b"\x01\x00\x00")
    flags_at = 1
    flags = 0
    items = 0
    chains: dict = {}
    pos = 0
    last_key = size - MIN_MATCH   # last position with a whole 3-byte key
    while pos < size:
        if items == 16:
            out[flags_at] = flags >> 8
            out[flags_at + 1] = flags & 0xFF
            flags_at = len(out)
            out += b"\x00\x00"
            flags = 0
            items = 0
            if len(out) > size:
                return None
        items += 1

        byte = data[pos]
        if data[pos:pos + MIN_RUN] == _RUN_PREFIX[byte]:
            end = min(size, pos + MAX_RUN)
            run = end - pos - len(data[pos:end].lstrip(_RUN_PREFIX[byte][:1]))
            count = run - MIN_RUN
            out += bytes((0, count >> 8, count & 0xFF, byte))
            flags = flags << 1 | 1
            stop = pos + run
        else:
            length = 0
            distance = 0
            if pos <= last_key:
                key = data[pos:pos + 3]
                candidates = chains.get(key)
                if candidates is not None:
                    longest = min(MAX_MATCH, size - pos)
                    target = data[pos:pos + longest]
                    oldest = pos - WINDOW
                    for at in reversed(candidates[-CHAIN_DEPTH:]):
                        if at < oldest:
                            break
                        if length and data[at + length] != target[length]:
                            continue   # cannot be longer than the best so far
                        source = data[at:at + longest]
                        if source == target:
                            length = longest
                            distance = pos - at
                            break
                        diff = int.from_bytes(source, "big") ^ int.from_bytes(target, "big")
                        common = longest - (diff.bit_length() + 7) // 8
                        if common > length:
                            length = common
                            distance = pos - at
                    candidates.append(pos)
                else:
                    chains[key] = [pos]
            if length >= MIN_MATCH:
                code = distance << 4 | (length - MIN_MATCH)
                out += bytes((code >> 8, code & 0xFF))
                flags = flags << 1 | 1
                stop = pos + length
                pos += 1   # this position is already in the chains
            else:
                out.append(byte)
                flags <<= 1
                pos += 1
                continue
        # Record the positions the item covered, so later matches can start there (of a
        # long run only its end: the other positions all have the same key).
        for at in range(max(pos, stop - MAX_MATCH), min(stop, last_key + 1)):
            key = data[at:at + 3]
            candidates = chains.get(key)
            if candidates is None:
                chains[key] = [at]
            else:
                candidates.append(at)
        pos = stop

    flags <<= 16 - items
    out[flags_at] = flags >> 8
    out[flags_at + 1] = flags & 0xFF
    if len(out) - 1 >= size:
        return None
    return bytes(out)


# LZ4 -----------------------------------------------------------------------------------
#
# An LZ4 block (https://github.com/lz4/lz4, doc/lz4_Block_format.md), no frame and no size
# header: sequences of a token (high nibble = literal count, low nibble = match length - 4,
# 15 continued by bytes up to the first one below 255), the literals, a little-endian u16
# offset (1..65535) and the match. The last sequence is literals only. As the format asks
# (and LZ4_compress_default does), the last 5 bytes are literals and no match starts in the
# last 12 bytes, so the reference decoder reads these blocks too.

LZ4_MIN_MATCH = 4
LZ4_LAST_LITERALS = 5
LZ4_MF_LIMIT = 12
LZ4_MAX_OFFSET = 0xFFFF
LZ4_SKIP_TRIGGER = 6           # like the reference: the step grows on incompressible data

try:   # the python-lz4 package, if installed, is the reference encoder and much faster
    import lz4.block as _lz4_block
except ImportError:
    _lz4_block = None


def _lz4_length(n: int) -> bytes:
    """The continuation bytes of a length whose nibble is 15 (n = length - 15)."""
    return b"\xff" * (n // 255) + bytes((n % 255,))


def _common_length(data: bytes, a: int, b: int, limit: int) -> int:
    """How many bytes data[a:] and data[b:] have in common, up to `limit`."""
    n = 0
    step = 16
    while n < limit:
        k = min(step, limit - n)
        x = data[a + n:a + n + k]
        y = data[b + n:b + n + k]
        if x == y:
            n += k
            step *= 4
            continue
        diff = int.from_bytes(x, "big") ^ int.from_bytes(y, "big")
        return n + k - (diff.bit_length() + 7) // 8
    return n


def lz4_compress(data: bytes) -> bytes | None:
    """Compresses one block like LZ4_compress_default (greedy, one candidate per 4-byte
    key). Returns the LZ4 block, or None when it would not be smaller than the data."""
    size = len(data)
    if size < 8 or len(zlib.compress(data, 1)) > size - size // 32:
        return None   # (almost) incompressible: not worth the search
    if _lz4_block is not None:
        out = _lz4_block.compress(data, mode="default", store_size=False)
        return out if len(out) < size else None

    out = bytearray()
    anchor = 0
    if size > LZ4_MF_LIMIT:
        last_start = size - LZ4_MF_LIMIT        # no match starts after this
        match_end = size - LZ4_LAST_LITERALS    # nor runs past this
        table: dict = {}
        pos = 0
        while True:
            # Find a match, stepping faster the longer none is found.
            attempts = 1 << LZ4_SKIP_TRIGGER
            ref = -1
            while pos <= last_start:
                key = data[pos:pos + 4]
                candidate = table.get(key)
                table[key] = pos
                if candidate is not None and pos - candidate <= LZ4_MAX_OFFSET:
                    ref = candidate
                    break
                pos += attempts >> LZ4_SKIP_TRIGGER
                attempts += 1
            if ref < 0:
                break
            # Extend it backwards over the pending literals, then forwards.
            while pos > anchor and ref > 0 and data[pos - 1] == data[ref - 1]:
                pos -= 1
                ref -= 1
            length = LZ4_MIN_MATCH + _common_length(data, pos + LZ4_MIN_MATCH, ref + LZ4_MIN_MATCH,
                                                    match_end - pos - LZ4_MIN_MATCH)
            _lz4_sequence(out, data, anchor, pos, pos - ref, length)
            pos += length
            anchor = pos
            if len(out) >= size:
                return None
            if pos > last_start:
                break
            table[data[pos - 2:pos + 2]] = pos - 2
    return _lz4_finish(out, data, anchor)


def _lz4_sequence(out: bytearray, data: bytes, anchor: int, pos: int, offset: int, length: int):
    """Appends the literals data[anchor:pos] and a match of `length` bytes `offset` back."""
    literals = pos - anchor
    code = length - LZ4_MIN_MATCH
    out.append(min(literals, 15) << 4 | min(code, 15))
    if literals >= 15:
        out += _lz4_length(literals - 15)
    out += data[anchor:pos]
    out += offset.to_bytes(2, "little")
    if code >= 15:
        out += _lz4_length(code - 15)


def _lz4_finish(out: bytearray, data: bytes, anchor: int) -> bytes | None:
    """Appends the last literals; None when the block did not get smaller."""
    literals = len(data) - anchor
    out.append(min(literals, 15) << 4)
    if literals >= 15:
        out += _lz4_length(literals - 15)
    out += data[anchor:]
    if len(out) >= len(data):
        return None
    return bytes(out)


# LZ4 HC --------------------------------------------------------------------------------
#
# The high-compression encoder of the reference (lib/lz4hc.c) writes the same LZ4 blocks,
# so the DLL reads them with the same decoder; it only searches harder. Like its level table:
# levels 3..9 follow chains of earlier positions with the same 4 bytes (4 << (level - 3)
# candidates) and look one byte ahead before taking a match ("lazy" matching); levels 10..12
# use the optimal parser, which weighs every match length at every position by its cost in
# bytes (96 / 512 candidates for levels 10 / 11; a match longer than 64 / 128 is taken at
# once). The reference's level 12 (16384 candidates, 4096) takes minutes per block on very
# repetitive data in Python, so level 12 here uses 2048 / 512: in tests it came out within
# 0.01% of the reference level 12 and still smaller than level 11. Level 9 is the reference's
# default. The output is not byte-identical to lz4hc.c (its chains are hashed and its parser
# keeps more state), but it is the same format and, level for level, close in size. With the
# python-lz4 package installed, its lz4hc.c is used at the level asked for instead.

LZ4HC_LEVEL_MIN = 3
LZ4HC_LEVEL_DEFAULT = 9
LZ4HC_LEVEL_OPT_MIN = 10
LZ4HC_LEVEL_MAX = 12
_LZ4HC_OPT_PARAMS = {10: (96, 64), 11: (512, 128), 12: (2048, 512)}   # candidates, sufficient length


def _lz4hc_search(data: bytes, chains: dict, pos: int, depth: int, limit: int) -> tuple:
    """(length, offset) of the longest match at `pos` among its last `depth` candidates,
    at most `limit` bytes long; (0, 0) if there is none. Does not record `pos`."""
    candidates = chains.get(data[pos:pos + 4])
    best = 0
    offset = 0
    if candidates:
        oldest = pos - LZ4_MAX_OFFSET
        for at in reversed(candidates[-depth:]):
            if at < oldest:
                break
            if best and data[at + best] != data[pos + best]:
                continue   # cannot be longer than the best so far
            length = LZ4_MIN_MATCH + _common_length(data, at + LZ4_MIN_MATCH, pos + LZ4_MIN_MATCH,
                                                    limit - LZ4_MIN_MATCH)
            if length > best:
                best = length
                offset = pos - at
                if best >= limit:
                    break
    return best, offset


def _lz4hc_insert(data: bytes, chains: dict, start: int, stop: int):
    """Records the positions start..stop-1 in the chains."""
    for at in range(start, stop):
        key = data[at:at + 4]
        candidates = chains.get(key)
        if candidates is None:
            chains[key] = [at]
        else:
            candidates.append(at)


def _lz4hc_chain(data: bytes, depth: int) -> bytes | None:
    """Levels 3..9: hash chains with lazy matching."""
    size = len(data)
    out = bytearray()
    anchor = 0
    last_start = size - LZ4_MF_LIMIT
    match_end = size - LZ4_LAST_LITERALS
    chains: dict = {}
    pos = 0
    recorded = 0                 # positions below this are in the chains
    while pos <= last_start:
        length, offset = _lz4hc_search(data, chains, pos, depth, match_end - pos)
        _lz4hc_insert(data, chains, pos, pos + 1)
        recorded = pos + 1
        if length < LZ4_MIN_MATCH:
            pos += 1
            continue
        # A longer match one byte further on wins over this one.
        while pos + 1 <= last_start:
            next_length, next_offset = _lz4hc_search(data, chains, pos + 1, depth, match_end - pos - 1)
            if next_length <= length:
                break
            _lz4hc_insert(data, chains, pos + 1, pos + 2)
            pos += 1
            recorded = pos + 1
            length, offset = next_length, next_offset
        # Extend it backwards over the pending literals.
        while pos > anchor and pos - offset > 0 and data[pos - 1] == data[pos - offset - 1]:
            pos -= 1
            length += 1
        _lz4_sequence(out, data, anchor, pos, offset, length)
        if len(out) >= size:
            return None
        _lz4hc_insert(data, chains, recorded, min(pos + length, last_start + 1))
        pos += length
        recorded = max(recorded, pos)
        anchor = pos
    return _lz4_finish(out, data, anchor)


def _lz4_extra(n: int) -> int:
    """The bytes a length (literal count, or match length - 4) takes beyond its nibble."""
    return 0 if n < 15 else 1 + (n - 15) // 255


def _lz4hc_optimal(data: bytes, depth: int, sufficient: int) -> bytes | None:
    """Levels 10..12: the cheapest parse in bytes. cost[i] = the fewest bytes that encode
    data[:i], reached with `run[i]` pending literals (the reference's approximation: one state
    per position)."""
    size = len(data)
    last_start = size - LZ4_MF_LIMIT
    match_end = size - LZ4_LAST_LITERALS
    infinite = 1 << 60
    cost = [infinite] * (size + 1)
    run = [0] * (size + 1)
    step: list = [None] * (size + 1)   # how i was reached: None = a literal, else (start, offset)
    cost[0] = 0
    chains: dict = {}
    skip_until = 0               # inside a match taken at once: no search
    for pos in range(size):
        here = cost[pos]
        literals = run[pos] + 1
        price = here + 1 + _lz4_extra(literals) - _lz4_extra(literals - 1)
        if price < cost[pos + 1]:
            cost[pos + 1] = price
            run[pos + 1] = literals
            step[pos + 1] = None
        if pos > last_start:
            continue
        if pos < skip_until:
            _lz4hc_insert(data, chains, pos, pos + 1)
            continue
        length, offset = _lz4hc_search(data, chains, pos, depth, match_end - pos)
        _lz4hc_insert(data, chains, pos, pos + 1)
        if length < LZ4_MIN_MATCH:
            continue
        # Token, offset and the extra literal-count bytes the pending run needed (already in
        # cost[pos] one by one), plus the match length's extra bytes.
        base = here + 3
        shortest = length if length > sufficient else LZ4_MIN_MATCH
        for n in range(shortest, length + 1):
            price = base + _lz4_extra(n - LZ4_MIN_MATCH)
            if price < cost[pos + n]:
                cost[pos + n] = price
                run[pos + n] = 0
                step[pos + n] = (pos, offset)
        if length > sufficient:
            skip_until = pos + length

    matches = []
    pos = size
    while pos > 0:
        how = step[pos]
        if how is None:
            pos -= 1
        else:
            matches.append((how[0], how[1], pos - how[0]))
            pos = how[0]
    out = bytearray()
    anchor = 0
    for start, offset, length in reversed(matches):
        _lz4_sequence(out, data, anchor, start, offset, length)
        anchor = start + length
    return _lz4_finish(out, data, anchor)


def lz4hc_compress(data: bytes, level: int = LZ4HC_LEVEL_DEFAULT) -> bytes | None:
    """Compresses one block like LZ4_compress_HC at `level` (3..12). Returns the LZ4 block,
    or None when it would not be smaller than the data."""
    level = max(LZ4HC_LEVEL_MIN, min(LZ4HC_LEVEL_MAX, level))
    size = len(data)
    if size < 8 or len(zlib.compress(data, 1)) > size - size // 32:
        return None   # (almost) incompressible: not worth the search
    if _lz4_block is not None:
        out = _lz4_block.compress(data, mode="high_compression", compression=level, store_size=False)
        return out if len(out) < size else None
    if size <= LZ4_MF_LIMIT:
        return _lz4_finish(bytearray(), data, 0)
    if level >= LZ4HC_LEVEL_OPT_MIN:
        return _lz4hc_optimal(data, *_LZ4HC_OPT_PARAMS[level])
    return _lz4hc_chain(data, 4 << (level - LZ4HC_LEVEL_MIN))


# Blocks (run in the worker processes) --------------------------------------------------

def _normalize_method(compress) -> str:
    """pack_files' `compress`: a COMPRESSION_METHODS name, or True (LZSS) / False (none)."""
    if compress is True:
        return "lzss"
    if compress is False or compress is None:
        return "none"
    method = str(compress).lower()
    if method not in COMPRESSION_METHODS:
        raise PackError(f"unknown compression {compress!r}: use one of {', '.join(COMPRESSION_METHODS)}")
    return method


def encode_block(raw: bytes, method: str, level: int = LZ4HC_LEVEL_DEFAULT) -> tuple:
    """(type, stored bytes without the type) of one block, before encryption. `level` is
    the LZ4 HC level."""
    if method == "lzss":
        stream = lzss_compress(raw)
        if stream is not None:
            return stream[0], stream[1:]
    elif method in ("lz4", "lz4hc"):
        stream = lz4_compress(raw) if method == "lz4" else lz4hc_compress(raw, level)
        if stream is not None:
            return BLOCK_LZ4, stream   # HC writes the same LZ4 blocks
    return BLOCK_STORED, raw


def encode_chunk(path: str, offset: int, length: int, key: int, method: str,
                 level: int = LZ4HC_LEVEL_DEFAULT) -> list:
    """Reads `length` bytes of a file and turns them into stored blocks.
    Returns [(type, encrypted data, checksum of the encrypted data), ...].
    Raises OSError only: the worker processes send their errors back by pickling them."""
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(length)
    if len(data) != length:
        raise OSError(f"{path} changed while it was being packed")
    blocks = []
    for start in range(0, length, BLOCK_SIZE) or [0]:
        kind, stored = encode_block(data[start:start + BLOCK_SIZE], method, level)
        stored = xor_key(stored, key)
        blocks.append((kind, stored, checksum16(stored)))
    return blocks


def _encode_job(job: tuple) -> list:
    return encode_chunk(*job)


# Packing -------------------------------------------------------------------------------

def _ansi_codec() -> str:
    try:
        "".encode("mbcs")
        return "mbcs"   # the Windows ANSI code page, which the game's names use
    except LookupError:
        return "cp1252"


NAME_CODEC = _ansi_codec()


class SourceFile:
    __slots__ = ("path", "name", "upper", "size", "filetime", "attributes")

    def __init__(self, path: str, name: bytes, size: int, filetime: int, attributes: int):
        self.path = path
        self.name = name
        self.upper = name.upper()   # ASCII only, like the DLL's _strupr
        self.size = size
        self.filetime = filetime
        self.attributes = attributes

    @property
    def display_name(self) -> str:
        return self.name.decode(NAME_CODEC, "replace")

    @property
    def block_count(self) -> int:
        return max(1, (self.size + BLOCK_SIZE - 1) // BLOCK_SIZE)

    @property
    def hash(self) -> int:
        return len(self.upper) << 16 | (sum(self.upper) & 0xFFFF)


def collect_files(folder: str, exclude=()) -> list:
    """Lists the files under `folder` with their archive names; raises PackError for names
    the archive cannot hold."""
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        raise PackError(f"{folder} is not a folder")
    excluded = {os.path.normcase(os.path.abspath(p)) for p in exclude}
    files = []
    problems = []
    seen = {}

    def unreadable(error: OSError):
        problems.append(f"{os.path.relpath(error.filename, folder)}: {error.strerror}")

    for root, dirs, names in os.walk(folder, onerror=unreadable):
        dirs.sort(key=str.lower)
        for name in sorted(names, key=str.lower):
            path = os.path.join(root, name)
            if os.path.normcase(path) in excluded:
                continue
            relative = os.path.relpath(path, folder).replace("/", "\\")
            try:
                encoded = relative.encode(NAME_CODEC, "strict")
            except UnicodeEncodeError:
                problems.append(f"{relative}: the name has characters the game cannot use")
                continue
            if len(encoded) > MAX_NAME_LENGTH:
                problems.append(f"{relative}: the name is longer than {MAX_NAME_LENGTH} characters")
                continue
            try:
                info = os.stat(path)
            except OSError as error:
                problems.append(f"{relative}: {error.strerror}")
                continue
            if info.st_size > 0xFFFFFFFF:
                problems.append(f"{relative}: larger than 4 GB")
                continue
            attributes = getattr(info, "st_file_attributes", 0x20) & ATTRIBUTE_MASK or ATTRIBUTE_NORMAL
            filetime = info.st_mtime_ns // 100 + FILETIME_UNIX_EPOCH
            entry = SourceFile(path, encoded, info.st_size, filetime, attributes)
            if entry.upper in seen:
                problems.append(f"{relative}: same name as {seen[entry.upper]} (names are not case-sensitive)")
                continue
            seen[entry.upper] = relative
            files.append(entry)
    if problems:
        shown = "\n".join(problems[:15])
        more = f"\n... and {len(problems) - 15} more" if len(problems) > 15 else ""
        raise PackError(f"These files cannot be packed:\n{shown}{more}")
    return files


class _ArchiveWriter:
    """Writes the files of an ISD1 archive one after another, then the table and header."""

    def __init__(self, f, key: int):
        self.f = f
        self.key = key
        self.entries = []
        self.current = None
        self.written = {}   # file index -> (data offset, size table, type table) of its blocks
        f.write(b"ISD1" + bytes(20))

    def begin(self, source: SourceFile, index: int = -1):
        self.current = source
        self.current_index = index
        self.header_offset = self.f.tell()
        self.types = bytearray()
        self.sizes = []
        # Header, name and block tables are written once the blocks are known.
        self.f.write(bytes(0x20 + len(source.name) + 5 * source.block_count))

    def add_blocks(self, blocks: list):
        for kind, stored, checksum in blocks:
            self.f.write(stored)
            self.types.append(kind)
            self.sizes.append(len(stored) | checksum << 16)
        if self.f.tell() > MAX_ARCHIVE_SIZE:
            raise PackError("The archive would be larger than 2 GB, which the game cannot read. "
                            "Split the files into several archives.")

    def end(self):
        source = self.current
        count = source.block_count
        if len(self.types) != count:
            raise PackError(f"{source.path} changed while it was being packed")
        end = self.f.tell()
        sizes = struct.pack(f"<{count}I", *self.sizes)
        types = xor_key(bytes(self.types), self.key)
        data_offset = self.header_offset + 0x20 + len(source.name) + 5 * count
        self.f.seek(self.header_offset)
        self._write_entry(source, end - self.header_offset, sizes, types, data_offset)
        self.f.seek(end)
        if self.current_index >= 0:
            self.written[self.current_index] = (data_offset, sizes, types)
        self.current = None

    def add_duplicate(self, source: SourceFile, original: int):
        """Writes the header, name and block tables of a file identical to the already
        written file `original`; its table entry points at that file's blocks, which the
        reader takes from the entry's data offset."""
        data_offset, sizes, types = self.written[original]
        self._write_entry(source, 0x20 + len(source.name) + len(sizes) + len(types),
                          sizes, types, data_offset)
        if self.f.tell() > MAX_ARCHIVE_SIZE:
            raise PackError("The archive would be larger than 2 GB, which the game cannot read.")

    def _write_entry(self, source: SourceFile, stored_size: int, sizes: bytes, types: bytes,
                     data_offset: int):
        """Writes the header, name and block tables at the current position and adds the
        table entry."""
        header_offset = self.f.tell()
        name = source.name
        count = len(types)
        tables_checksum = checksum16(types, checksum16(sizes, checksum16(name)))
        header = struct.pack("<IIQIIIHH", stored_size, source.attributes,
                             source.filetime, source.size, count, 0,
                             len(name) | NAME_ENCRYPTED_BLOCKS, tables_checksum)
        header = header[:0x18] + struct.pack("<I", checksum16(header)) + header[0x1C:]
        self.f.write(xor_key(header, self.key) + xor_key(name, self.key) + sizes + types)
        self.entries.append((source.hash, source.upper, header_offset, data_offset))

    def finish(self):
        self.entries.sort(key=lambda e: (e[0], e[1]))
        table = b"".join(struct.pack("<III16s", h, header, data, upper[-16:])
                         for h, upper, header, data in self.entries)
        table = xor_key(table, self.key)
        table_offset = self.f.tell()
        if table_offset + len(table) > MAX_ARCHIVE_SIZE:
            raise PackError("The archive would be larger than 2 GB, which the game cannot read.")
        self.f.write(table)
        fields = [len(self.entries), table_offset, len(table), checksum16(table), 0]
        fields[4] = checksum16(b"ISD1" + struct.pack("<5I", *fields))
        self.f.seek(4)
        self.f.write(xor_key(struct.pack("<5I", *fields), self.key))
        self.f.seek(0, os.SEEK_END)


HASH_CHUNK = 1024 * 1024


def _file_digest(path: str, make) -> bytes:
    """Digest of a whole file: `make` is a hashlib constructor, or None for CRC-32."""
    crc = 0
    hasher = make() if make else None
    with open(path, "rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK)
            if not chunk:
                break
            if hasher is not None:
                hasher.update(chunk)
            else:
                crc = zlib.crc32(chunk, crc)
    return hasher.digest() if hasher is not None else crc.to_bytes(4, "little")


def find_duplicates(files: list, progress=None, cancel: threading.Event | None = None) -> dict:
    """Finds files with the same contents as an earlier file of the list.

    Returns {index of a duplicate: index of the first file with those contents}. Only files
    of equal size are compared: first by CRC-32 (fast), and files whose CRC-32 matches by
    SHA-256 as well, so a CRC collision is never taken for a duplicate. Empty files are left
    alone (they have no blocks to share)."""
    by_size = collections.defaultdict(list)
    for index, source in enumerate(files):
        if source.size > 0:
            by_size[source.size].append(index)
    candidates = [group for group in by_size.values() if len(group) > 1]
    total = sum(files[group[0]].size * len(group) for group in candidates)
    done = 0
    duplicates = {}
    for group in candidates:
        by_crc = collections.defaultdict(list)
        for index in group:
            if cancel is not None and cancel.is_set():
                raise PackCancelled()
            if progress:
                progress(done, total, files[index].display_name)
            by_crc[_file_digest(files[index].path, None)].append(index)
            done += files[index].size
        for matches in by_crc.values():
            if len(matches) < 2:
                continue
            first_by_digest = {}
            for index in matches:
                if cancel is not None and cancel.is_set():
                    raise PackCancelled()
                digest = _file_digest(files[index].path, hashlib.sha256)
                first = first_by_digest.setdefault(digest, index)
                if first != index:
                    duplicates[index] = first
    return duplicates


def pack_files(files: list, output: str, key: int, compress: bool | str = True, workers: int = 0,
               progress=None, cancel: threading.Event | None = None, dedup: bool = True,
               level: int = LZ4HC_LEVEL_DEFAULT) -> dict:
    """Packs `files` (from collect_files) into the archive `output`.

    `compress` is a COMPRESSION_METHODS name ("lzss", "lz4", "lz4hc", "none"), or True for
    LZSS and False for none; `level` is the LZ4 HC level (3..12). With `dedup`, files with the same contents are stored once: the others
    get their own header and name but share the first one's blocks (see find_duplicates).

    progress(done_bytes, total_bytes, name) is called as files are packed (from this
    thread). Setting `cancel` stops packing (PackCancelled). The archive is written to
    "<output>.part" and only replaces `output` when complete.
    """
    if not files:
        raise PackError("There are no files to pack.")
    method = _normalize_method(compress)
    if not LZ4HC_LEVEL_MIN <= level <= LZ4HC_LEVEL_MAX:
        raise PackError(f"The LZ4 HC level must be {LZ4HC_LEVEL_MIN} to {LZ4HC_LEVEL_MAX}.")
    total = sum(f.size for f in files)
    workers = workers or os.cpu_count() or 1
    if total < 2 * 1024 * 1024:
        workers = 1   # starting the processes would take longer than the work

    started = time.monotonic()
    duplicates = find_duplicates(files, progress, cancel) if dedup else {}

    jobs = []   # (file index, (path, offset, length, key, method, level))
    for index, source in enumerate(files):
        if index in duplicates:
            continue
        for offset in range(0, source.size, CHUNK_BLOCKS * BLOCK_SIZE) or [0]:
            length = min(CHUNK_BLOCKS * BLOCK_SIZE, source.size - offset)
            jobs.append((index, (source.path, offset, length, key, method, level)))

    temp = output + ".part"
    executor = None
    try:
        if workers > 1:
            executor = concurrent.futures.ProcessPoolExecutor(max_workers=workers)

            def results():
                # In order, with a few jobs per process queued ahead.
                pending = collections.deque()
                for index, job in jobs:
                    if len(pending) >= workers * 4:
                        done_index, length, future = pending.popleft()
                        yield done_index, length, future.result()
                    pending.append((index, job[2], executor.submit(_encode_job, job)))
                while pending:
                    done_index, length, future = pending.popleft()
                    yield done_index, length, future.result()
        else:
            def results():
                for index, job in jobs:
                    yield index, job[2], _encode_job(job)

        done = 0
        with open(temp, "wb") as f:
            writer = _ArchiveWriter(f, key)
            current = -1
            if progress:
                progress(0, total, files[0].display_name)
            for index, length, blocks in results():
                if cancel is not None and cancel.is_set():
                    raise PackCancelled()
                if index != current:
                    if current >= 0:
                        writer.end()
                    current = index
                    writer.begin(files[index], index)
                writer.add_blocks(blocks)
                done += length
                if progress:
                    progress(done, total, files[index].display_name)
            writer.end()
            for index, original in sorted(duplicates.items()):
                source = files[index]
                try:
                    unchanged = os.stat(source.path).st_size == source.size
                except OSError:
                    unchanged = False
                if not unchanged:
                    raise PackError(f"{source.path} changed while it was being packed")
                writer.add_duplicate(source, original)
                done += source.size
            if progress:
                progress(total, total, files[-1].display_name)
            writer.finish()
            archive_size = f.tell()
        os.replace(temp, output)
    except BaseException as error:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
            executor = None
        try:
            os.remove(temp)
        except OSError:
            pass
        if isinstance(error, concurrent.futures.process.BrokenProcessPool):
            raise PackError("The compression processes stopped. Try again with 1 process.") from error
        if isinstance(error, OSError):
            raise PackError(str(error)) from error
        raise
    finally:
        if executor is not None:
            executor.shutdown(wait=True)
    return {"files": len(files), "input_size": total, "archive_size": archive_size,
            "duplicates": len(duplicates),
            "duplicate_size": sum(files[i].size for i in duplicates),
            "seconds": time.monotonic() - started}


def parse_key(text: str) -> int:
    """A game archive's name, "blank", or "LOW:HIGH" (two 32-bit hex values)."""
    text = text.strip()
    for name, low, high, _ in GAME_KEYS:
        if text.lower() in (name.lower(), name.lower()[:-4]):
            return make_key(low, high)
    if text.lower() in ("blank", "none", "0"):
        return 0
    parts = text.replace(",", ":").split(":")
    if len(parts) == 2:
        return make_key(_parse_hex32(parts[0]), _parse_hex32(parts[1]))
    raise ValueError(f"unknown key {text!r}: use an archive name, 'blank' or LOW:HIGH in hex")


def _parse_hex32(text: str) -> int:
    text = text.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text or len(text) > 8 or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise ValueError(f"{text!r} is not a 32-bit hex value")
    return int(text, 16)


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size:,} bytes"
    for unit in ("KB", "MB", "GB"):
        size /= 1024
        if size < 1024 or unit == "GB":
            return f"{size:,.1f} {unit}"


# Window --------------------------------------------------------------------------------

CUSTOM_KEY = "Custom key"
BLANK_KEY = "Blank key (no encryption)"


def _game_key(name: str):
    for entry in GAME_KEYS:
        if entry[0] == name:
            return entry
    return None


class PackerWindow:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.root = root
        root.title("DTA Packer")
        root.minsize(640, 520)

        self.source_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.key_choice = tk.StringVar(value="PatchX02.dta")
        self.low_var = tk.StringVar()
        self.high_var = tk.StringVar()
        self.key_info = tk.StringVar()
        self.compress_var = tk.StringVar(value=COMPRESSION_METHODS["lzss"])
        self.level_var = tk.IntVar(value=LZ4HC_LEVEL_DEFAULT)
        self.workers_var = tk.IntVar(value=os.cpu_count() or 1)
        self.dedup_var = tk.BooleanVar(value=True)
        self.summary_var = tk.StringVar()
        self.status_var = tk.StringVar()

        self.files = []
        self.loaded = None        # the folder whose files are listed
        self.suggested = ""       # the output name chosen by the window, not the user
        self.confirmed = ""       # an output the save dialog already asked to overwrite
        self.thread = None
        self.cancel = None
        self.messages = queue.Queue()

        frame = ttk.Frame(root, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(7, weight=1)

        ttk.Label(frame, text="Source folder").grid(row=0, column=0, sticky="w", pady=3)
        self.source_entry = ttk.Entry(frame, textvariable=self.source_var)
        self.source_entry.grid(row=0, column=1, sticky="ew", padx=6)
        self.browse_source = ttk.Button(frame, text="Browse...", command=self.choose_source)
        self.browse_source.grid(row=0, column=2)

        ttk.Label(frame, text="Encryption key").grid(row=1, column=0, sticky="w", pady=3)
        choices = [entry[0] for entry in GAME_KEYS] + [CUSTOM_KEY, BLANK_KEY]
        self.key_box = ttk.Combobox(frame, textvariable=self.key_choice, values=choices,
                                    state="readonly", height=len(choices))
        self.key_box.grid(row=1, column=1, sticky="w", padx=6)
        key_frame = ttk.Frame(frame)
        key_frame.grid(row=2, column=1, columnspan=2, sticky="w", padx=6)
        ttk.Label(key_frame, text="Low 0x").pack(side="left")
        self.low_entry = ttk.Entry(key_frame, textvariable=self.low_var, width=10, font="TkFixedFont")
        self.low_entry.pack(side="left")
        ttk.Label(key_frame, text="   High 0x").pack(side="left")
        self.high_entry = ttk.Entry(key_frame, textvariable=self.high_var, width=10, font="TkFixedFont")
        self.high_entry.pack(side="left")
        ttk.Label(frame, textvariable=self.key_info, foreground="gray40", wraplength=480).grid(
            row=3, column=1, columnspan=2, sticky="w", padx=6, pady=(0, 6))

        ttk.Label(frame, text="Output archive").grid(row=4, column=0, sticky="w", pady=3)
        self.output_entry = ttk.Entry(frame, textvariable=self.output_var)
        self.output_entry.grid(row=4, column=1, sticky="ew", padx=6)
        self.browse_output = ttk.Button(frame, text="Browse...", command=self.choose_output)
        self.browse_output.grid(row=4, column=2)

        options = ttk.Frame(frame)
        options.grid(row=5, column=1, columnspan=2, sticky="w", padx=6, pady=6)
        ttk.Label(options, text="Compression").pack(side="left")
        methods = list(COMPRESSION_METHODS.values())
        self.compress_check = ttk.Combobox(options, textvariable=self.compress_var, values=methods,
                                           state="readonly", width=max(len(m) for m in methods))
        self.compress_check.pack(side="left", padx=4)
        ttk.Label(options, text="Level").pack(side="left")
        self.level_spin = ttk.Spinbox(options, from_=LZ4HC_LEVEL_MIN, to=LZ4HC_LEVEL_MAX,
                                      textvariable=self.level_var, width=3, state="readonly")
        self.level_spin.pack(side="left", padx=4)
        self.compress_check.bind("<<ComboboxSelected>>", self.on_compress_choice)
        self.on_compress_choice()
        ttk.Label(options, text="     Processes").pack(side="left")
        self.workers_spin = ttk.Spinbox(options, from_=1, to=max(1, os.cpu_count() or 1),
                                        textvariable=self.workers_var, width=4)
        self.workers_spin.pack(side="left", padx=4)
        self.dedup_check = ttk.Checkbutton(options, text="Store identical files once",
                                           variable=self.dedup_var)
        self.dedup_check.pack(side="left", padx=(12, 0))

        ttk.Label(frame, textvariable=self.summary_var).grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 2))
        list_frame = ttk.Frame(frame)
        list_frame.grid(row=7, column=0, columnspan=3, sticky="nsew")
        self.file_list = tk.Listbox(list_frame, activestyle="none", font="TkFixedFont")
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_list.yview)
        self.file_list.configure(yscrollcommand=scroll.set)
        self.file_list.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.progress = ttk.Progressbar(frame, maximum=1000)
        self.progress.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(10, 2))
        ttk.Label(frame, textvariable=self.status_var).grid(row=9, column=0, columnspan=3, sticky="w")
        buttons = ttk.Frame(frame)
        buttons.grid(row=10, column=0, columnspan=3, sticky="e", pady=(8, 0))
        self.pack_button = ttk.Button(buttons, text="Pack", command=self.start_pack)
        self.pack_button.pack(side="left", padx=4)
        self.cancel_button = ttk.Button(buttons, text="Cancel", state="disabled", command=self.cancel_pack)
        self.cancel_button.pack(side="left")

        self.key_box.bind("<<ComboboxSelected>>", self.on_key_choice)
        self.source_entry.bind("<Return>", self.load_folder)
        self.source_entry.bind("<FocusOut>", self.load_folder)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.on_key_choice()
        self.load_folder()

    # Settings

    def on_key_choice(self, _=None):
        choice = self.key_choice.get()
        entry = _game_key(choice)
        if entry:
            self.low_var.set(f"{entry[1]:08X}")
            self.high_var.set(f"{entry[2]:08X}")
            self.key_info.set(entry[3])
            state = "readonly"
        elif choice == BLANK_KEY:
            self.low_var.set("00000000")
            self.high_var.set("00000000")
            self.key_info.set("The archive is not encrypted. The game only mounts the archives "
                              "listed above, each with its own key, so this needs a modified game.")
            state = "readonly"
        else:
            self.key_info.set("Two 32-bit hex values, as in the game's key table "
                              "(PatchX02.dta is Low A0A0A0A3, High A0A0A0A0).")
            state = "normal"
        self.low_entry.configure(state=state)
        self.high_entry.configure(state=state)
        self.suggest_output()

    def suggest_output(self):
        """Names the output after the chosen archive, next to the source folder, until the
        user picks a name."""
        current = self.output_var.get().strip()
        if current and current != self.suggested:
            return
        entry = _game_key(self.key_choice.get())
        if entry is None and current:
            return
        if current:
            directory = os.path.dirname(current)
        else:
            folder = self.source_var.get().strip()
            if not folder:
                return
            directory = os.path.dirname(os.path.abspath(folder))
        self.suggested = os.path.join(directory, entry[0] if entry else "Custom.dta")
        self.output_var.set(self.suggested)

    def output_path(self) -> str:
        output = self.output_var.get().strip()
        return os.path.abspath(output) if output else ""

    def current_key(self) -> int:
        try:
            return make_key(_parse_hex32(self.low_var.get()), _parse_hex32(self.high_var.get()))
        except ValueError:
            raise PackError("The key must be two 32-bit hex values (up to 8 digits each).")

    # Files

    def show_files(self, files):
        self.files = files
        self.file_list.delete(0, "end")
        total = sum(f.size for f in files)
        self.summary_var.set(f"{len(files):,} files, {_format_size(total)}, stored as:")
        for f in files:
            self.file_list.insert("end", f.display_name)

    def load_folder(self, _=None):
        """Lists the files of the source folder (again when it changed)."""
        folder = self.source_var.get().strip()
        if folder == self.loaded:
            return
        self.loaded = folder
        self.files = []
        self.file_list.delete(0, "end")
        if not folder:
            self.summary_var.set("Choose the folder whose contents go into the archive.")
            return
        self.suggest_output()
        output = self.output_path()
        try:
            self.show_files(collect_files(folder, exclude=[output, output + ".part"] if output else []))
        except PackError as error:
            self.summary_var.set("The folder cannot be packed as it is:")
            for line in str(error).splitlines()[1:] or [str(error)]:
                self.file_list.insert("end", line)

    def choose_source(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory(parent=self.root, title="Folder to pack", mustexist=True,
                                         initialdir=self.source_var.get() or None)
        if folder:
            self.source_var.set(os.path.normpath(folder))
            self.load_folder()

    def choose_output(self):
        from tkinter import filedialog
        current = self.output_var.get().strip()
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Save archive as", defaultextension=".dta",
            filetypes=[("HD2 archives", "*.dta"), ("All files", "*.*")],
            initialdir=os.path.dirname(current) if current else None,
            initialfile=os.path.basename(current) if current else "")
        if path:
            self.output_var.set(os.path.normpath(path))
            self.suggested = ""
            self.confirmed = self.output_path()   # the dialog asked about replacing it

    # Packing

    def compress_method(self) -> str:
        choice = self.compress_var.get()
        return next((name for name, text in COMPRESSION_METHODS.items() if text == choice), "lzss")

    def on_compress_choice(self, _=None):
        """The level only applies to LZ4 HC."""
        self.level_spin.configure(state="readonly" if self.compress_method() == "lz4hc" else "disabled")

    def set_busy(self, busy: bool):
        for widget in (self.source_entry, self.browse_source, self.output_entry, self.browse_output,
                       self.compress_check, self.workers_spin, self.dedup_check, self.pack_button):
            widget.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy else "disabled")
        if busy:
            for widget in (self.key_box, self.low_entry, self.high_entry, self.level_spin):
                widget.configure(state="disabled")
        else:
            self.key_box.configure(state="readonly")
            self.compress_check.configure(state="readonly")
            self.on_compress_choice()
            self.on_key_choice()

    def start_pack(self):
        from tkinter import messagebox
        try:
            folder = self.source_var.get().strip()
            output = self.output_path()
            if not folder:
                raise PackError("Choose the folder to pack.")
            if not output:
                raise PackError("Choose where to save the archive.")
            key = self.current_key()
            self.loaded = folder
            files = collect_files(folder, exclude=[output, output + ".part"])
            self.show_files(files)
            workers = int(self.workers_var.get())
        except PackError as error:
            messagebox.showerror("DTA Packer", str(error), parent=self.root)
            return
        except (ValueError, self.tk.TclError):
            messagebox.showerror("DTA Packer", "The number of processes must be a whole number.",
                                 parent=self.root)
            return
        if os.path.exists(output) and os.path.normcase(output) != os.path.normcase(self.confirmed):
            if not messagebox.askyesno("DTA Packer", f"{output} exists. Replace it?", parent=self.root):
                return

        self.cancel = threading.Event()
        self.set_busy(True)
        self.progress["value"] = 0
        self.status_var.set("Starting...")
        dedup = self.dedup_var.get()
        compress = self.compress_method()
        level = int(self.level_var.get())

        def report(done, total, name):
            self.messages.put(("progress", done, total, name))

        def work():
            try:
                result = pack_files(files, output, key, compress, workers, report, self.cancel, dedup,
                                    level)
                self.messages.put(("done", result, output))
            except PackCancelled:
                self.messages.put(("cancelled",))
            except PackError as error:
                self.messages.put(("error", str(error)))
            except Exception as error:
                self.messages.put(("error", f"{type(error).__name__}: {error}"))

        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()
        self.root.after(100, self.poll)

    def poll(self):
        """Shows the packing thread's progress; it cannot touch the widgets itself."""
        from tkinter import messagebox
        progress = None
        finished = None
        while True:
            try:
                message = self.messages.get_nowait()
            except queue.Empty:
                break
            if message[0] == "progress":
                progress = message
            else:
                finished = message
        if progress:
            _, done, total, name = progress
            self.progress["value"] = 1000 * done / total if total else 1000
            self.status_var.set(f"{_format_size(done)} of {_format_size(total)}   {name}")
        if finished is None:
            self.root.after(100, self.poll)
            return

        self.thread = None
        self.set_busy(False)
        if finished[0] == "done":
            result, output = finished[1], finished[2]
            self.progress["value"] = 1000
            ratio = 100 * result["archive_size"] / result["input_size"] if result["input_size"] else 100
            self.status_var.set(f"Packed {result['files']:,} files into {_format_size(result['archive_size'])} "
                                f"({ratio:.0f}%) in {result['seconds']:.1f} s.")
            if result["duplicates"]:
                self.status_var.set(self.status_var.get() + f" {result['duplicates']:,} duplicate files "
                                    f"({_format_size(result['duplicate_size'])}) stored once.")
            messagebox.showinfo("DTA Packer", f"Created {output}\n\n{self.status_var.get()}", parent=self.root)
        elif finished[0] == "cancelled":
            self.progress["value"] = 0
            self.status_var.set("Cancelled; no archive was written.")
        else:
            self.progress["value"] = 0
            self.status_var.set("Failed; no archive was written.")
            messagebox.showerror("DTA Packer", finished[1], parent=self.root)

    def cancel_pack(self):
        if self.cancel is not None:
            self.cancel.set()
            self.status_var.set("Cancelling...")

    def on_close(self):
        from tkinter import messagebox
        if self.thread is not None and self.thread.is_alive():
            if not messagebox.askyesno("DTA Packer", "Packing is still running. Stop it and quit?",
                                       parent=self.root):
                return
            self.cancel.set()
            self.thread.join()
        self.root.destroy()


def run_gui():
    import tkinter as tk
    root = tk.Tk()
    PackerWindow(root)
    root.mainloop()


# Command line --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Packs a folder into a Hidden & Dangerous 2 .dta archive. "
                    "Without arguments, opens the window.")
    parser.add_argument("folder", help="the folder to pack; names are relative to it")
    parser.add_argument("output", help="the archive to write")
    parser.add_argument("--key", default="PatchX02.dta",
                        help="a game archive's name (PatchX02.dta, Patch.dta, ...), 'blank', "
                             "or LOW:HIGH as two 32-bit hex values (default: PatchX02.dta)")
    parser.add_argument("--compression", choices=list(COMPRESSION_METHODS), default="lzss",
                        help="lzss (default: read by every rw_data.dll), lz4 (fast to decode, but "
                             "only the rw_data.dll port reads it), lz4hc (the same LZ4 blocks, "
                             "smaller but slower to pack) or none")
    parser.add_argument("--level", type=int, default=LZ4HC_LEVEL_DEFAULT,
                        choices=range(LZ4HC_LEVEL_MIN, LZ4HC_LEVEL_MAX + 1), metavar="3..12",
                        help=f"LZ4 HC level: 3..9 hash chains, 10..12 optimal parsing (smallest, "
                             f"slowest; default: {LZ4HC_LEVEL_DEFAULT})")
    parser.add_argument("--store", action="store_true", help="do not compress (same as --compression none)")
    parser.add_argument("--workers", type=int, default=0, help="compression processes (default: all CPUs)")
    parser.add_argument("--no-dedup", action="store_true",
                        help="store files with the same contents separately (by default they "
                             "share one copy of the data)")
    args = parser.parse_args(argv)
    try:
        key = parse_key(args.key)
    except ValueError as error:
        parser.error(str(error))
    output = os.path.abspath(args.output)
    try:
        files = collect_files(args.folder, exclude=[output, output + ".part"])
        last = [0.0]

        def report(done, total, name):
            now = time.monotonic()
            if now - last[0] >= 0.5 or done == total:
                last[0] = now
                print(f"\r{100 * done / total if total else 100:5.1f}%  {name[:60]:<60}", end="", flush=True)

        method = "none" if args.store else args.compression
        result = pack_files(files, output, key, method, args.workers, report, dedup=not args.no_dedup,
                            level=args.level)
    except PackError as error:
        print(f"\nerror: {error}", file=sys.stderr)
        return 1
    print(f"\nPacked {result['files']:,} files ({_format_size(result['input_size'])}) into {output} "
          f"({_format_size(result['archive_size'])}) in {result['seconds']:.1f} s")
    if result["duplicates"]:
        print(f"{result['duplicates']:,} files ({_format_size(result['duplicate_size'])}) were identical "
              f"to another file and share its data")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1:
        sys.exit(main())
    run_gui()
