"""Minimal HPACK (RFC 7541) for the referee's h2c prober.

Encoder: literal header field *without* indexing, never Huffman. Always legal,
and it keeps the encoder's dynamic table empty so nothing can desync.

Decoder: indexed fields, all three literal forms, and dynamic table size
updates. Huffman-coded *values* are not decoded — see HUFFMAN_LIMITATION in
docs/OPERATIONS.md. The entry is still inserted into the dynamic table (with a
None value) so subsequent indices stay in sync, and the probe falls back to
judging the response by its framing and body.
"""
from __future__ import annotations

STATIC = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"),
    (":status", "200"), (":status", "204"), (":status", "206"), (":status", "304"),
    (":status", "400"), (":status", "404"), (":status", "500"),
    ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""), ("accept-ranges", ""), ("accept", ""),
    ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""),
    ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
    ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
    ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""),
    ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
]
NAME_INDEX = {}
for _i, (_n, _v) in enumerate(STATIC, start=1):
    NAME_INDEX.setdefault(_n, _i)


class HpackError(ValueError):
    pass


def _int_encode(value: int, prefix_bits: int, flags: int) -> bytes:
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([flags | value])
    out = bytearray([flags | limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _int_decode(buf: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    limit = (1 << prefix_bits) - 1
    value = buf[pos] & limit
    pos += 1
    if value < limit:
        return value, pos
    shift = 0
    while True:
        if pos >= len(buf):
            raise HpackError("truncated integer")
        byte = buf[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos
        if shift > 28:
            raise HpackError("integer overflow")


def _str_encode(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _int_encode(len(raw), 7, 0x00) + raw     # H=0, no Huffman


def _str_decode(buf: bytes, pos: int) -> tuple[str | None, int]:
    huffman = bool(buf[pos] & 0x80)
    length, pos = _int_decode(buf, pos, 7)
    if pos + length > len(buf):
        raise HpackError("truncated string")
    raw = buf[pos:pos + length]
    pos += length
    if huffman:
        return None, pos                            # see module docstring
    return raw.decode("utf-8", "replace"), pos


def encode(headers: list[tuple[str, str]]) -> bytes:
    out = bytearray()
    for name, value in headers:
        name = name.lower()
        idx = NAME_INDEX.get(name)
        if idx:
            out += _int_encode(idx, 4, 0x00)        # literal, no indexing, indexed name
        else:
            out += b"\x00" + _str_encode(name)
        out += _str_encode(value)
    return bytes(out)


MAX_TABLE_SIZE = 1 << 16        # the peer cannot talk us into a huge table


class Decoder:
    """One decoder per connection — the dynamic table is connection state."""

    def __init__(self, max_size: int = 4096):
        self.max_size = min(max_size, MAX_TABLE_SIZE)
        self.table: list[tuple[str, str | None]] = []

    def _lookup(self, index: int) -> tuple[str, str | None]:
        if index == 0:
            raise HpackError("index 0 is illegal")
        if index <= len(STATIC):
            return STATIC[index - 1]
        offset = index - len(STATIC) - 1
        if offset >= len(self.table):
            raise HpackError(f"index {index} out of range")
        return self.table[offset]

    def _insert(self, name: str, value: str | None) -> None:
        self.table.insert(0, (name, value))
        # Evict by RFC 7541 §4.1 sizing (32 bytes overhead per entry).
        size = sum(len(n) + len(v or "") + 32 for n, v in self.table)
        while size > self.max_size and self.table:
            n, v = self.table.pop()
            size -= len(n) + len(v or "") + 32

    def decode(self, block: bytes) -> list[tuple[str, str | None]]:
        out: list[tuple[str, str | None]] = []
        pos = 0
        while pos < len(block):
            byte = block[pos]
            if byte & 0x80:                                   # indexed field
                index, pos = _int_decode(block, pos, 7)
                out.append(self._lookup(index))
            elif byte & 0x40:                                 # literal, incremental indexing
                index, pos = _int_decode(block, pos, 6)
                if index:
                    name = self._lookup(index)[0]
                else:
                    name, pos = _str_decode(block, pos)
                value, pos = _str_decode(block, pos)
                self._insert(name or "", value)
                out.append((name or "", value))
            elif byte & 0x20:                                 # dynamic table size update
                requested, pos = _int_decode(block, pos, 5)
                # The peer picks this number. Honouring it unclamped lets a
                # hostile service ask for a gigabyte-sized table and then
                # fill it — the decoder is parsing attacker bytes.
                self.max_size = min(requested, MAX_TABLE_SIZE)
                self._insert_noop()
            else:                                             # literal, never/without indexing
                index, pos = _int_decode(block, pos, 4)
                if index:
                    name = self._lookup(index)[0]
                else:
                    name, pos = _str_decode(block, pos)
                value, pos = _str_decode(block, pos)
                out.append((name or "", value))
        return out

    def _insert_noop(self) -> None:
        size = sum(len(n) + len(v or "") + 32 for n, v in self.table)
        while size > self.max_size and self.table:
            n, v = self.table.pop()
            size -= len(n) + len(v or "") + 32
