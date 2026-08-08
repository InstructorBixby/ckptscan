"""The pre-zip torch format.

One file, several pickle streams concatenated: a magic number, a
protocol-version dict, the system info, then the object graph, then
storage keys. `pickletools.genops` stops at the first `STOP`, so
analysing the file as a single stream reads the magic number and
nothing else -- which looks perfectly clean and misses the entire
payload.

So: parse a stream, note where it ended, seek there, parse again.
"""
from __future__ import annotations

import io

from ckptscan import opcodes
from ckptscan.analysers import pickles
from ckptscan.findings import Finding
from ckptscan.registry import default_severity as sev

MAX_STREAMS = 64
_STARTS = (b"\x80", b"(", b"c", b"]", b"}", b"K")


def streams(fh) -> list:
    """[(offset, Stream)] for each concatenated pickle."""
    out = []
    while len(out) < MAX_STREAMS:
        start = fh.tell()
        probe = fh.read(1)
        if not probe:
            break
        if probe not in _STARTS:
            # Storage data sits after the streams in this format.
            break
        fh.seek(start)
        try:
            stream = opcodes.parse(fh)
        except opcodes.ParseError:
            break
        out.append((start, stream))
        if stream.truncated or not stream.end:
            break
        fh.seek(start + stream.end)
    return out


def analyse(data, *, path: str, location: str = "", extra=None,
            strict: bool = False) -> list:
    fh = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) \
        else data
    fh.seek(0)
    found = streams(fh)
    if not found:
        return [Finding(
            rule="CKPT-004", severity=sev("CKPT-004"), path=path,
            location=location,
            message="legacy torch file contained no parseable pickle "
                    "stream")]
    out = []
    for index, (offset, stream) in enumerate(found):
        where = f"{location}stream {index} @{offset}" if location \
            else f"stream {index} @{offset}"
        out.extend(pickles.from_stream(stream, path=path,
                                       location=where, extra=extra,
                                       strict=strict))
    return out


def split(data: bytes) -> list:
    """Byte ranges of each stream. Kept for the tests and for tooling."""
    fh = io.BytesIO(data)
    return [(offset, data[offset:offset + (stream.end or 1)])
            for offset, stream in streams(fh)]
