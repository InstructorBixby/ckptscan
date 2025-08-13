"""The pre-zip torch format.

One file, several pickle streams concatenated: a magic number, a
protocol-version dict, the system info, then the object graph, then
storage keys. `pickletools.genops` stops at the first `STOP`, so
analysing the file as a single stream reads the magic number and
nothing else -- which looks perfectly clean and misses the entire
payload.

So: walk the streams. Find each `STOP` the parser reports and start
again after it, until the bytes run out.
"""
from __future__ import annotations

from ckptscan import opcodes
from ckptscan.analysers import pickles
from ckptscan.findings import Finding, Severity

MAX_STREAMS = 64


def split(data: bytes) -> list[tuple[int, bytes]]:
    """[(offset, stream bytes)] for each concatenated pickle."""
    out = []
    pos = 0
    while pos < len(data) and len(out) < MAX_STREAMS:
        try:
            stream = opcodes.parse(data[pos:])
        except opcodes.ParseError:
            break
        stops = [p for name, p in stream.opcodes if name == "STOP"]
        if not stops:
            out.append((pos, data[pos:]))
            break
        end = stops[-1] + 1
        out.append((pos, data[pos:pos + end]))
        if end <= 0:
            break
        pos += end
        # Trailing bytes that are not another pickle: storage data in
        # the old format sits after the streams.
        if pos < len(data) and data[pos] != 0x80 and \
                data[pos:pos + 1] not in (b"(", b"c", b"]", b"}"):
            break
    return out


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    streams = split(data)
    if not streams:
        return [Finding(
            rule="CKPT-004", severity=Severity.LOW, path=path,
            location=location,
            message="legacy torch file contained no parseable pickle "
                    "stream")]
    out = []
    for index, (offset, body) in enumerate(streams):
        where = f"{location}stream {index} @{offset}" if location \
            else f"stream {index} @{offset}"
        out.extend(pickles.analyse(body, path=path, location=where))
    return out
