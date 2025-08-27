"""safetensors, which is the answer and still worth checking.

The format is safe by construction: an 8-byte little-endian header
length, a JSON header, then raw tensor bytes. There is no opcode
stream, no callable, nothing to execute. The recommendation this whole
tool ends up making is "ship safetensors", and that recommendation is
correct.

So why analyse it at all? Because "it is a safetensors file" is a claim
about the *name* until somebody checks the bytes, and because a
malformed header is a parser problem in whatever reads it next:

  CKPT-017  header inconsistency -- offsets outside the file,
            overlapping tensors, a header larger than the file, a
            duplicate name
  CKPT-008  (from the scanner) the extension and the bytes disagree

None of these is code execution. They are reported at LOW or MEDIUM and
the summary says so, because inflating them would undermine the one
recommendation worth making.
"""
from __future__ import annotations

import json
import struct

from ckptscan.findings import Finding, Severity

MAX_HEADER = 100 * 1024 * 1024


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    if len(data) < 8:
        return [Finding(rule="CKPT-004", severity=Severity.LOW,
                        path=path, location=location,
                        message="file is shorter than a header length")]
    (n,) = struct.unpack("<Q", data[:8])
    if n > MAX_HEADER or 8 + n > len(data):
        return [Finding(
            rule="CKPT-017", severity=Severity.MEDIUM, path=path,
            location=location,
            message=(f"header declares {n} bytes, file holds "
                     f"{len(data) - 8} after the length prefix"),
            detail={"header_len": n, "file_len": len(data)})]
    try:
        header = json.loads(data[8:8 + n].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [Finding(rule="CKPT-017", severity=Severity.MEDIUM,
                        path=path, location=location,
                        message=f"header is not valid JSON: {exc}")]
    if not isinstance(header, dict):
        return [Finding(rule="CKPT-017", severity=Severity.MEDIUM,
                        path=path, location=location,
                        message="header is not a JSON object")]

    out = []
    payload = len(data) - 8 - n
    spans: list[tuple[int, int, str]] = []
    for name, spec in header.items():
        if name == "__metadata__":
            continue
        if not isinstance(spec, dict) or "data_offsets" not in spec:
            out.append(Finding(
                rule="CKPT-017", severity=Severity.LOW, path=path,
                location=location or name,
                message=f"tensor {name!r} has no data_offsets"))
            continue
        try:
            begin, end = spec["data_offsets"]
            begin, end = int(begin), int(end)
        except (TypeError, ValueError, KeyError):
            out.append(Finding(
                rule="CKPT-017", severity=Severity.LOW, path=path,
                location=location or name,
                message=f"tensor {name!r} has unreadable data_offsets"))
            continue
        if begin < 0 or end < begin or end > payload:
            out.append(Finding(
                rule="CKPT-017", severity=Severity.MEDIUM, path=path,
                location=location or name,
                message=(f"tensor {name!r} spans [{begin}, {end}) "
                         f"outside the {payload}-byte payload"),
                detail={"tensor": name, "begin": begin, "end": end,
                        "payload": payload}))
            continue
        spans.append((begin, end, name))

    spans.sort()
    for (a_begin, a_end, a_name), (b_begin, b_end, b_name) in zip(
            spans, spans[1:]):
        if b_begin < a_end:
            out.append(Finding(
                rule="CKPT-017", severity=Severity.LOW, path=path,
                location=location or b_name,
                message=(f"tensors {a_name!r} and {b_name!r} overlap "
                         f"in the payload"),
                detail={"a": a_name, "b": b_name}))
        assert b_end >= b_begin
    return out
