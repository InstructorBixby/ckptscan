"""joblib, which is a pickle with extra steps.

`joblib.dump` writes a pickle, optionally compressed, optionally with
numpy arrays stored out of band. The compressed variants start with a
zlib, gzip, bz2, lzma or lz4 magic rather than a pickle opcode, so a
format sniff says "unknown" and the file is skipped -- which is exactly
wrong for a format whose whole purpose is `sklearn` model
distribution.

So: decompress in memory, with a hard output cap, and hand the result
to the pickle analyser.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import zlib

from ckptscan.analysers import pickles
from ckptscan.findings import Finding, Severity

MAX_OUT = 256 * 1024 * 1024

MAGICS = [
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bz2"),
    (b"\xfd7zXZ", "xz"),
    (b"\x78\x01", "zlib"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
    (b"ZF", "joblib-zfile"),
]


def compression_of(data: bytes) -> str:
    for magic, name in MAGICS:
        if data.startswith(magic):
            return name
    return ""


def _inflate(data: bytes, kind: str) -> bytes:
    if kind == "gzip":
        return gzip.decompress(data)[:MAX_OUT]
    if kind == "bz2":
        return bz2.decompress(data)[:MAX_OUT]
    if kind == "xz":
        return lzma.decompress(data)[:MAX_OUT]
    if kind == "zlib":
        return zlib.decompressobj().decompress(data, MAX_OUT)
    if kind == "joblib-zfile":
        # joblib's own container: 'ZF' then a decimal length then a
        # zlib stream.
        rest = data[2:]
        i = 0
        while i < len(rest) and rest[i:i + 1].isdigit():
            i += 1
        return zlib.decompressobj().decompress(rest[i:], MAX_OUT)
    return b""


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    kind = compression_of(data)
    if not kind:
        return pickles.analyse(data, path=path, location=location)
    try:
        body = _inflate(data, kind)
    except (OSError, zlib.error, lzma.LZMAError, ValueError) as exc:
        return [Finding(
            rule="CKPT-004", severity=Severity.LOW, path=path,
            location=location,
            message=f"{kind} container did not decompress: {exc}")]
    if not body:
        return [Finding(
            rule="CKPT-004", severity=Severity.LOW, path=path,
            location=location,
            message=f"{kind} container decompressed to nothing")]
    return pickles.analyse(
        body, path=path,
        location=f"{location} ({kind})".strip())
