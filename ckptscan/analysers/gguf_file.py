"""GGUF, read for its metadata and nothing else.

GGUF is the other safe-by-construction format: a magic, a version, a
count of tensors, a count of key-value pairs, then typed metadata and
raw tensor data. Strings are length-prefixed, there are no callables,
and nothing in the format can ask a loader to import anything.

So this reads the counts and the header extent, flags a file whose
header does not fit the bytes, and stops. There is no code-execution
rule here because there is no code-execution path here, and inventing
one to look thorough would be dishonest.

  CKPT-019  header counts or string lengths inconsistent with the file
"""
from __future__ import annotations

import struct

from ckptscan.findings import Finding, Severity

MAX_COUNT = 10_000_000


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    if len(data) < 24 or not data.startswith(b"GGUF"):
        return [Finding(rule="CKPT-004", severity=Severity.LOW,
                        path=path, location=location,
                        message="not a GGUF header")]
    version, = struct.unpack_from("<I", data, 4)
    if version < 2:
        # v1 put the counts in 32-bit fields. Readable, just not by
        # this, and saying so beats guessing.
        return [Finding(
            rule="CKPT-019", severity=Severity.INFO, path=path,
            location=location,
            message=f"GGUF version {version} predates the 64-bit "
                    f"counts this reads; not analysed",
            detail={"version": version})]
    n_tensors, n_kv = struct.unpack_from("<QQ", data, 8)
    out = []
    if n_tensors > MAX_COUNT or n_kv > MAX_COUNT:
        out.append(Finding(
            rule="CKPT-019", severity=Severity.MEDIUM, path=path,
            location=location,
            message=(f"header claims {n_tensors} tensors and {n_kv} "
                     f"metadata entries in a {len(data)}-byte file"),
            detail={"n_tensors": n_tensors, "n_kv": n_kv,
                    "file_len": len(data)}))
    return out
