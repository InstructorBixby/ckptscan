"""`.npy` and `.npz`.

An `.npy` file is a header plus raw bytes, and raw bytes are not
executable. Except: if the dtype is `object`, the array's contents are
a *pickle*, and `numpy.load` will only read it when you pass
`allow_pickle=True`. So the question for a `.npy` is exactly one
question -- is this an object array -- and the answer is in the header
dict, which is a Python literal.

The header is parsed with `ast.literal_eval`, not `eval`. A header is
attacker-controlled and `eval` on it would be the same bug this whole
tool exists to find, in the tool.

Rules:
  CKPT-005  an object-dtype array; loading needs allow_pickle=True and
            then executes the pickle inside
"""
from __future__ import annotations

import ast
import struct

from ckptscan.analysers import pickles
from ckptscan.findings import Finding, Severity


class HeaderError(Exception):
    pass


def read_header(data: bytes) -> tuple[dict, int]:
    """(header dict, offset of the array data)."""
    if not data.startswith(b"\x93NUMPY"):
        raise HeaderError("not an npy file")
    major = data[6]
    if major == 1:
        (n,) = struct.unpack("<H", data[8:10])
        start = 10
    elif major in (2, 3):
        (n,) = struct.unpack("<I", data[8:12])
        start = 12
    else:
        raise HeaderError(f"npy format version {major} not understood")
    raw = data[start:start + n]
    try:
        text = raw.decode("latin-1" if major < 3 else "utf-8")
        header = ast.literal_eval(text.strip())
    except (ValueError, SyntaxError) as exc:
        raise HeaderError(f"header is not a literal: {exc}") from exc
    if not isinstance(header, dict):
        raise HeaderError("header is not a dict")
    return header, start + n


def _is_object_dtype(descr) -> bool:
    if isinstance(descr, str):
        return descr.lstrip("<>=|").startswith("O")
    if isinstance(descr, (list, tuple)):
        return any(_is_object_dtype(d[1] if isinstance(d, (list, tuple))
                                    and len(d) > 1 else d)
                   for d in descr)
    return False


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    try:
        header, offset = read_header(data)
    except HeaderError as exc:
        return [Finding(
            rule="CKPT-004", severity=Severity.LOW, path=path,
            location=location, message=str(exc))]

    if not _is_object_dtype(header.get("descr")):
        return []

    out = [Finding(
        rule="CKPT-005", severity=Severity.HIGH, path=path,
        location=location,
        message=("object-dtype array: the contents are a pickle, and "
                 "`numpy.load(..., allow_pickle=True)` executes it. "
                 "An array of numbers never needs this."),
        detail={"descr": str(header.get("descr")),
                "shape": str(header.get("shape"))})]
    # The pickle is right there. Analysing it turns "this needs
    # allow_pickle" into "this needs allow_pickle and calls os.system",
    # which is a different conversation with whoever shipped it.
    out.extend(pickles.analyse(
        data[offset:], path=path,
        location=f"{location} object payload".strip()))
    return out
