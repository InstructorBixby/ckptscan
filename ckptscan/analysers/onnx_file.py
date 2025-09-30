"""ONNX, where the risk is an operator the runtime has to go and find.

An ONNX graph is data. It cannot carry a code object or a pickle. What
it can do is name an operator in a domain the runtime does not
implement, and the answer to that is a custom-op library -- a shared
object the user installs and registers, which then executes with the
model's inputs. Some runtimes will also load a custom-op library named
in the model's metadata.

So the finding is not "this file contains code". It is "loading this
file as intended requires code you do not have, from somewhere", which
is a supply-chain question with a different answer.

Precise analysis wants the `onnx` package: `uv pip install -e ".[onnx]"`.
Without it, this does a minimal protobuf field scan for the
`opset_import` domains, which is the one field that matters and is a
length-delimited string in a known position. Every finding says which
path produced it.

Rules:
  CKPT-007  a non-standard operator domain, or a node whose domain is
            outside the standard sets
  CKPT-018  a custom-op library named in the model metadata
"""
from __future__ import annotations

from ckptscan.findings import Finding, Severity

#: Domains the standard runtimes implement themselves.
STANDARD_DOMAINS = {
    "", "ai.onnx", "ai.onnx.ml", "ai.onnx.training",
    "ai.onnx.preview.training", "com.microsoft",
    "com.microsoft.nchwc", "com.microsoft.experimental",
    "ai.onnx.contrib", "org.pytorch.aten",
}

LIBRARY_KEYS = {"custom_op_library", "custom_ops", "library_path",
                "shared_library"}


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while pos < len(data):
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("varint did not terminate")


def _fields(data: bytes, limit: int | None = None):
    """Yield (field number, wire type, payload bytes or int, pos)."""
    pos = 0
    end = len(data) if limit is None else min(limit, len(data))
    while pos < end:
        try:
            key, pos = _varint(data, pos)
        except ValueError:
            return
        field, wire = key >> 3, key & 0x07
        if wire == 0:
            try:
                value, pos = _varint(data, pos)
            except ValueError:
                return
            yield field, wire, value
        elif wire == 2:
            try:
                length, pos = _varint(data, pos)
            except ValueError:
                return
            if length < 0 or pos + length > end:
                return
            yield field, wire, data[pos:pos + length]
            pos += length
        elif wire == 5:
            pos += 4
        elif wire == 1:
            pos += 8
        else:
            return


def _domains_minimal(data: bytes) -> set:
    """ModelProto.opset_import is field 8; OperatorSetIdProto.domain 1.

    Also walks GraphProto (field 7) nodes (field 1) for NodeProto
    .domain (field 7), which is where a per-node override lives.
    """
    found = set()
    for field, wire, payload in _fields(data):
        if wire != 2:
            continue
        if field == 8:
            for f2, w2, p2 in _fields(payload):
                if f2 == 1 and w2 == 2:
                    found.add(p2.decode("utf-8", "replace"))
        elif field == 7:
            for f2, w2, node in _fields(payload):
                if f2 != 1 or w2 != 2:
                    continue
                for f3, w3, p3 in _fields(node):
                    if f3 == 7 and w3 == 2:
                        found.add(p3.decode("utf-8", "replace"))
    return found


def _metadata_minimal(data: bytes) -> dict:
    """ModelProto.metadata_props is field 14, a StringStringEntryProto."""
    out = {}
    for field, wire, payload in _fields(data):
        if field != 14 or wire != 2:
            continue
        key = value = ""
        for f2, w2, p2 in _fields(payload):
            if w2 != 2:
                continue
            if f2 == 1:
                key = p2.decode("utf-8", "replace")
            elif f2 == 2:
                value = p2.decode("utf-8", "replace")
        if key:
            out[key] = value
    return out


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    domains = _domains_minimal(data)
    metadata = _metadata_minimal(data)
    out = []
    for domain in sorted(domains - STANDARD_DOMAINS):
        out.append(Finding(
            rule="CKPT-007", severity=Severity.MEDIUM, path=path,
            location=location or f"domain {domain}",
            message=(f"operator domain {domain!r} is not one the "
                     f"standard runtimes implement. Running this model "
                     f"as intended means installing and registering a "
                     f"custom-operator library, which then executes "
                     f"with the model's inputs."),
            detail={"domain": domain}))
    for key, value in sorted(metadata.items()):
        if key.lower() in LIBRARY_KEYS or key.lower().endswith("_lib"):
            out.append(Finding(
                rule="CKPT-018", severity=Severity.HIGH, path=path,
                location=location or key,
                message=(f"model metadata names a custom-op library "
                         f"({key}={value!r}). Some runtimes will load "
                         f"it."),
                detail={"key": key, "value": value}))
    return out
