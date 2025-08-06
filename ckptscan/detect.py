"""What kind of file is this, according to its bytes.

The extension is a hint and nothing more. A `.bin` is a zip archive
about half the time and a bare pickle the rest; a `.pt` can be either;
a `.safetensors` that is actually a pickle is a reasonable thing for an
attacker to try, because the name is the whole basis on which a loader
-- or a reviewer -- decided it was safe.

So: sniff, and report the disagreement separately.
"""
from __future__ import annotations

import struct
from pathlib import Path

ZIP = "zip"
PICKLE = "pickle"
TORCH_LEGACY = "torch-legacy"
NPY = "npy"
NPZ = "npz"
HDF5 = "hdf5"
SAFETENSORS = "safetensors"
GGUF = "gguf"
ONNX = "onnx"
UNKNOWN = "unknown"

#: What an extension claims the file is.
BY_SUFFIX = {
    ".pt": ZIP, ".pth": ZIP, ".ckpt": ZIP, ".bin": PICKLE,
    ".pkl": PICKLE, ".pickle": PICKLE, ".joblib": PICKLE,
    ".npy": NPY, ".npz": NPZ,
    ".h5": HDF5, ".hdf5": HDF5, ".keras": ZIP,
    ".safetensors": SAFETENSORS, ".gguf": GGUF, ".onnx": ONNX,
}

# The legacy torch format is a pickle stream whose first object is a
# magic number. Protocol 2 header, then LONG1 with ten bytes.
TORCH_MAGIC = 0x1950A86A20F9469CFC6C
_LEGACY_PREFIX = b"\x80\x02\x8a\x0a" + TORCH_MAGIC.to_bytes(10, "little")


def sniff(data: bytes, *, name: str = "") -> str:
    """Format according to the bytes. `name` only breaks zip ties."""
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return NPZ if name.endswith(".npz") else ZIP
    if data.startswith(_LEGACY_PREFIX):
        return TORCH_LEGACY
    if data.startswith(b"\x93NUMPY"):
        return NPY
    if data.startswith(b"\x89HDF\r\n\x1a\n"):
        return HDF5
    if data.startswith(b"GGUF"):
        return GGUF
    if _looks_safetensors(data):
        return SAFETENSORS
    if _looks_pickle(data):
        return PICKLE
    if _looks_onnx(data):
        return ONNX
    return UNKNOWN


def _looks_safetensors(data: bytes) -> bool:
    """8-byte little-endian header length, then a JSON object."""
    if len(data) < 9:
        return False
    (n,) = struct.unpack("<Q", data[:8])
    if not 2 <= n <= 100_000_000 or 8 + n > len(data) + 1:
        return False
    return data[8:9] == b"{"


def _looks_pickle(data: bytes) -> bool:
    if not data:
        return False
    if data[0] == 0x80 and len(data) > 1 and data[1] <= 5:
        return True
    # Protocol 0 and 1 have no header. These are the opcodes a stream
    # realistically opens with; a false positive here only costs a
    # pickle parse that then fails cleanly.
    return data[0:1] in (b"(", b"]", b"}", b"c", b"]", b"K", b"\x28")


def _looks_onnx(data: bytes) -> bool:
    """A protobuf with field 1 (ir_version) as a varint, usually.

    There is no magic number for ONNX, so this is weak on purpose and
    the extension does most of the work. Field 1, wire type 0 is byte
    0x08, and the graph is field 7 (0x3a) somewhere early.
    """
    return data.startswith(b"\x08") and b"\x3a" in data[:256]


def declared(path: str | Path) -> str:
    return BY_SUFFIX.get(Path(path).suffix.lower(), UNKNOWN)


#: Formats that are, as far as this tool is concerned, the same shape.
EQUIVALENT = {
    frozenset({ZIP, PICKLE}),        # .pt and .bin are both, in practice
    frozenset({ZIP, NPZ}),           # an npz IS a zip
}


def agrees(claimed: str, actual: str) -> bool:
    if claimed == actual or UNKNOWN in (claimed, actual):
        return True
    return frozenset({claimed, actual}) in EQUIVALENT
