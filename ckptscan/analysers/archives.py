"""A modern torch checkpoint is a zip archive.

`archive/data.pkl` holds the object graph; the tensors are raw storage
files beside it. So the analysis is: open the zip without extracting
anything, find the members that matter, and run the right analyser over
each -- as a stream, because a storage member is the size of the model.

Rules:
  CKPT-010  a pickle inside a nested archive
  CKPT-012  a zip member with an absolute or traversing path
  CKPT-014  a member whose declared size is implausible
"""
from __future__ import annotations

import io
import zipfile

from ckptscan import detect
from ckptscan.analysers import numpy_arrays, pickles
from ckptscan.findings import Finding, Severity
from ckptscan.registry import default_severity as sev

PICKLE_NAMES = {"data.pkl", "archive/data.pkl", "constants.pkl"}

MAX_WHOLE_MEMBER = 256 * 1024 * 1024
MAX_RATIO = 200
HEAD = 4096


def _is_pickleish(name: str, head: bytes) -> bool:
    base = name.rsplit("/", 1)[-1]
    if base in PICKLE_NAMES or name in PICKLE_NAMES:
        return True
    if base.endswith((".pkl", ".pickle")):
        return True
    return detect.sniff(head) in (detect.PICKLE, detect.TORCH_LEGACY)


def _open(data):
    if isinstance(data, (bytes, bytearray)):
        return zipfile.ZipFile(io.BytesIO(data))
    return zipfile.ZipFile(data)


def analyse(data, *, path: str, depth: int = 0, prefix: str = "",
            extra=None, strict: bool = False) -> list:
    out: list = []
    try:
        zf = _open(data)
    except zipfile.BadZipFile as exc:
        return [Finding(
            rule="CKPT-004", severity=sev("CKPT-004"), path=path,
            location=prefix, message=f"not a readable zip: {exc}")]

    with zf:
        for info in zf.infolist():
            name = info.filename
            where = f"{prefix}{name}" if prefix else name

            if name.startswith("/") or ".." in name.split("/"):
                out.append(Finding(
                    rule="CKPT-012", severity=sev("CKPT-012"),
                    path=path, location=where,
                    message=("archive member name escapes the archive "
                             "root; any loader that extracts rather "
                             "than streams will write outside it"),
                    detail={"member": name}))

            if info.is_dir():
                continue
            if (info.compress_size and
                    info.file_size / info.compress_size > MAX_RATIO):
                out.append(Finding(
                    rule="CKPT-014", severity=Severity.MEDIUM,
                    path=path, location=where,
                    message=(f"member expands "
                             f"{info.file_size // max(1, info.compress_size)}x; "
                             f"a loader that reads it whole may not "
                             f"survive it"),
                    detail={"member": name,
                            "file_size": info.file_size,
                            "compress_size": info.compress_size}))

            with zf.open(info) as fh:
                head = fh.read(HEAD)
                inner = detect.sniff(head, name=name)

                if _is_pickleish(name, head):
                    member = _Rewound(head, fh)
                    out.extend(pickles.analyse(
                        member, path=path, location=where,
                        extra=extra, strict=strict))
                    continue

                if info.file_size > MAX_WHOLE_MEMBER:
                    out.append(Finding(
                        rule="CKPT-014", severity=sev("CKPT-014"),
                        path=path, location=where,
                        message=(f"member declares {info.file_size} "
                                 f"bytes and this analysis needs it "
                                 f"whole; not read (limit "
                                 f"{MAX_WHOLE_MEMBER})"),
                        detail={"member": name,
                                "file_size": info.file_size}))
                    continue

                if inner == detect.NPY:
                    out.extend(numpy_arrays.analyse(
                        head + fh.read(MAX_WHOLE_MEMBER), path=path,
                        location=where, extra=extra, strict=strict))
                elif inner in (detect.ZIP, detect.NPZ):
                    if depth >= 3:
                        out.append(Finding(
                            rule="CKPT-010", severity=sev("CKPT-010"),
                            path=path, location=where,
                            message="archive nesting deeper than 3; "
                                    "not descending further"))
                        continue
                    body = head + fh.read(MAX_WHOLE_MEMBER)
                    nested = analyse(body, path=path, depth=depth + 1,
                                     prefix=f"{where}!", extra=extra,
                                     strict=strict)
                    if nested:
                        out.append(Finding(
                            rule="CKPT-010", severity=sev("CKPT-010"),
                            path=path, location=where,
                            message=("a nested archive inside this "
                                     "checkpoint contains findings of "
                                     "its own; there is no legitimate "
                                     "reason for a checkpoint to be "
                                     "wrapped this way"),
                            detail={"member": name,
                                    "nested_findings": len(nested)}))
                    out.extend(nested)
    return out


class _Rewound:
    """A stream with its first HEAD bytes pushed back on the front.

    Sniffing needs a look at the head and `ZipFile.open` does not
    seek, so the head is held and replayed. Constant memory, and the
    rest of the member is still read lazily.
    """

    def __init__(self, head: bytes, rest):
        self._buf = head
        self._rest = rest

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            out, self._buf = self._buf, b""
            return out + self._rest.read()
        if self._buf:
            out = self._buf[:n]
            self._buf = self._buf[len(out):]
            if len(out) == n:
                return out
            return out + self._rest.read(n - len(out))
        return self._rest.read(n)

    def readline(self) -> bytes:
        if self._buf:
            index = self._buf.find(b"\n")
            if index >= 0:
                out = self._buf[:index + 1]
                self._buf = self._buf[index + 1:]
                return out
            out, self._buf = self._buf, b""
            return out + self._rest.readline()
        return self._rest.readline()
