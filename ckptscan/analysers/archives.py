"""A modern torch checkpoint is a zip archive.

`archive/data.pkl` holds the object graph; the tensors are raw storage
files beside it. So the analysis is: open the zip without extracting
anything, find the members that matter, and run the right analyser over
each.

Two things that are not obvious:

- **A member's name is attacker-controlled.** An absolute path or a
  `..` segment in a zip is a classic extraction bug, and some loaders
  do extract. Reported as a finding whether or not the loader here
  would be affected, because this tool is read-only and the loader
  downstream is somebody else's.
- **An archive can contain an archive.** A `.pt` with a nested zip
  inside it holding the real pickle is not a hypothetical; it is what
  you build if you know a scanner only looks one level deep.

Rules:
  CKPT-010  a pickle inside a nested archive
  CKPT-012  a zip member with an absolute or traversing path
  CKPT-014  a member whose declared size is implausible for its
            compressed size
"""
from __future__ import annotations

import io
import zipfile

from ckptscan import detect
from ckptscan.analysers import numpy_arrays, pickles
from ckptscan.findings import Finding, Severity

#: Members worth parsing as a pickle regardless of what they are called.
PICKLE_NAMES = {"data.pkl", "archive/data.pkl", "constants.pkl"}

MAX_MEMBER = 256 * 1024 * 1024
MAX_RATIO = 200


def _is_pickleish(name: str, head: bytes) -> bool:
    base = name.rsplit("/", 1)[-1]
    if base in PICKLE_NAMES or name in PICKLE_NAMES:
        return True
    if base.endswith((".pkl", ".pickle")):
        return True
    return detect.sniff(head) in (detect.PICKLE, detect.TORCH_LEGACY)


def analyse(data: bytes, *, path: str, depth: int = 0,
            prefix: str = "") -> list:
    out: list = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return [Finding(
            rule="CKPT-004", severity=Severity.LOW, path=path,
            location=prefix, message=f"not a readable zip: {exc}")]

    with zf:
        for info in zf.infolist():
            name = info.filename
            where = f"{prefix}{name}" if prefix else name

            if name.startswith("/") or ".." in name.split("/"):
                out.append(Finding(
                    rule="CKPT-012", severity=Severity.HIGH, path=path,
                    location=where,
                    message=("archive member name escapes the archive "
                             "root; any loader that extracts rather "
                             "than streams will write outside it"),
                    detail={"member": name}))

            if info.file_size > MAX_MEMBER:
                out.append(Finding(
                    rule="CKPT-014", severity=Severity.LOW, path=path,
                    location=where,
                    message=(f"member declares {info.file_size} bytes; "
                             f"not read (limit {MAX_MEMBER})"),
                    detail={"member": name,
                            "file_size": info.file_size}))
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

            if info.is_dir():
                continue
            with zf.open(info) as fh:
                head = fh.read(4096)
                inner = detect.sniff(head, name=name)
                if _is_pickleish(name, head):
                    body = head + fh.read(MAX_MEMBER)
                    out.extend(pickles.analyse(body, path=path,
                                               location=where))
                elif inner == detect.NPY:
                    body = head + fh.read(MAX_MEMBER)
                    out.extend(numpy_arrays.analyse(
                        body, path=path, location=where))
                elif inner in (detect.ZIP, detect.NPZ):
                    body = head + fh.read(MAX_MEMBER)
                    if depth >= 3:
                        out.append(Finding(
                            rule="CKPT-010", severity=Severity.MEDIUM,
                            path=path, location=where,
                            message="archive nesting deeper than 3; "
                                    "not descending further"))
                        continue
                    nested = analyse(body, path=path, depth=depth + 1,
                                     prefix=f"{where}!")
                    if nested:
                        out.append(Finding(
                            rule="CKPT-010", severity=Severity.MEDIUM,
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
