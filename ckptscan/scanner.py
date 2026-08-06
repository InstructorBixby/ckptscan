"""Dispatch a path to the analysers that apply to it.

Three things matter here.

**The format comes from the bytes**, never the extension, and a
disagreement is itself a finding. Two honest exceptions: `.keras` and
`.pt` are both zips, so the member list decides; and ONNX is a bare
protobuf with no magic, so the extension is all there is.

**Nothing reads a whole file to look at its first kilobyte.** A sharded
checkpoint member is gigabytes of tensor data behind a few hundred
opcodes of structure.

**The posture travels with the scan.** A project-local allowlist and
`--strict` are passed down rather than read from a global, so a library
caller gets the same behaviour as the CLI and two scans with different
policies cannot interfere.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ckptscan import detect
from ckptscan.analysers import (archives, gguf_file, joblib_files,
                                keras_h5, keras_zip, numpy_arrays,
                                onnx_file, pickles, safetensors_file,
                                torch_legacy)
from ckptscan.findings import Finding, Severity
from ckptscan.registry import default_severity as sev

CANDIDATES = {
    ".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib",
    ".npy", ".npz", ".h5", ".hdf5", ".keras", ".safetensors",
    ".gguf", ".onnx", ".model", ".zip", ".sav", ".z",
}

COMPRESSED_SUFFIXES = {".joblib", ".sav", ".z", ".gz", ".bz2", ".xz"}

HEAD = 1024 * 1024
MAX_WHOLE_FILE = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class Posture:
    """How strict to be, and what this project allows locally."""
    extra: dict = field(default_factory=dict)
    strict: bool = False

    @classmethod
    def from_config(cls, cfg, *, strict: bool = False) -> "Posture":
        return cls(extra=dict(getattr(cfg, "allow", {}) or {}),
                   strict=strict)


DEFAULT = Posture()


def _mismatch(path: Path, claimed: str, actual: str) -> Finding:
    lying_about_safety = (
        claimed in (detect.SAFETENSORS, detect.GGUF, detect.ONNX)
        and actual in (detect.PICKLE, detect.TORCH_LEGACY, detect.ZIP))
    severity = Severity.HIGH if lying_about_safety else Severity.MEDIUM
    return Finding(
        rule="CKPT-008", severity=severity, path=str(path),
        message=(f"extension claims {claimed}, bytes say {actual}. "
                 f"The name is usually the only basis on which anyone "
                 f"decided this file was safe to load."),
        detail={"claimed": claimed, "actual": actual})


def _whole_file_analyser(head: bytes, actual: str):
    if actual in (detect.ZIP, detect.NPZ):
        if keras_zip.is_keras_archive(head):
            return keras_zip.analyse
        return archives.analyse
    return {
        detect.NPY: numpy_arrays.analyse,
        detect.SAFETENSORS: safetensors_file.analyse,
        detect.GGUF: gguf_file.analyse,
        detect.HDF5: keras_h5.analyse,
        detect.ONNX: onnx_file.analyse,
    }.get(actual)


#: Analysers that understand the posture arguments. The header readers
#: do not: there is no allowlist question in a safetensors header.
_TAKES_POSTURE = (pickles.analyse, torch_legacy.analyse,
                  archives.analyse, joblib_files.analyse,
                  numpy_arrays.analyse)


def _call(fn, data, *, path: str, posture: Posture) -> list:
    if fn in _TAKES_POSTURE:
        return fn(data, path=path, extra=posture.extra,
                  strict=posture.strict)
    return fn(data, path=path)


def scan_file(path: str | Path, *, posture: Posture | None = None,
              extra=None, strict: bool = False) -> list:
    posture = posture or (Posture(extra=dict(extra or {}),
                                  strict=strict))
    p = Path(path)
    size = p.stat().st_size
    with p.open("rb") as fh:
        head = fh.read(HEAD)
        actual = detect.sniff(head, name=p.name)
        claimed = detect.declared(p)

        out = []
        if not detect.agrees(claimed, actual):
            out.append(_mismatch(p, claimed, actual))

        suffix = p.suffix.lower()
        if (suffix in COMPRESSED_SUFFIXES
                and joblib_files.compression_of(head)):
            out.extend(_call(joblib_files.analyse, head + fh.read(),
                             path=str(p), posture=posture))
            return out

        if claimed == detect.ONNX and actual in (detect.UNKNOWN,
                                                 detect.ONNX):
            out.extend(onnx_file.analyse(head + fh.read(HEAD),
                                         path=str(p)))
            return out

        if actual in (detect.PICKLE, detect.TORCH_LEGACY):
            fh.seek(0)
            fn = (pickles.analyse if actual == detect.PICKLE
                  else torch_legacy.analyse)
            out.extend(_call(fn, fh, path=str(p), posture=posture))
            return out

        if actual in (detect.ZIP, detect.NPZ):
            fh.seek(0)
            if keras_zip.is_keras_archive(head):
                out.extend(keras_zip.analyse(fh, path=str(p)))
            else:
                out.extend(_call(archives.analyse, fh, path=str(p),
                                 posture=posture))
            return out

        if size > MAX_WHOLE_FILE:
            out.append(Finding(
                rule="CKPT-014", severity=sev("CKPT-014"),
                path=str(p),
                message=(f"{size} bytes, and this format has to be "
                         f"read whole; not analysed (limit "
                         f"{MAX_WHOLE_FILE})"),
                detail={"size": size}))
            return out

        fn = _whole_file_analyser(head, actual)
        if fn is None:
            if actual == detect.UNKNOWN:
                out.append(Finding(
                    rule="CKPT-007", severity=Severity.INFO,
                    path=str(p),
                    message="format not recognised; nothing analysed"))
            return out
        out.extend(_call(fn, head + fh.read(), path=str(p),
                         posture=posture))
        return out


def candidates(path: str | Path) -> list:
    p = Path(path)
    if p.is_file():
        return [p]
    return [c for c in sorted(p.rglob("*"))
            if c.is_file() and c.suffix.lower() in CANDIDATES]


def scan_path(path: str | Path, **kw) -> list:
    out = []
    for child in candidates(path):
        out.extend(scan_file(child, **kw))
    return out
