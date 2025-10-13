"""Dispatch a path to the analysers that apply to it.

Everything interesting about this module is in the dispatch: the format
comes from the bytes, never the extension, and a disagreement between
the two is itself a finding rather than something to resolve quietly.

Two exceptions to "never the extension", both honest:

- `.keras` and `.pt` are both zips, so the member list decides.
- ONNX is a bare protobuf with no magic number. There is nothing to
  sniff, so the extension is all there is, and a file that claims to be
  ONNX and parses as something executable gets `CKPT-008` first.
"""
from __future__ import annotations

from pathlib import Path

from ckptscan import detect
from ckptscan.analysers import (archives, gguf_file, joblib_files,
                                keras_h5, keras_zip, numpy_arrays,
                                onnx_file, pickles, safetensors_file,
                                torch_legacy)
from ckptscan.findings import Finding, Severity

#: Extensions worth opening when walking a directory.
CANDIDATES = {
    ".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib",
    ".npy", ".npz", ".h5", ".hdf5", ".keras", ".safetensors",
    ".gguf", ".onnx", ".model", ".zip", ".sav", ".z",
}

COMPRESSED_SUFFIXES = {".joblib", ".sav", ".z", ".gz", ".bz2", ".xz"}


def _zip_analyser(data: bytes):
    """A .keras file and a .pt file are both zips."""
    if keras_zip.is_keras_archive(data):
        return keras_zip.analyse
    return archives.analyse


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


def analyser_for(data: bytes, actual: str):
    if actual in (detect.ZIP, detect.NPZ):
        return _zip_analyser(data)
    return {
        detect.PICKLE: pickles.analyse,
        detect.TORCH_LEGACY: torch_legacy.analyse,
        detect.NPY: numpy_arrays.analyse,
        detect.SAFETENSORS: safetensors_file.analyse,
        detect.GGUF: gguf_file.analyse,
        detect.HDF5: keras_h5.analyse,
        detect.ONNX: onnx_file.analyse,
    }.get(actual)


def scan_file(path: str | Path) -> list:
    p = Path(path)
    data = p.read_bytes()
    suffix = p.suffix.lower()

    if (suffix in COMPRESSED_SUFFIXES
            and joblib_files.compression_of(data)):
        return joblib_files.analyse(data, path=str(p))

    actual = detect.sniff(data, name=p.name)
    claimed = detect.declared(p)

    out = []
    if not detect.agrees(claimed, actual):
        out.append(_mismatch(p, claimed, actual))

    # ONNX has no magic number, so a file that claims to be one and
    # does not parse as anything else is analysed as one.
    if claimed == detect.ONNX and actual in (detect.UNKNOWN,
                                             detect.ONNX):
        out.extend(onnx_file.analyse(data, path=str(p)))
        return out

    fn = analyser_for(data, actual)
    if fn is None:
        if actual == detect.UNKNOWN:
            out.append(Finding(
                rule="CKPT-007", severity=Severity.INFO, path=str(p),
                message="format not recognised; nothing analysed"))
        return out
    out.extend(fn(data, path=str(p)))
    return out


def scan_path(path: str | Path) -> list:
    """One file, or every candidate file under a directory."""
    p = Path(path)
    if p.is_file():
        return scan_file(p)
    out = []
    for child in sorted(p.rglob("*")):
        if child.is_file() and child.suffix.lower() in CANDIDATES:
            out.extend(scan_file(child))
    return out
