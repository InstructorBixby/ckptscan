"""Dispatch a path to the analysers that apply to it."""
from __future__ import annotations

from pathlib import Path

from ckptscan.analysers import pickles

PICKLE_SUFFIXES = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"}


def scan_file(path: str | Path) -> list:
    p = Path(path)
    data = p.read_bytes()
    return pickles.analyse(data, path=str(p))


def scan_path(path: str | Path) -> list:
    """One file, or every candidate file under a directory."""
    p = Path(path)
    if p.is_file():
        return scan_file(p)
    out = []
    for child in sorted(p.rglob("*")):
        if child.is_file() and child.suffix.lower() in PICKLE_SUFFIXES:
            out.extend(scan_file(child))
    return out
