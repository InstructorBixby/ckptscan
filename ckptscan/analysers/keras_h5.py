"""The `.h5` container: HDF5, with the config in a root attribute.

Reading HDF5 properly means `h5py`, and `h5py` is a compiled
dependency with a numpy requirement. Taking that on for one format
would make this tool unavailable anywhere it cannot build a wheel, so
it is an extra: `uv pip install -e ".[keras]"`.

Without it there is a fallback that scans the raw bytes for the config
string. HDF5 stores a small string attribute inline and uncompressed,
so looking for the JSON and parsing from the first `{` works on every
real saved model I have tried. It is still a heuristic, it can be
defeated by a file that compresses the attribute, and every finding it
produces says so.

A heuristic that announces itself is defensible. A heuristic that
reports as though it were a parse is not.
"""
from __future__ import annotations

import json
import re

from ckptscan.analysers import keras_config
from ckptscan.findings import Finding, Severity

MAX_SCAN = 64 * 1024 * 1024
_CONFIG_NEEDLE = re.compile(rb"model_config")


def _h5py():
    try:
        import h5py
    except ImportError:
        return None
    return h5py


def _precise(path: str) -> tuple[object | None, str]:
    h5py = _h5py()
    if h5py is None:
        return None, "h5py not installed"
    try:
        with h5py.File(path, "r") as fh:
            raw = fh.attrs.get("model_config")
    except OSError as exc:
        return None, f"h5py could not open the file: {exc}"
    if raw is None:
        return None, "no model_config attribute"
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        return json.loads(raw), ""
    except json.JSONDecodeError as exc:
        return None, f"model_config is not valid JSON: {exc}"


def _fallback(data: bytes) -> object | None:
    """Find the config JSON in the raw bytes. Best effort, by design."""
    m = _CONFIG_NEEDLE.search(data[:MAX_SCAN])
    if not m:
        return None
    start = data.find(b"{", m.end())
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, min(len(data), start + MAX_SCAN)):
        ch = data[i:i + 1]
        if in_string:
            if escaped:
                escaped = False
            elif ch == b"\\":
                escaped = True
            elif ch == b'"':
                in_string = False
            continue
        if ch == b'"':
            in_string = True
        elif ch == b"{":
            depth += 1
        elif ch == b"}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(
                        data[start:i + 1].decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    return None
    return None


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    config, why = _precise(path)
    precise = config is not None
    if config is None:
        config = _fallback(data)
    if config is None:
        if why in ("no model_config attribute", ""):
            return []
        return [Finding(
            rule="CKPT-007", severity=Severity.INFO, path=path,
            location=location,
            message=(f"HDF5 file not analysed ({why}) and the raw-byte "
                     f"fallback found no model config. Install "
                     f"ckptscan[keras] to read this precisely."))]
    return keras_config.analyse_config(
        config, path=path, location="model_config:", precise=precise)
