"""The `.keras` container: a zip holding config.json."""
from __future__ import annotations

import io
import json
import zipfile

from ckptscan.analysers import keras_config
from ckptscan.findings import Finding
from ckptscan.registry import default_severity as sev

CONFIG_MEMBERS = ("config.json", "model_config.json")
MAX_CONFIG = 64 * 1024 * 1024


def _open(data):
    if isinstance(data, (bytes, bytearray)):
        return zipfile.ZipFile(io.BytesIO(data))
    return zipfile.ZipFile(data)


def is_keras_archive(data) -> bool:
    """True for a zip holding a Keras model config.

    Takes the head of a file as well as a whole one: the central
    directory is at the END of a zip, so a head-only check cannot read
    the member list and falls back to the local file header names,
    which is enough to tell a `.keras` from a `.pt`.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return bool(set(zf.namelist()) & set(CONFIG_MEMBERS))
        except (zipfile.BadZipFile, OSError):
            return any(name.encode() in data
                       for name in CONFIG_MEMBERS)
    try:
        with _open(data) as zf:
            return bool(set(zf.namelist()) & set(CONFIG_MEMBERS))
    except (zipfile.BadZipFile, OSError):
        return False


def analyse(data, *, path: str, location: str = "") -> list:
    try:
        zf = _open(data)
    except zipfile.BadZipFile as exc:
        return [Finding(rule="CKPT-004", severity=sev("CKPT-004"),
                        path=path, location=location,
                        message=f"not a readable zip: {exc}")]
    with zf:
        names = set(zf.namelist())
        member = next((m for m in CONFIG_MEMBERS if m in names), None)
        if member is None:
            return []
        with zf.open(member) as fh:
            raw = fh.read(MAX_CONFIG)
        try:
            config = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [Finding(
                rule="CKPT-004", severity=sev("CKPT-004"), path=path,
                location=member,
                message=f"{member} is not valid JSON: {exc}")]
        return keras_config.analyse_config(
            config, path=path, location=f"{member}:")
