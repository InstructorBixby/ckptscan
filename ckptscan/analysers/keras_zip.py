"""The `.keras` container: a zip holding config.json."""
from __future__ import annotations

import io
import json
import zipfile

from ckptscan.analysers import keras_config
from ckptscan.findings import Finding, Severity

CONFIG_MEMBERS = ("config.json", "model_config.json")
MAX_CONFIG = 64 * 1024 * 1024


def is_keras_archive(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
    except zipfile.BadZipFile:
        return False
    return bool(names & set(CONFIG_MEMBERS))


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return [Finding(rule="CKPT-004", severity=Severity.LOW,
                        path=path, location=location,
                        message=f"not a readable zip: {exc}")]
    out = []
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
                rule="CKPT-004", severity=Severity.LOW, path=path,
                location=member,
                message=f"{member} is not valid JSON: {exc}")]
        out.extend(keras_config.analyse_config(
            config, path=path, location=f"{member}:"))
    return out
