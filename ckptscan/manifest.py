"""Compare a directory against a published list of hashes.

This is the cheapest useful thing in the whole tool and the one with
the strongest answer. Static analysis says what a file would do;
a manifest says whether it is the file the publisher produced, and a
clean scan of the wrong file is worth nothing.

Three input shapes, because three are what people publish:

- `sha256sum` output: `<hex>  <path>`, two spaces, optionally `*path`
  for binary mode.
- a JSON object mapping path to hex, or to `{"sha256": hex, ...}`.
- a JSON array of `{"path": ..., "sha256": ...}` records.

Hashing is streamed. A 70B shard does not fit in memory and reading one
whole to hash it is the single easiest way to turn a scanner into an
OOM kill in somebody's CI.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

CHUNK = 1024 * 1024

_SUMLINE = re.compile(r"^(?P<hex>[0-9a-fA-F]{32,128})\s+\*?"
                      r"(?P<path>.+?)\s*$")


class ManifestError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    path: str
    digest: str
    algorithm: str = "sha256"


_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


def _algorithm_for(hexd: str) -> str:
    algo = _BY_LENGTH.get(len(hexd))
    if algo is None:
        raise ManifestError(
            f"{len(hexd)} hex characters is not a digest length this "
            f"reads (md5, sha1, sha256, sha512)")
    return algo


def parse(text: str) -> list[Entry]:
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        return _parse_json(stripped)
    return _parse_sums(text)


def _parse_sums(text: str) -> list[Entry]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _SUMLINE.match(line)
        if not m:
            raise ManifestError(f"line {n}: not a checksum line")
        hexd = m.group("hex").lower()
        out.append(Entry(path=m.group("path"), digest=hexd,
                         algorithm=_algorithm_for(hexd)))
    if not out:
        raise ManifestError("manifest is empty")
    return out


def _one(path: str, value) -> Entry:
    if isinstance(value, str):
        hexd = value.lower()
    elif isinstance(value, dict):
        hexd = str(value.get("sha256") or value.get("digest")
                   or value.get("hash") or "").lower()
        if hexd.startswith("sha256:"):
            hexd = hexd.split(":", 1)[1]
    else:
        raise ManifestError(f"{path}: cannot read a digest from "
                            f"{type(value).__name__}")
    if not hexd:
        raise ManifestError(f"{path}: no digest")
    return Entry(path=path, digest=hexd,
                 algorithm=_algorithm_for(hexd))


def _parse_json(text: str) -> list[Entry]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"not valid JSON: {exc}") from exc
    if isinstance(doc, dict):
        inner = doc.get("files") if "files" in doc else doc
        if isinstance(inner, dict):
            return [_one(k, v) for k, v in sorted(inner.items())]
        doc = inner
    if isinstance(doc, list):
        out = []
        for row in doc:
            if not isinstance(row, dict):
                raise ManifestError("array entries must be objects")
            path = row.get("path") or row.get("filename") \
                or row.get("name")
            if not path:
                raise ManifestError("array entry has no path")
            out.append(_one(str(path), row))
        return out
    raise ManifestError("manifest JSON is neither an object nor an "
                        "array")


def read(path: str | Path) -> list[Entry]:
    p = Path(path)
    if not p.exists():
        raise ManifestError(f"no manifest at {p}")
    return parse(p.read_text(encoding="utf-8"))


def digest_file(path: str | Path, algorithm: str = "sha256") -> str:
    """Streamed, because a shard does not fit in memory."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
