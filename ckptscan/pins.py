"""Which torch is pinned, because `CKPT-013` severity depends on it.

`torch.load(p)` with no `weights_only` is a refusal on 2.6 and later
and a shell on anything earlier. Reporting both at the same severity
makes the rule useless in both directions: noise for a current project,
and a LOW on a project pinned to 2.1 where it is the most serious thing
in the repository.

So: find the pin. `pyproject.toml`, `requirements*.txt`,
`constraints*.txt`, and a `poetry.lock`-style `torch = "..."` line.
Deliberately crude, because a wrong answer here must fail safe --
an unreadable pin is treated as unknown, and unknown keeps the
original severity rather than lowering it.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

#: The release that flipped the default.
FLIP = (2, 6)

_REQ = re.compile(
    r"^\s*torch\s*(?P<op>==|>=|~=|<=|<|>)?\s*"
    r"(?P<ver>\d+(?:\.\d+){0,2})", re.I | re.M)


def _parse(version: str) -> tuple:
    parts = []
    for chunk in version.split(".")[:3]:
        try:
            parts.append(int(chunk))
        except ValueError:
            break
    return tuple(parts)


def _from_text(text: str):
    best = None
    for m in _REQ.finditer(text):
        ver = _parse(m.group("ver"))
        if not ver:
            continue
        op = m.group("op") or "=="
        # The question is "what is the oldest torch this project may
        # run on", so a floor is the interesting bound and an exact pin
        # is both bounds.
        if op in ("==", "~=", ">=", ">"):
            if best is None or ver < best:
                best = ver
        elif op in ("<", "<="):
            if best is None:
                best = (0,)
    return best


def torch_floor(root: str | Path) -> tuple | None:
    """Oldest torch this project may install, or None if unknown."""
    root = Path(root)
    if root.is_file():
        root = root.parent
    candidates = []
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            doc = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            doc = {}
        deps = (doc.get("project", {}) or {}).get("dependencies", [])
        extras = (doc.get("project", {}) or {}).get(
            "optional-dependencies", {}) or {}
        for group in extras.values():
            deps = list(deps) + list(group)
        candidates.append("\n".join(str(d) for d in deps))
        candidates.append(pyproject.read_text(encoding="utf-8",
                                              errors="replace"))
    for pattern in ("requirements*.txt", "constraints*.txt",
                    "*.lock"):
        for path in sorted(root.glob(pattern)):
            candidates.append(
                path.read_text(encoding="utf-8", errors="replace"))

    found = None
    for text in candidates:
        ver = _from_text(text)
        if ver and (found is None or ver < found):
            found = ver
    return found


def predates_flip(floor: tuple | None) -> bool | None:
    """True if the pin is older than the flip, None if unknown."""
    if floor is None:
        return None
    return floor < FLIP
