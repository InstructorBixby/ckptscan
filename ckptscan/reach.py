"""From "this stream mentions os.system" to "this stream calls it".

A `GLOBAL` on its own is an import. An import is interesting but it is
not the finding -- `copyreg._reconstructor` is imported by the normal
path, and a module that is imported and never called executes only its
module-level code, which is a real risk but a different one.

The finding is a global that is *consumed by a call-like opcode*:
REDUCE, NEWOBJ, NEWOBJ_EX, INST, OBJ, or BUILD reaching a `__setstate__`
on it.
"""
from __future__ import annotations

from dataclasses import dataclass

from ckptscan import policy
from ckptscan.opcodes import GlobalRef, Stream

CALLED = "called"
IMPORTED = "imported"


@dataclass(frozen=True)
class Reach:
    module: str
    attr: str
    pos: int
    how: str            # CALLED | IMPORTED
    opcode: str         # which opcode consumed it, "" if imported only
    verdict: str        # dangerous | allowed | unknown
    reason: str

    @property
    def dotted(self) -> str:
        return f"{self.module}.{self.attr}"


def reach_of(stream: Stream) -> list[Reach]:
    """One Reach per global, deduplicated by (module, attr, how)."""
    called: dict[tuple[str, str], tuple[int, str]] = {}
    for callee, opcode, pos in stream.calls:
        if isinstance(callee, GlobalRef):
            key = (callee.module, callee.attr)
            called.setdefault(key, (pos, opcode))

    out: list[Reach] = []
    seen: set = set()
    for ref in stream.globals:
        key = (ref.module, ref.attr)
        how = CALLED if key in called else IMPORTED
        if (key, how) in seen:
            continue
        seen.add((key, how))
        pos, opcode = called.get(key, (ref.pos, ""))
        out.append(Reach(
            module=ref.module, attr=ref.attr, pos=pos, how=how,
            opcode=opcode, verdict=policy.classify(*key),
            reason=policy.reason(*key)))
    return sorted(out, key=lambda r: (r.verdict != "dangerous",
                                      r.verdict != "unknown",
                                      r.dotted))


def summary(reaches: list[Reach]) -> dict:
    out = {"dangerous": 0, "unknown": 0, "allowed": 0}
    for r in reaches:
        if r.how == CALLED:
            out[r.verdict] += 1
    return out
