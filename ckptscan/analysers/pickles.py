"""Analyse a pickle stream. The core of the tool.

Rules:
  CKPT-001  a call reaching a known-dangerous callable
  CKPT-002  a call reaching a callable that is not on the allowlist
  CKPT-003  an import of a known-dangerous module, never called
  CKPT-004  the stream is truncated or malformed

CKPT-002 is the one that does the work and the one that generates the
complaints. A checkpoint from a project with its own custom classes
legitimately calls things no allowlist can know about, so CKPT-002 is
MEDIUM and says "I do not recognise this" rather than claiming harm.
"""
from __future__ import annotations

from ckptscan import opcodes, reach
from ckptscan.findings import Finding, Severity


def analyse(data: bytes, *, path: str, location: str = "") -> list:
    try:
        stream = opcodes.parse(data)
    except opcodes.ParseError as exc:
        return [Finding(
            rule="CKPT-004", severity=Severity.LOW, path=path,
            location=location,
            message=f"not a parseable pickle stream: {exc}")]

    out = []
    for r in reach.reach_of(stream):
        if r.how == reach.CALLED and r.verdict == "dangerous":
            out.append(Finding(
                rule="CKPT-001", severity=Severity.CRITICAL, path=path,
                location=location or f"offset {r.pos}",
                message=(f"{r.opcode} calls {r.dotted} -- {r.reason}. "
                         f"Loading this file executes code."),
                detail={"module": r.module, "attr": r.attr,
                        "opcode": r.opcode, "offset": r.pos,
                        "protocol": stream.protocol}))
        elif r.how == reach.CALLED and r.verdict == "unknown":
            out.append(Finding(
                rule="CKPT-002", severity=Severity.MEDIUM, path=path,
                location=location or f"offset {r.pos}",
                message=(f"{r.opcode} calls {r.dotted}, which is not on "
                         f"the allowlist. Legitimate for a checkpoint "
                         f"with custom classes; review it."),
                detail={"module": r.module, "attr": r.attr,
                        "opcode": r.opcode, "offset": r.pos,
                        "protocol": stream.protocol}))
        elif r.how == reach.IMPORTED and r.verdict == "dangerous":
            out.append(Finding(
                rule="CKPT-003", severity=Severity.HIGH, path=path,
                location=location or f"offset {r.pos}",
                message=(f"imports {r.dotted} without calling it in "
                         f"this stream -- {r.reason}. The import "
                         f"itself runs the module's top level."),
                detail={"module": r.module, "attr": r.attr,
                        "offset": r.pos}))
    if stream.truncated:
        out.append(Finding(
            rule="CKPT-004", severity=Severity.LOW, path=path,
            location=location,
            message="stream ended early or hit the opcode budget; "
                    "analysis is incomplete"))
    return out
