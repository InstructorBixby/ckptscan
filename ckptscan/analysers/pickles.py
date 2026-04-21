"""Analyse a pickle stream. The core of the tool.

Rules:
  CKPT-001  a call reaching a known-dangerous callable
  CKPT-002  a call reaching a callable that is not on the allowlist
  CKPT-003  an import of a known-dangerous module, never called
  CKPT-004  the stream is truncated or malformed

CKPT-002 is the one that does the work and the one that generates the
complaints. A checkpoint from a project with its own custom classes
legitimately calls things no allowlist can know about, so it says "I do
not recognise this" rather than claiming harm.

Takes bytes or an open binary stream. Severities come from
`ckptscan.registry`, so a rule's severity lives in one place.
"""
from __future__ import annotations

from ckptscan import opcodes, reach
from ckptscan.findings import Finding
from ckptscan.registry import default_severity as sev

#: Dangerous callables whose reach is a network primitive. These map
#: onto the exfiltration group in llm-redteam-notes, where the
#: detection advice transfers directly.
_EGRESS_MODULES = {"socket", "urllib.request", "requests", "httplib",
                   "http.client", "ftplib", "smtplib", "telnetlib"}


def _taxonomy(module: str) -> tuple:
    return ("EX-004",) if module in _EGRESS_MODULES else ()


def analyse(data, *, path: str, location: str = "") -> list:
    try:
        stream = opcodes.parse(data)
    except opcodes.ParseError as exc:
        return [Finding(
            rule="CKPT-004", severity=sev("CKPT-004"), path=path,
            location=location,
            message=f"not a parseable pickle stream: {exc}")]
    return from_stream(stream, path=path, location=location)


def from_stream(stream, *, path: str, location: str = "") -> list:
    out = []
    for r in reach.reach_of(stream):
        base = {"module": r.module, "attr": r.attr,
                "opcode": r.opcode, "offset": r.pos,
                "protocol": stream.protocol}
        where = location or f"offset {r.pos}"
        if r.how == reach.CALLED and r.verdict == "dangerous":
            out.append(Finding(
                rule="CKPT-001", severity=sev("CKPT-001"), path=path,
                location=where,
                message=(f"{r.opcode} calls {r.dotted} -- {r.reason}. "
                         f"An unrestricted load executes this."),
                detail=base, taxonomy=_taxonomy(r.module)))
        elif r.how == reach.CALLED and r.verdict == "unknown":
            out.append(Finding(
                rule="CKPT-002", severity=sev("CKPT-002"), path=path,
                location=where,
                message=(f"{r.opcode} calls {r.dotted}, which is not on "
                         f"the allowlist. Legitimate for a checkpoint "
                         f"with custom classes; review it."),
                detail=base))
        elif r.how == reach.IMPORTED and r.verdict == "dangerous":
            out.append(Finding(
                rule="CKPT-003", severity=sev("CKPT-003"), path=path,
                location=where,
                message=(f"imports {r.dotted} without calling it in "
                         f"this stream -- {r.reason}. The import "
                         f"itself runs the module's top level."),
                detail=base, taxonomy=_taxonomy(r.module)))
    if stream.truncated:
        out.append(Finding(
            rule="CKPT-004", severity=sev("CKPT-004"), path=path,
            location=location,
            message="stream ended early or hit the opcode budget; "
                    "analysis is incomplete"))
    return out
