"""CKPT-009: the directory against the manifest.

Reports three things and treats them as one rule, because the
remediation for all three is "go back to the publisher":

  mismatch   the file is there and the hash differs
  missing    the manifest lists it and it is not on disk
  extra      it is on disk and the manifest does not list it

`extra` is the one people argue about. It stays, because nothing stops
a loader reading a file nobody published, and an attacker who can add a
file to a verified directory has not had to change a single hash.
"""
from __future__ import annotations

from pathlib import Path

from ckptscan import manifest
from ckptscan.findings import Finding
from ckptscan.registry import default_severity as sev

#: Files that live beside weights and are nobody's supply-chain
#: problem.
IGNORED_NAMES = {".gitattributes", ".gitignore", "README.md",
                 "LICENSE", "LICENSE.txt", "ckptscan.toml"}


def _interesting(path: Path, root: Path) -> bool:
    if path.name in IGNORED_NAMES:
        return False
    return not any(part.startswith(".") for part in
                   path.relative_to(root).parts)


def verify(root: str | Path, manifest_path: str | Path, *,
           report_extra: bool = True) -> list:
    root = Path(root)
    entries = manifest.read(manifest_path)
    out = []
    listed = set()

    for entry in entries:
        target = (root / entry.path).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            out.append(Finding(
                rule="CKPT-012", severity="high",
                path=str(manifest_path), location=entry.path,
                message=("manifest entry points outside the directory "
                         "being verified"),
                detail={"entry": entry.path}))
            continue
        listed.add(target)
        if not target.exists():
            out.append(Finding(
                rule="CKPT-009", severity=sev("CKPT-009"),
                path=str(root / entry.path), location="missing",
                message=("listed in the manifest and not present on "
                         "disk"),
                detail={"expected": entry.digest,
                        "algorithm": entry.algorithm}))
            continue
        actual = manifest.digest_file(target, entry.algorithm)
        if actual != entry.digest:
            out.append(Finding(
                rule="CKPT-009", severity=sev("CKPT-009"),
                path=str(root / entry.path), location="mismatch",
                message=(f"{entry.algorithm} is {actual[:16]}..., the "
                         f"manifest says {entry.digest[:16]}.... This "
                         f"is not the file that was published."),
                detail={"expected": entry.digest, "actual": actual,
                        "algorithm": entry.algorithm}))

    if report_extra:
        for child in sorted(root.rglob("*")):
            if not child.is_file() or not _interesting(child, root):
                continue
            if child.resolve() in listed:
                continue
            if Path(manifest_path).resolve() == child.resolve():
                continue
            out.append(Finding(
                rule="CKPT-009", severity=sev("CKPT-009"),
                path=str(child), location="unlisted",
                message=("present on disk and not in the manifest. "
                         "Nothing stops a loader reading it, and "
                         "adding a file changes no hash."),
                detail={}))
    return out
