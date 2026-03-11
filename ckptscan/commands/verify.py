"""`ckptscan verify`: the directory against a published manifest."""
from __future__ import annotations

import sys

from ckptscan import manifest
from ckptscan.analysers import manifests


def run(args) -> int:
    try:
        findings = manifests.verify(
            args.path, args.manifest,
            report_extra=not args.allow_extra)
    except manifest.ManifestError as exc:
        print(f"ckptscan: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ckptscan: {exc}", file=sys.stderr)
        return 2
    args._findings = findings
    args._scanned = len(manifest.read(args.manifest))
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser(
        "verify",
        help="check a directory against a published checksum list")
    p.add_argument("path")
    p.add_argument("--manifest", required=True,
                   help="sha256sum output, or a JSON hash map")
    p.add_argument("--allow-extra", action="store_true",
                   help="do not report files the manifest omits")
    p.set_defaults(fn=run)
