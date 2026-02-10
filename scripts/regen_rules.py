#!/usr/bin/env python3
"""Regenerate docs/rules.md from the registry.

The rule table was written twice -- once in the registry and once in
the docs -- and within three releases they disagreed about two
severities. So the docs are generated and CI diffs them.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ckptscan.commands.rules import as_markdown  # noqa: E402

TARGET = ROOT / "docs" / "rules.md"


def main() -> int:
    text = as_markdown()
    if "--check" in sys.argv:
        current = TARGET.read_text(encoding="utf-8") \
            if TARGET.exists() else ""
        if current != text:
            print("docs/rules.md is stale; run scripts/regen_rules.py",
                  file=sys.stderr)
            return 1
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
