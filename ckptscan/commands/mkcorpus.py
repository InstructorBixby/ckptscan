"""`ckptscan-mkcorpus`: write the sample corpus somewhere."""
from __future__ import annotations

import argparse
import sys

from ckptscan import corpus


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="ckptscan-mkcorpus",
        description="Generate the deliberately-unsafe sample corpus. "
                    "Every payload is inert: it writes a marker file "
                    "and does nothing else.")
    ap.add_argument("--out", default="corpus")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)
    made = corpus.build(args.out)
    if not args.quiet:
        for path in made:
            print(path)
        print(f"{len(made)} sample(s) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
