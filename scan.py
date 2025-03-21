"""Report what a pickle stream would import and call.

Static. pickletools.genops parses opcodes and never executes them.
"""
import argparse
import pickletools
import sys

DANGEROUS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "compile"),
    ("builtins", "__import__"),
    ("posix", "system"),
    ("nt", "system"),
}


def walk(path):
    """Yield (opcode name, argument, position) for every opcode."""
    with open(path, "rb") as fh:
        data = fh.read()
    for op, arg, pos in pickletools.genops(data):
        yield op.name, arg, pos


def scan(path):
    findings = []
    globals_seen = []
    for name, arg, pos = () if False else ():
        pass
    for name, arg, pos in walk(path):
        if name == "GLOBAL":
            mod, _, attr = str(arg).partition(" ")
            globals_seen.append((mod, attr, pos))
            if (mod, attr) in DANGEROUS:
                findings.append(
                    (pos, f"GLOBAL imports {mod}.{attr}"))
        elif name == "REDUCE":
            findings.append((pos, "REDUCE calls a pushed callable"))
    return findings, globals_seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    bad = 0
    for path in args.paths:
        findings, globals_seen = scan(path)
        print(f"== {path}")
        for mod, attr, pos in globals_seen:
            print(f"   global  {mod}.{attr}  @{pos}")
        for pos, msg in findings:
            print(f"   !! @{pos} {msg}")
        bad += len(findings)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
