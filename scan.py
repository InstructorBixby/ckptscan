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

# Opcodes that push a string we might later see consumed by
# STACK_GLOBAL. Protocol 2 and below emit GLOBAL with the module and
# name in the argument; protocol 4 pushes two SHORT_BINUNICODEs and
# then STACK_GLOBAL, so the naive GLOBAL-only check sees nothing at all
# in any modern checkpoint. That is the first thing I got wrong.
STRING_PUSH = {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE",
               "BINUNICODE8", "STRING", "BINSTRING",
               "SHORT_BINSTRING"}


def walk(path):
    with open(path, "rb") as fh:
        data = fh.read()
    for op, arg, pos in pickletools.genops(data):
        yield op.name, arg, pos


def scan(path):
    findings = []
    globals_seen = []
    stack = []
    for name, arg, pos in walk(path):
        if name in STRING_PUSH:
            stack.append(str(arg))
            continue
        if name == "GLOBAL":
            mod, _, attr = str(arg).partition(" ")
            globals_seen.append((mod, attr, pos))
            if (mod, attr) in DANGEROUS:
                findings.append((pos, f"GLOBAL imports {mod}.{attr}"))
        elif name == "STACK_GLOBAL":
            attr = stack.pop() if stack else "?"
            mod = stack.pop() if stack else "?"
            globals_seen.append((mod, attr, pos))
            if (mod, attr) in DANGEROUS:
                findings.append(
                    (pos, f"STACK_GLOBAL imports {mod}.{attr}"))
        elif name == "REDUCE":
            findings.append((pos, "REDUCE calls a pushed callable"))
        else:
            # Anything else invalidates my toy string stack. Clearing
            # it is wrong in general and good enough for the one shape
            # STACK_GLOBAL actually appears in; a real stack model
            # comes next.
            stack.clear()
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
