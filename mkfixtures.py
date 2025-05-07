"""Build the deliberately-unsafe pickles the tests scan.

Generated, never committed. Two reasons:

1. A repository with working malicious payloads in it is a repository
   people are right to be wary of cloning, and every scanner that
   ships one gets flagged by somebody's endpoint protection.
2. A generated fixture is readable. The payload is four lines of Python
   in this file rather than an opaque blob somebody has to trust.

Every payload here is **inert**: it writes a marker file into a
directory the caller names, and does nothing else. No network, no
persistence, no execution of anything downloaded. The point is to
exercise the detector, and a marker file does that exactly as well as
anything harmful would.
"""
import argparse
import os
import pathlib
import pickle


MARKER = "ckptscan-fixture-ran"


class SystemPayload:
    """REDUCE -> os.system. The textbook shape."""

    def __reduce__(self):
        return (os.system, (f"touch /tmp/{MARKER}",))


class EvalPayload:
    """REDUCE -> builtins.eval."""

    def __reduce__(self):
        return (eval, ("open('/tmp/" + MARKER + "', 'w').close()",))


class BenignTensorish:
    """What an ordinary checkpoint looks like: a REDUCE nobody minds."""

    def __reduce__(self):
        return (dict, ([("weight", [0.0, 1.0])],))


def write(path, obj, protocol):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(obj, fh, protocol=protocol)
    return path


def build(out: pathlib.Path):
    made = []
    made.append(write(out / "system_p2.pkl", SystemPayload(), 2))
    made.append(write(out / "system_p4.pkl", SystemPayload(), 4))
    made.append(write(out / "eval_p4.pkl", EvalPayload(), 4))
    made.append(write(out / "benign_p4.pkl", BenignTensorish(), 4))
    made.append(write(out / "plain_dict.pkl",
                      {"weight": [1, 2, 3]}, 4))
    return made


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples/generated")
    args = ap.parse_args()
    for p in build(pathlib.Path(args.out)):
        print(p)


if __name__ == "__main__":
    main()
