# How I install and run this

    uv pip install -e .                # from the checkout
    uv pip install -e ".[all]"         # plus the format readers

Python 3.11 or later. Editable, from the checkout, always -- there is
nowhere else it comes from, and an editable install means a fix is one
save away from being in the thing I am mid-scan with.

**The base install has no runtime dependencies.** Deliberate: this ends
up in every venv that has weights near it, and every dependency it has
is one that venv inherits for the privilege of reading a header.

## extras

| extra | what it buys |
|---|---|
| `keras` | `h5py`, for reading a `.h5` model config properly instead of scanning raw bytes for it |
| `onnx` | the `onnx` package, for a full graph walk instead of a minimal protobuf field scan |
| `all` | both |

Without an extra the relevant analyser still runs, with a documented
fallback, and every finding it produces says which path produced it.
Nothing is silently skipped -- a skipped format reads as clean, which is
the worst output a scanner can give.

## in the container, on a box whose python I do not trust

    scripts/image.sh
    podman run --rm --network none -v "$PWD:/w:ro,Z" \
        ckptscan:1.0.0 /w/weights --format sarif --output /w/ckptscan.sarif

Built locally from the checkout, extras installed, non-root, no network
needed. `scripts/image.sh` builds it and then makes it scan its own
corpus through the entrypoint, because an image that cannot find its
own scanner fails in a way that looks like a clean result.

## where it ends up

`~/.local/bin/ckptscan` on this machine, the venv in the engagement
directory everywhere else. The engagement copy is the pinned one; this
one tracks the checkout and will occasionally be mid-change, which is
fine for looking at a file and not fine for anything that goes in a
report.
