# ckptscan

Scans model checkpoints for code that runs when you load them.

    ckptscan model.pt
    ckptscan ./weights --fail-on high
    ckptscan loaders ./src

## the problem

A pickle is not a data format. It is a little stack program, and a
pickle loader is its interpreter. `GLOBAL` imports whatever module and
attribute the file names; `REDUCE` calls it with arguments the file
supplies. Arbitrary code execution is the *documented behaviour* of the
format, and the ecosystem distributes weights this way -- people
download a file from the internet and hand it to a loader.

## what changed, and what did not

PyTorch 2.6 made `torch.load(weights_only=True)` the default
(2025-01-29). That is the biggest improvement to this problem that has
happened and it makes the common case -- somebody loading a downloaded
checkpoint with no idea the format was executable -- a refusal instead
of a shell.

What is left:

- **code that opts out.** `weights_only=False` is a documented
  parameter and every project whose checkpoint holds anything but
  tensors hits the refusal and has to choose.
- **old pins.** `torch==2.1.0` in a requirements file gets the old
  default for as long as that file exists.
- **Keras `Lambda` layers.** A marshalled code object in a model
  config. Not torch, no pickle, unaffected.
- **ONNX custom operators.** The model names an operator; the runtime
  loads a shared library to provide it.
- **`numpy.load(allow_pickle=True)`** and **joblib**, which have their
  own opt-outs or none at all.

So this tool scans checkpoints *and* source code, and the
recommendation it ends up making is not "scan harder" -- it is **ship
safetensors, keep your loaders current, do not pass the opt-out.**
`docs/weights-only.md` is the long version.

## this never unpickles anything

The analysis is a static walk of the opcode stream with
`pickletools.genops`, which parses without executing. Nothing here
imports a module the file names, constructs a class it names, or calls
a callable it names. There is a test asserting exactly that and it is
the most important test in the repository.

A scanner that has to run the file to decide whether running the file
is safe is not a scanner. The alternative -- unpickle in a sandbox --
fails twice over: deciding that executed code did nothing bad is harder
than this entire problem, and dynamic analysis only ever sees the
branch it took, so a payload gated on a hostname does nothing in your
sandbox and everything on the target.

## formats

`.pt` / `.pth` / `.bin` / `.ckpt` (zip and legacy), bare pickles,
joblib, `.npy` / `.npz`, Keras `.keras` and `.h5`, ONNX, safetensors
and GGUF. `docs/formats.md` has a column for the only thing that
matters: whether the format can execute anything at all.

## the allowlist is the product

Pointed at a directory of ordinary public checkpoints, the naive
version of this produced 1,900 findings from nine files, every one of
them `collections.OrderedDict` and `torch._utils._rebuild_tensor_v2`.
A PyTorch state dict *is* an `OrderedDict`, and a tensor *is*
reconstructed through `REDUCE`. That is the format working as designed.

So `REDUCE` alone is not a finding; `REDUCE` reaching something
unrecognised is. Every allowlist entry carries the reason it is there
-- a test enforces that -- because an entry is a promise that calling
that thing with attacker-chosen arguments is harmless.

## what a clean report means

"No load-time code execution reachable in what I could parse." Not
"safe". `CKPT-002` findings are judgement calls, and some allowlisted
reconstruction helpers take sizes and strides that a hostile file can
make inconsistent -- a loader memory-safety concern this tool cannot
see.

## exit codes

| code | meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default: medium) |
| 1 | findings at or above it |
| 2 | usage or input error |
