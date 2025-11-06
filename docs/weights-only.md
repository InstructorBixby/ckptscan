# `torch.load(weights_only=True)` by default

PyTorch 2.6 flipped the default: `torch.load` now restricts
unpickling unless you explicitly opt out (released 2025-01-29, see
https://github.com/pytorch/pytorch/releases/tag/v2.6.0). This is the
single largest improvement to this problem that has happened, it was
the right call, and it makes the most common path safe by default for
the first time.

A tool in this space has two options now. It can carry on as though
nothing happened, which is dishonest and makes it noise. Or it can say
what is left. This is the second one.

## what it genuinely fixes

`torch.load("downloaded.pt")`, written by somebody who had no idea the
format was executable, on a current PyTorch. That is the overwhelming
majority of the exposure by volume, and it is now a refusal instead of
a shell.

The restricted unpickler allows a fixed set of tensor-reconstruction
callables and nothing else, which is a much better version of the
allowlist in this tool: enforced at load time rather than reported
afterwards, and maintained by people who own the format. Where the two
disagree, they are right.

## what it does not fix

**1. Code paths that opt out.** `weights_only=False` is a documented
parameter, and every project with a checkpoint containing anything
other than tensors -- an optimiser state with a custom class, a
`Namespace`, a tokenizer object, a config dataclass -- hits the
refusal and has to choose. Many pass `False`. Many more copy a
StackOverflow answer that passes `False`. This is now the dominant
shape of the problem and it is why `ckptscan loaders` scans source
code and not just files.

**2. Pinned older versions.** A requirements file saying `torch==2.1.0`
gets the old default, forever, in CI, in a container that gets rebuilt
for years. The flip is a fact about the newest release, not about the
installed base.

**3. Keras `Lambda` layers.** Not torch. A marshalled code object in a
model config, reconstructed on load. `keras.models.load_model` has its
own `safe_mode`, which is also opt-out-able and also widely disabled in
tutorials. See `docs/keras.md`.

**4. ONNX custom operators.** Not torch, no pickle, nothing to
restrict. The model names an operator and the runtime goes and finds a
shared library.

**5. `numpy.load(allow_pickle=True)`.** A separate loader with a
separate opt-out, widely used because object arrays are convenient.

**6. joblib and anything sklearn-shaped.** `joblib.load` is a pickle
load with compression on top and has no `weights_only` equivalent at
all. Every sklearn model distributed as a `.joblib` is in exactly the
position torch was in before the flip.

**7. Everything that already shipped.** Files that exist, in caches, in
artifact stores, in container images.

## what this means for the tool

Three changes, all of them reductions:

- A bare pickle in a torch-shaped file is reported with the loader
  default in mind. The message says what a current loader does about
  it, because a finding that overstates its consequence gets ignored
  along with the ones that do not.
- The recommendation is no longer "scan your checkpoints". It is
  **convert to safetensors, keep your loaders current, and do not pass
  the opt-out.** Scanning is what you do for the files you did not
  choose.
- `ckptscan loaders` exists. The file and the call site are two halves
  of one finding, and after the flip the call site is the more
  informative half.

## the honest summary

For PyTorch, this is mostly solved and what is left is opt-outs and old
pins. For Keras, ONNX, numpy object arrays and joblib, nothing changed
at all. A tool that says that is more useful than one implying the sky
is still falling.
