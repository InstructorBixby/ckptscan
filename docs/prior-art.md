# What I looked at first

Written down because I will come back here in a year convinced I
checked and there was nothing. There was something. Twice.

## picklescan

Published 2023-02, https://github.com/mmaitre314/picklescan. The one
that made this a known problem rather than a conference anecdote, and
the one wired into the model hub that most people download weights
from -- which means it has scanned several orders of magnitude more
files than this ever will.

It walks opcodes statically, it has a dangerous-globals list, and it
handles the zip and legacy torch layouts. The design is the same as
this one because it is the correct design.

Where this does more: non-torch formats (Keras `Lambda` layers, ONNX
custom ops, joblib containers, `.npy` object arrays), a source scan for
loaders that opt out, SARIF output, manifest verification, and a
configuration file with mandatory justifications.

Where it does more: it is deployed at a scale that has produced a
dangerous-globals list refined against real abuse rather than against
my own test corpus. That list is better than mine and I have taken
entries from it, and should keep re-reading it.

## modelscan

Published 2023-08, https://github.com/protectai/modelscan. Broader
format coverage than picklescan -- it reaches Keras and TensorFlow --
and the closest thing to this tool's scope.

Where this differs: the severity policy with mandatory justification,
the loader scan, and an allowlist where every entry has a written
reason. Those are preferences about how a scanner should behave in CI,
not claims of better detection.

Where it does more: it is a product with a company behind it, which
means documentation, integrations and a support path. When a client
asks what to deploy across their org rather than what I personally run,
that is the answer, and saying so costs me nothing.

## the restricted unpickler

Not a tool, and better than all of them. `torch.load(weights_only=True)`
does not detect the problem, it removes the capability, which is the
strictly stronger move. Since PyTorch 2.6 it is the default. Any
scanner that does not lead with this is selling something; see
`docs/weights-only.md`.

## so why did I write one anyway

Three reasons that survived writing down.

1. **The non-pickle formats.** A Keras `Lambda` layer is arbitrary code
   in a JSON config and no amount of pickle hardening touches it. Same
   for an ONNX custom operator. These are under-covered everywhere.
2. **The loader scan.** After the default flipped, the call site is the
   more informative half of the finding, and I could not find anything
   that looks at both.
3. **I needed it to behave a particular way in a report** -- stable
   rule ids, SARIF I can feed into my own tooling, a configuration file
   where turning a rule off requires writing down why, so that the
   config file *is* the audit trail. Those are engagement requirements
   and they are reason enough, as long as I never start telling myself
   this got here first.

## which one I reach for

- A file a hub served me: picklescan has already looked at it, so this
  is a second opinion rather than the first.
- A client asking what to standardise on: modelscan.
- Non-torch formats, loader call sites, or SARIF into my own tooling:
  this one. That is the whole list.
- Actually fixing it: safetensors, and a current loader.

Running two scanners costs nothing and they disagree in interesting
places. Where this one disagrees with picklescan's globals list, the
default assumption is that picklescan is right and this is the bug.
