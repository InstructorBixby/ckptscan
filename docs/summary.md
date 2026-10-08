# If you only do three things

Written because the question I get after an engagement is always the
same, and because a tool's own documentation is the wrong place to
argue that the tool is the answer.

## 1. stop producing pickles

Publish weights as safetensors. The format cannot execute anything --
there is no opcode stream, no callable, no way for the file to ask a
loader to import something. Every rule in this scanner is a way of
asking "could this execute", and for a safetensors file the answer is
no by construction, which is a better answer than any scanner can give.

Converting is a one-time cost, usually an afternoon, and it removes the
whole class rather than detecting instances of it.

## 2. keep the loaders current, and do not opt out

`torch.load(weights_only=True)` has been the default since PyTorch 2.6
(2025-01-29). That makes the common case a refusal instead of a shell.
So:

- do not pin an older torch for an unrelated reason and forget why
- do not pass `weights_only=False` to make a legacy checkpoint load;
  convert the checkpoint instead
- the same reasoning for `numpy.load(allow_pickle=True)` and
  `keras.models.load_model(safe_mode=False)`

`ckptscan loaders` exists to find exactly these three, and after the
default flipped it is the more useful half of the tool.

## 3. verify what you downloaded

Against a published checksum list, before you look at anything else. A
clean scan of the wrong file is worth nothing, and this is the cheapest
check in the whole stack.

## and then scan

Scanning is for the files you did not choose: a model from a hub, an
artefact from a vendor, something in a cache nobody remembers pulling.
It is a compensating control, it has false positives, its allowlist is
a list of promises somebody made, and it cannot see a payload that
stays inside allowlisted callables.

That is not an argument against running it. It is an argument against
running it *instead* of the three things above, which is the mistake I
see most often -- a scanner in CI, a green build, and
`weights_only=False` three directories away.

## the honest summary of this project

It detects a real class of problem that the ecosystem is slowly
engineering out of existence, which is the correct direction. The parts
of it with the longest useful life are probably the loader scan, the
non-torch format coverage, and `docs/allowlist.md` -- because the
allowlist argument is the one that does not go away.
