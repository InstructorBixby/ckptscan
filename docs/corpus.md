# The sample corpus

    ckptscan-mkcorpus --out corpus
    ckptscan corpus/unsafe
    ckptscan corpus/clean       # must be silent

Twenty-odd checkpoints, generated on demand, never committed. Half are
deliberately unsafe and half are deliberately ordinary, and the second
half is the half that catches the regressions nobody expects.

## nothing malicious is committed

The repository contains the generator, not the payloads. Two reasons,
and the second is the one that decided it:

1. A repository with working malicious checkpoints in it is one people
   are right to be wary of cloning, and it will be flagged by
   somebody's endpoint protection within a week of being useful.
2. A generated sample is **readable**. The payload is four lines of
   Python in `ckptscan/corpus.py` rather than an opaque blob somebody
   has to take on trust. A security tool asking you to trust an opaque
   blob has lost the argument before it starts.

## every payload is inert

The dangerous callable in every unsafe sample resolves to a marker
write -- `touch /tmp/ckptscan-corpus-ran` -- and nothing else. No
network, no persistence, no deletion, no environment capture, nothing
downloaded. There is a test that greps the generator's own source for
`socket`, `urllib`, `requests`, `rmtree` and `os.remove` and fails if
any appears.

This costs nothing in detection coverage. The detector sees
`GLOBAL os system` and a call opcode; it cannot tell what the argument
would have done, and it does not look. A real payload would exercise
exactly the same code path.

## do not load them

Not because they will hurt you -- because you do not need to. The
entire premise of the tool is that you can find out what a checkpoint
would do without running it.

The one defensible reason is to satisfy yourself that they really would
execute: load one in a container with no network and look for the
marker file. The corpus README says so, and that is the only place in
this project that suggests loading anything.

## the two halves fail together

`MANIFEST.json` records, for every sample, the rules it must produce
and the worst severity it must reach -- or that it must produce
nothing at all. The test suite asserts both in one run, which means:

- a detector that stops detecting fails
- a change that silences a false positive by breaking a detection fails
- a new rule that fires on an ordinary checkpoint fails

That third one is the one that keeps happening. `clean/state_dict.pkl`
is an `OrderedDict` of tensors and it is in there because the naive
version of this tool produced 1,900 findings from nine files of exactly
that shape.

## using it to evaluate something else

The corpus is deliberately not specific to this tool. If you are
comparing scanners, generate it and point them all at it. The
interesting column is not how many of `unsafe/` each one catches -- it
is how many of `clean/` each one stays quiet on.
