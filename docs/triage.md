# Triaging what it says

Two shapes of wrongness, and the first one matters more.

## it fired on a file that is fine

These matter more than a missed detection. A scanner that fires on
legitimate checkpoints gets turned off, and then it catches nothing at
all -- and the thing that turns it off is me, at the end of a long day,
with one flag.

Before deciding anything, write down four things, because a week later
I will have none of them:

- the version, from `ckptscan --version`
- the finding as printed, the whole line, including the rule id
- **what produced the file** -- framework and version, or the project it
  came from. This is usually the whole answer: a callable a named
  framework emits is a candidate for the shipped table, and one my own
  code emits belongs in that project's config.
- what the reported callable does when called, and what an attacker
  controls about its arguments

If I cannot keep the file, keep the opcode sequence instead. A minimal
reproducer built with `ckptscan/corpus.py` is better than either.

## it missed something it should have caught

**Never keep a working malicious file for this.** Write down the shape
-- format, container nesting, pickle protocol, and which opcode
sequence reaches execution -- and then add a generator to
`ckptscan/corpus.py` that builds that shape with the marker write as
the payload. The sample becomes part of the corpus and the pipeline
keeps asserting it still fires.

A detector going quiet is the failure I would never notice, because
quiet looks exactly like success.
