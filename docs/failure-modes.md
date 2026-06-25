# How this breaks

A note to the version of me that comes back to this after six months
away and is about to add a fast path.

## the bug class that matters

**Anything in here that executes content from a scanned file.** The
entire premise is that this can be pointed at a hostile checkpoint
safely -- that is the only reason it is safe to run it on the laptop
rather than in a VM, and I do run it on the laptop. A code path that
imports a module the file names, constructs a class it names, calls a
callable it names, `eval`s a header, or hands a member to something
that does any of those, is the most serious possible bug here
regardless of how hard it is to reach.

Three deliberate defences, all three tested:

- the analysis is `pickletools.genops` only, which parses and does not
  execute
- the `.npy` header is parsed with `ast.literal_eval`, never `eval`
- a test monkeypatches `os.system`, `builtins.eval` and `__import__`,
  scans the unsafe corpus, and fails if any of them is reached

If I ever find a fourth path, it goes on this list and gets a test
before anything else happens.

## the other things worth keeping an eye on

- **A detection bypass.** A file that reaches load-time execution and
  reports clean. Keep the shape, add a corpus sample, never keep a
  working file.
- **Resource exhaustion a scan cannot survive.** A crafted archive or
  stream that makes this allocate without bound. A scanner that gets
  OOM-killed reports nothing, which looks exactly like clean.
- **Path traversal while scanning.** This never extracts and never
  writes, so a member name should not be able to reach the filesystem.
  Guarded; the guard is the kind of thing a refactor removes.
- **A manifest entry escaping the verified directory.** Also guarded,
  same warning.

## what is not a bug in this sense

- A false positive. Those are bugs and they are the bulk of the work --
  `docs/triage.md` -- but they fail safe.
- The content of a checkpoint somebody else published. Not this tool's
  problem; that is a conversation with whoever published it.
- A missed `CKPT-002`, where the callable is simply unusual. That rule
  is a judgement call by design.
- This declining to analyse something and saying so. Reporting "not
  analysed" is the correct behaviour. Silently skipping would not be,
  and that distinction is the whole reason `CKPT-007` exists.

## the sentence to keep

A clean report means "no load-time code execution reachable in what I
could parse". It does not mean safe. Every time I have been tempted to
shorten that in output text, the shortened version was a claim I could
not back.
