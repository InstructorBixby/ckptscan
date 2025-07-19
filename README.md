# ckptscan

Scans model checkpoints for code that runs when you load them.

    ckptscan model.pt
    ckptscan ./weights --fail-on high

## the problem

A pickle is not a data format. It is a little stack program, and
`torch.load` is its interpreter. `GLOBAL` imports whatever module and
attribute the file names; `REDUCE` calls it with arguments the file
supplies. Arbitrary code execution is the *documented behaviour* of the
format, and the entire ecosystem distributes weights this way -- people
download a file from the internet and hand it to a loader.

## this never unpickles anything

The analysis is a static walk of the opcode stream with
`pickletools.genops`, which parses without executing. Nothing in this
tool imports a module the file names, constructs a class the file
names, or calls a callable the file names. There is a test asserting
exactly that, and it is the most important test in the repository.

A scanner that has to run the file to decide whether running the file
is safe is not a scanner. The alternative -- unpickle in a sandbox --
fails twice over: deciding that executed code did nothing bad is
harder than this entire problem, and dynamic analysis only ever sees
the branch it took, so a payload gated on a hostname does nothing in
your sandbox and everything on the target.

## rules

| id | severity | what |
|---|---|---|
| `CKPT-001` | critical | a call reaching a known-dangerous callable |
| `CKPT-002` | medium | a call reaching something not on the allowlist |
| `CKPT-003` | high | an import of a dangerous module, not called here |
| `CKPT-004` | low | the stream is truncated or malformed |

## the allowlist is the product

Pointed at a directory of ordinary public checkpoints, the naive
version of this produced 1,900 findings from nine files, every one of
them `collections.OrderedDict` and `torch._utils._rebuild_tensor_v2`.
A PyTorch state dict *is* an `OrderedDict`, and a tensor *is*
reconstructed through `REDUCE`. That is the format working as designed.

So `REDUCE` alone is not a finding; `REDUCE` reaching something
unrecognised is. Which makes the allowlist the whole product, and
everything else here plumbing around a list of callables known to be
fine. Every entry carries the reason it is there -- a test enforces
that -- because an entry is a promise that calling that thing with
attacker-chosen arguments is harmless, and a promise I cannot write
down should not be made.

## what a clean report means

"No load-time code execution reachable in what I could parse." Not
"safe". Two reasons, both honest:

- `CKPT-002` findings are judgement calls. A project with its own
  classes legitimately calls things no allowlist knows.
- Some allowlisted reconstruction helpers take sizes, strides and
  offsets, and a hostile file can make those inconsistent. That is a
  memory-safety problem in the loader rather than code execution in the
  file, and it is outside what this tool can see.

## exit codes

| code | meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default: medium) |
| 1 | findings at or above it |
| 2 | usage or input error |
