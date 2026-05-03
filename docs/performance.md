# Performance and memory

    ckptscan ./weights --jobs 8
    ckptscan ./weights --jobs 1     # serial, for debugging

## memory is a correctness property here

The first report from somebody else's machine was an out-of-memory kill
on a sharded 70B model. Not the analysis -- `read_bytes()`. A 9 GiB
shard was being read whole so that a function could look at the first
few hundred opcodes of it.

`pickletools.genops` accepts a file object and consumes it lazily. It
always did. The fix was to stop materialising the file: constant
memory, and faster, because a payload is almost always in the first
kilobyte and the tensor data after it never has to be touched.

What still gets read whole, and why none of it scales with the weights:

| | bound |
|---|---|
| a compressed container (joblib) | decompression needs an output buffer; capped, and the cap is reported |
| an `.npy` header | a few hundred bytes |
| a Keras `config.json` | a few hundred kilobytes |
| a safetensors or GGUF header | bounded by the format |
| a nested archive member | capped at 256 MiB, and the cap is reported |

A file in a format that genuinely needs reading whole, above 2 GiB, is
reported as `CKPT-014` rather than attempted. A scanner that gets
OOM-killed in CI reports nothing at all, which is the worst possible
output.

## parallelism

Sharded models are the common shape -- four to twenty independent files
in a directory -- so the walk uses a thread pool. The work is mostly
I/O with small bursts of opcode parsing, and threads are enough; a
process pool would pay for pickling findings back between processes,
which is a joke this project does not need to make twice.

Output order does not depend on `--jobs`: findings are sorted by
severity, then path, then rule before rendering, and there is a test
that the serial and parallel JSON are byte-identical. A scanner whose
report shuffles between runs cannot be diffed, and diffing two reports
is most of what anyone does with them.

## what is actually slow

Almost never the opcode walk. In order:

1. **Hashing, in `verify`.** It reads every byte by definition. There
   is no way around it and no cache, because a cache is a thing to
   attack.
2. **Decompressing a large joblib.** Unavoidable for that format;
   another reason not to use it.
3. **Walking a huge directory.** `rglob` over a cache directory with a
   hundred thousand files costs more than scanning the nine that
   matter. Point it at the model directory, not at `~`.

## rough numbers

A 4-shard 7B model in safetensors: header checks only, well under a
second. The same model as `.bin` shards: a few seconds, almost all of
it opening files. `verify` over the same directory: as long as reading
14 GiB takes on that disk, which is the honest answer and the reason
`verify` belongs in a nightly job rather than a pre-commit hook.
