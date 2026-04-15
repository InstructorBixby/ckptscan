# Design notes

## static, and why there is no debate about it

The obvious implementation is to unpickle in a sandbox and watch what
happens. Three reasons not to:

1. **A sandbox is a research project.** Executing attacker-controlled
   code and then deciding it did nothing bad is the hardest problem in
   this entire field, and a scanner that gets it wrong has executed the
   payload on the machine of the person who was being careful.
2. **Dynamic analysis only sees the path it took.** A payload guarded by
   a hostname check, a date, or the presence of a GPU does nothing in a
   sandbox and everything on the target. The opcode stream contains
   both branches whether or not either runs.
3. **`pickletools.genops` already parses the format correctly.** It is
   in the standard library, it is what the pickle maintainers use, and
   it does not call a single thing the stream names.

## the first run against real files

The naive version produced 1,900 findings from nine ordinary public
checkpoints, every one of them `collections.OrderedDict` and
`torch._utils._rebuild_tensor_v2`. A PyTorch state dict *is* an
`OrderedDict`, and a tensor *is* reconstructed through `REDUCE`. So
`REDUCE` alone is not a finding and the allowlist is the product.

## the allowlist is a liability, and that is the trade

Every entry is a promise that calling that thing with arguments an
attacker chose is harmless. Each entry carries a reason, and an entry
whose reason I cannot write down does not go in.

The one I keep coming back to: a legitimate reconstruction function
that takes a size, a stride and a storage offset can be handed values
that make the resulting tensor read out of bounds. That is a
memory-safety bug in the loader rather than code execution in the file,
and it is why a clean report says "no load-time code execution
reachable" and not "safe".

## memory

The first report from somebody else's machine was an out-of-memory
kill on a sharded 70B model. Not a bug in the analysis -- a bug in
`read_bytes()`. A 9 GiB shard was being read whole so that a function
could look at the first few hundred opcodes of it.

`pickletools.genops` accepts a file object and reads as it goes. It
always did. The fix was to stop materialising the file and hand over
the open handle: constant memory, and faster, because a payload is
almost always in the first kilobyte and the tensor data after it never
has to be touched.

The same mistake was in the archive analyser, which was reading each zip
member into a bytes object before parsing it. `ZipFile.open` returns a
stream too.

What still has to be read whole:

- the compressed containers, because decompression needs an output
  buffer. Capped, and the cap is reported as a finding when it is hit.
- the `.npy` header, which is tiny.
- a Keras `config.json`, which is a few hundred kilobytes.
- the safetensors and GGUF headers, which are bounded by the format.

None of those scale with the weights, which was the whole problem.

## what a finding means

"This stream would import this and call it, and I do not recognise it."
Not "this file is malicious". The first statement is checkable and the
second is a judgement the tool is not entitled to make.
