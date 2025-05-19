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

So: parse the opcodes, resolve the names, report the reach. No import of
the named module, no construction of the named class, nothing.

## the first run against real files

I pointed the naive version at a directory of checkpoints I had lying
around -- nothing exotic, a handful of models from public repositories
-- and got 1,900 findings from nine files. Every one of them was this:

    global  collections.OrderedDict
    global  torch._utils._rebuild_tensor_v2
    global  torch.FloatStorage
    !! REDUCE calls a pushed callable

A PyTorch state dict is an `OrderedDict` of tensors, and a tensor is
reconstructed by calling `torch._utils._rebuild_tensor_v2` through
`REDUCE`. Hundreds of times. That is not a weakness in the files, it is
the format working as designed, and a scanner that reports it is a
scanner nobody runs twice.

So `REDUCE` on its own is not a finding. **`REDUCE` reaching a callable
that is not on the allowlist** is a finding, and that makes the
allowlist the product. Everything else in this repository is plumbing
around a list of callables known to be fine, and the quality of that
list is the quality of the tool.

It is also the honest reason this is not a regex. You can grep a file
for `os.system` in two lines. You will then spend a month on
`OrderedDict`.

## the allowlist is a liability, and that is the trade

Every entry is a promise that calling that thing with arguments an
attacker chose is harmless. Some of those promises are weaker than they
look, so each entry carries a reason, and an entry whose reason I cannot
write down does not go in.

The one I keep coming back to: a legitimate reconstruction function that
takes a size, a stride and a storage offset can be handed values that
make the resulting tensor read out of bounds. That is a memory-safety
bug in the loader rather than code execution in the file, and it is a
real argument against ever calling it the file is safe. Which is why a
clean report says "no load-time code execution reachable" and not
"safe".

## what a finding means

"This stream would import this and call it, and I do not recognise it."
Not "this file is malicious". The distinction matters because the first
statement is checkable and the second is a judgement the tool is not
entitled to make.
