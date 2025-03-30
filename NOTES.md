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

## the one thing a static walk cannot do

Decide. The stream says `GLOBAL torch._utils _rebuild_tensor_v2`
followed by `REDUCE`, and that is both completely normal and
structurally identical to `GLOBAL os system` followed by `REDUCE`. The
difference is entirely in the allowlist, which means **the allowlist is
the product**. Everything else here is plumbing around a list of
callables that are known to be fine, and the quality of that list is the
quality of the tool.

That is also the honest reason this is not solved by a regex: you can
grep a file for `os.system` in two lines, and you will then spend a
month on false positives from `collections.OrderedDict`.

## what a finding means

"This stream would import this and call it." Not "this file is
malicious". The distinction matters because almost every real
checkpoint from almost every real project trips the naive version of
this check, and a tool that cries wolf on every legitimate file gets
turned off in a week.
