# ckptscan

Finds code that executes when you load a model checkpoint.

```
ckptscan ./weights
ckptscan loaders ./src
ckptscan verify ./weights --manifest SHA256SUMS
```

**It never unpickles anything.** The analysis is a static walk of the
pickle opcode stream, and a test monkeypatches `os.system`,
`builtins.eval` and `__import__`, scans the whole unsafe corpus, and
fails if any is reached.

## the three to re-read when coming back to this

1. **[The weights_only default](weights-only.md).** PyTorch 2.6 made
   the restricted unpickler the default and that fixed most of this.
   What is left is opt-outs, old pins, and four formats that were never
   torch. Everything else here is downstream of that page.
2. **[The allowlist](allowlist.md).** The hard problem is not
   detection, it is false positives. A state dict *is* an
   `OrderedDict` and a tensor *is* rebuilt through `REDUCE`, so the
   allowlist is the product.
3. **[What I looked at first](prior-art.md).** Two scanners got here
   first. The four reasons this exists anyway, so I stop re-deciding.

## where the rest of it is

| | |
|---|---|
| [Rules](rules.md) | every `CKPT-` id, generated from the registry |
| [Formats](formats.md) | with a column for whether each can execute at all |
| [In a pipeline](ci.md) | the check, and where to put it |
| [Configuring](config.md) | and why disabling a rule needs a written reason |

## what a clean report means

No load-time code execution reachable in what could be parsed. Not
"safe". The README's limitations section is the honest list, and the
recommendation this whole thing arrives at is: **ship safetensors, keep
the loaders current, do not pass the opt-out.** Scanning is for the
files I did not choose.
