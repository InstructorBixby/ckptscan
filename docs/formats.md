# Formats

The column that matters is the last one.

| format | how it is read | can it execute at load |
|---|---|---|
| `.pt` / `.pth` / `.ckpt` (zip) | zip members, `archive/data.pkl` analysed as a pickle | **yes** |
| `.pt` / `.pth` (legacy) | concatenated pickle streams | **yes** |
| `.bin` | either of the above, decided by the bytes | **yes** |
| `.pkl` / `.pickle` | pickle opcode walk | **yes** |
| `.joblib` / `.sav` / `.z` | decompressed, then a pickle opcode walk | **yes** |
| `.npy` | header parsed; object dtype means the body is a pickle | **yes, with `allow_pickle=True`** |
| `.npz` | zip of `.npy` members, each analysed | **yes, with `allow_pickle=True`** |
| `.safetensors` | header consistency only | no |
| `.gguf` | header counts only | no |

## the format is sniffed, never inferred from the name

A `.bin` is a zip about half the time and a bare pickle the rest. A
`.pt` can be either. So every file is sniffed from its magic bytes and
the extension is treated as a *claim*; a disagreement is `CKPT-008`.

That rule exists for one case in particular: a pickle named
`model.safetensors`. The name is usually the entire basis on which
somebody decided a file was safe to load, which makes it worth lying
about, which makes it worth checking. That direction of mismatch is
HIGH; the rest are MEDIUM.

## the legacy torch format, and why it needs its own analyser

It is several pickle streams concatenated: a magic number, a protocol
version, system info, the object graph, then storage keys.
`pickletools.genops` stops at the first `STOP`, which in this format is
the end of the magic number -- so analysing the file as a single stream
reads a long integer, finds nothing, and reports clean. Every payload
in such a file lives in a later stream.

That is a pleasant kind of bug to find in your own tool before anyone
else does, and it is why `tests/test_torch_legacy.py` has a fixture
whose payload is deliberately in stream 2.

## nested archives

A checkpoint containing an archive containing the real pickle is what
you build if you know a scanner looks one level deep. So the zip
analyser recurses, to a depth of three, and reports the nesting itself
as `CKPT-010` -- there is no legitimate reason for a checkpoint to be
wrapped that way, so the structure is evidence independent of what is
inside it.

## safetensors and GGUF

Both are safe by construction. No opcode stream, no callable, no way
for the file to ask a loader to import anything. The checks here are
header consistency -- offsets inside the file, no overlapping tensors,
counts that fit the bytes -- and they top out at MEDIUM.

Keeping them at MEDIUM is deliberate. The recommendation this tool
exists to make is *ship safetensors*, and a tool that reports a header
quirk in a safetensors file at the same severity as `os.system` in a
pickle has made its own advice unusable.

## not covered yet

Keras saved models, which can hold arbitrary code in a `Lambda` layer,
and ONNX, which can reference custom operators. Both are real and both
need their own analyser.
