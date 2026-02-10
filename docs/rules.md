# Rules

Generated from `ckptscan/registry.py` by
`ckptscan rules --format markdown`. Do not edit by hand.

| id | severity | title |
|---|---|---|
| [`CKPT-001`](#ckpt-001) | critical | Call to a known-dangerous callable |
| [`CKPT-002`](#ckpt-002) | medium | Call to a callable that is not on the allowlist |
| [`CKPT-003`](#ckpt-003) | high | Import of a dangerous module, not called here |
| [`CKPT-004`](#ckpt-004) | low | Stream truncated, malformed or unparseable |
| [`CKPT-005`](#ckpt-005) | high | Object-dtype numpy array |
| [`CKPT-006`](#ckpt-006) | critical | Keras Lambda layer |
| [`CKPT-007`](#ckpt-007) | medium | Unrecognised format or non-standard operator domain |
| [`CKPT-008`](#ckpt-008) | medium | Declared format does not match the magic bytes |
| [`CKPT-010`](#ckpt-010) | medium | Nested archive inside a checkpoint |
| [`CKPT-011`](#ckpt-011) | medium | Unrestricted deserialisation call |
| [`CKPT-012`](#ckpt-012) | high | Archive member escapes the archive root |
| [`CKPT-013`](#ckpt-013) | high | Loader opts out of the restricted unpickler |
| [`CKPT-014`](#ckpt-014) | low | Implausible archive member size |
| [`CKPT-015`](#ckpt-015) | high | numpy.load with allow_pickle=True |
| [`CKPT-016`](#ckpt-016) | high | Keras loader with safe_mode=False |
| [`CKPT-017`](#ckpt-017) | medium | safetensors header inconsistency |
| [`CKPT-018`](#ckpt-018) | high | Loader must resolve something from outside |
| [`CKPT-019`](#ckpt-019) | medium | GGUF header inconsistency |

## CKPT-001

**Call to a known-dangerous callable** -- default severity `critical`.

**What.** A call opcode in a pickle stream reaches a callable on the dangerous list -- os.system, subprocess, eval, a network primitive, a nested unpickler.

**Why it matters.** This is not a heuristic. Loading the file with an unrestricted unpickler runs that call with arguments the file chose. There is no legitimate reason for a weights file to do this.

**Fix.** Do not load it. Obtain the weights from a source you can verify, or convert from a copy you trust to safetensors. If this is your own file, find what put it there.

## CKPT-002

**Call to a callable that is not on the allowlist** -- default severity `medium`.

**What.** A call opcode reaches a callable this tool does not recognise.

**Why it matters.** Often legitimate: a project with its own classes pickles them, and no allowlist can know every project's classes. Also exactly what a payload looks like when it reaches execution through something unusual. The point of the rule is to put the decision in front of a human.

**Fix.** Look at the name. If it belongs to the project that produced the checkpoint, add it to a local allowlist with a written reason. If you cannot account for it, treat it as CKPT-001.

## CKPT-003

**Import of a dangerous module, not called here** -- default severity `high`.

**What.** A dangerous module is imported by the stream but no call opcode in this stream consumes it.

**Why it matters.** An import is not nothing: it executes the module's top level. It is also how a payload is staged, with the call in another stream or another member of the same archive.

**Fix.** Treat as CKPT-001 unless you can account for the import.

## CKPT-004

**Stream truncated, malformed or unparseable** -- default severity `low`.

**What.** The opcode stream ended early, hit the opcode budget, or could not be parsed at all.

**Why it matters.** Usually a corrupt download or a format this tool guessed wrong about. Occasionally deliberate: a stream that a parser rejects and a loader accepts is a way past a scanner.

**Fix.** Re-download and re-scan. If it is reproducible, the file is not loadable either and should be treated as hostile until explained.

## CKPT-005

**Object-dtype numpy array** -- default severity `high`.

**What.** An .npy or .npz member whose dtype is object, which means its contents are a pickle.

**Why it matters.** Loading it requires allow_pickle=True, and then it executes. An array of numbers never needs this.

**Fix.** Re-save the data with a numeric dtype. If the array really holds Python objects, that is a data-format problem, not a loader flag to set.

## CKPT-006

**Keras Lambda layer** -- default severity `critical`.

**What.** A Lambda, TFOpLambda or SlicingOpLambda layer in a saved model config.

**Why it matters.** The config carries a marshalled code object. Loading the model reconstructs it and it becomes callable. No pickle is involved, so pickle hardening does not touch it.

**Fix.** Rebuild the layer as a Layer subclass that lives in your own code, and load with safe_mode on. Do not pass safe_mode=False to make the error go away.

## CKPT-007

**Unrecognised format or non-standard operator domain** -- default severity `medium`.

**What.** Either a file whose format could not be identified, or an ONNX operator domain no standard runtime implements.

**Why it matters.** An unidentified file was not analysed, which is not the same as clean. A custom operator domain means running the model as intended requires a shared library from somewhere.

**Fix.** For a format: identify it, and note it down if it should be supported. For a domain: find out what provides it before installing anything.

## CKPT-008

**Declared format does not match the magic bytes** -- default severity `medium`.

**What.** The extension claims one format and the bytes are another.

**Why it matters.** Sometimes harmless -- a .bin is a zip about half the time. The interesting direction is a pickle named .safetensors, because the name is usually the entire basis on which somebody decided the file was safe to load. That direction is HIGH.

**Fix.** Rename it to what it is, then scan it again as that.

## CKPT-010

**Nested archive inside a checkpoint** -- default severity `medium`.

**What.** An archive member that is itself an archive, with findings inside it.

**Why it matters.** There is no legitimate reason for a checkpoint to be wrapped this way. The structure is evidence independently of what is inside it: it is what you build when you know a scanner looks one level deep.

**Fix.** Treat the inner findings at their own severity and treat the nesting as a reason to distrust the source.

## CKPT-011

**Unrestricted deserialisation call** -- default severity `medium`.

**What.** pickle.load, joblib.load, dill.load or pandas.read_pickle in source code.

**Why it matters.** No restricted mode exists for these calls. Whatever they are given executes. Whether that matters depends entirely on where the input comes from, which this cannot see.

**Fix.** Change the format. For sklearn, ONNX or skops; for arrays, safetensors or a numeric npy. If the input is genuinely trusted, say so in a comment next to the call and silence the rule with a justification.

## CKPT-012

**Archive member escapes the archive root** -- default severity `high`.

**What.** A zip member whose name is absolute or contains a .. segment.

**Why it matters.** Any loader that extracts rather than streams will write outside the destination. This tool only reads, so the finding is about the loader downstream.

**Fix.** Do not extract it. If you must, use a loader that rejects absolute and traversing member names.

## CKPT-013

**Loader opts out of the restricted unpickler** -- default severity `high`.

**What.** torch.load with weights_only=False, or relying on the default where the project pins a torch older than the one that made it restricted.

**Why it matters.** The restricted unpickler is the single most effective control available for this class, and this is the code that turns it off. Usually added to make a legacy checkpoint load.

**Fix.** Re-save the checkpoint as tensors only, or as safetensors, then remove the flag. If the checkpoint must carry objects, load it once in an isolated environment and convert it.

## CKPT-014

**Implausible archive member size** -- default severity `low`.

**What.** A member whose declared size is enormous, or whose expansion ratio is extreme.

**Why it matters.** A loader that reads the member whole may not survive it. Not code execution; a resource problem with a cheap fix.

**Fix.** Cap what the loader will read. This tool declines to read it either, so the member was not analysed.

## CKPT-015

**numpy.load with allow_pickle=True** -- default severity `high`.

**What.** A call that enables pickle execution inside numpy's loader.

**Why it matters.** Equivalent to weights_only=False, for numpy. Normally added because an array turned out to hold objects.

**Fix.** Fix the data so the array has a numeric dtype, then remove the flag.

## CKPT-016

**Keras loader with safe_mode=False** -- default severity `high`.

**What.** load_model, model_from_json or model_from_config with safe_mode=False.

**Why it matters.** This is what deserialises a Lambda layer, which is what runs the code object in the model config. Widely recommended on the internet as the fix for a load error, which is the whole problem.

**Fix.** Rebuild the Lambda layers as real layers in your own code. The error is the control working.

## CKPT-017

**safetensors header inconsistency** -- default severity `medium`.

**What.** Tensor offsets outside the payload, overlapping spans, a header longer than the file, or a header that is not a JSON object.

**Why it matters.** The format cannot execute anything, so this is never code execution. It is a parser problem for whatever reads it next, and a sign the file is corrupt or hand-made.

**Fix.** Re-save or re-download. Deliberately capped below HIGH: treating a header quirk in a safe format as seriously as os.system in a pickle would make this tool's own recommendation unusable.

## CKPT-018

**Loader must resolve something from outside** -- default severity `high`.

**What.** A Keras registered_name or custom object, or an ONNX custom-op library named in model metadata.

**Why it matters.** Loading the artefact as intended means importing or loading code the artefact names but does not contain. Where that code comes from is the finding.

**Fix.** Establish what provides it and whether you trust that, before installing anything. Prefer an artefact that uses only framework-provided components.

## CKPT-019

**GGUF header inconsistency** -- default severity `medium`.

**What.** Tensor or metadata counts that do not fit the file, or a version this tool does not read.

**Why it matters.** Like CKPT-017: the format cannot execute anything, so this is corruption or a hand-made file, not execution.

**Fix.** Re-download. If the counts are deliberate, the file will not load either.
