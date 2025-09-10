# Keras saved models

A Keras model is architecture plus weights, and the architecture is
JSON. That sounds safe and is not, because of one layer type.

## Lambda

`keras.layers.Lambda` wraps an arbitrary Python function as a layer.
When the model is saved, that function is serialised -- its code
object, marshalled and base64-encoded, together with its closure and
defaults -- into the model config. When the model is loaded, the code
object is reconstructed and becomes callable.

So a saved Keras model is a program, and the program is sitting in a
JSON string inside the file. No pickle involved, which means no amount
of pickle hardening touches it:

- `torch.load(weights_only=True)` is irrelevant; this is not torch.
- A picklescan-style tool sees a JSON file with no opcodes in it.
- The file can be a perfectly valid `.keras` archive or `.h5`.

## what the two container formats look like

| | |
|---|---|
| `.keras` | a zip with `config.json`, `metadata.json` and `model.weights.h5` |
| `.h5` | HDF5, with the config JSON in the `model_config` attribute of the root group |

The zip form is easy: read the member, parse the JSON, walk the layer
list. The HDF5 form needs an HDF5 reader, which means `h5py`, which is
a hard dependency this tool is not going to take for one format. So:
`ckptscan[keras]` makes the check precise, and without it there is a
byte-level fallback that looks for the config string in the raw file.
The fallback is weaker and says so in the finding.

## rules

| id | severity | what |
|---|---|---|
| `CKPT-006` | critical | a `Lambda` layer; the config carries a marshalled code object that is reconstructed on load |
| `CKPT-018` | high | a reference to a custom object or registered function the loader must resolve, including `custom_objects` entries and `function` specs that are not a plain builtin name |

`CKPT-006` is critical without qualification. Unlike `CKPT-002` there
is no benign reading: a `Lambda` layer in a model you did not build is
somebody else's code that runs when you load it. The remediation is
also unambiguous -- rebuild the layer as a real layer subclass that is
part of your own code, or do not load the model.

## the thing that makes this worse than pickle

Loading a Keras model is a documented, encouraged, high-level
operation. `keras.models.load_model("downloaded.keras")` looks like
reading a file. There is a `safe_mode` parameter that refuses to
deserialise Lambda layers, it defaults to on in recent versions, and
every tutorial that hit a Lambda layer teaches you to pass
`safe_mode=False` to make the error go away. That is the whole problem:
the mitigation exists and the internet is full of instructions to
disable it.

That is also why `ckptscan loaders` scans *code* for `safe_mode=False`
and not just checkpoints for Lambda layers. The file and the call site
are two halves of one finding.
