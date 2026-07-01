# ckptscan

Finds code that executes when you load a model checkpoint. Static: it
never unpickles anything.

## how I run it

    uv pip install -e .

No runtime dependencies in the base install. `docs/install.md` for the
extras and the container.

    $ ckptscan ./weights
    CRITICAL CKPT-001 weights/model.pt [archive/data.pkl]: REDUCE calls
             os.system -- operating-system call. An unrestricted load
             executes this.
    MEDIUM   CKPT-002 weights/other.pt [archive/data.pkl]: REDUCE calls
             mypkg.serial.Box, which is not on the allowlist.
             Legitimate for a checkpoint with custom classes; review it.
    2 file(s) scanned: 1 critical, 1 medium. 2 at or above medium.
    $ echo $?
    1

    $ ckptscan ./weights --explain          # add the remediation
    $ ckptscan ./weights --format sarif --output ckptscan.sarif
    $ ckptscan loaders ./src                # the call sites
    $ ckptscan verify ./weights --manifest SHA256SUMS

First thing in an engagement directory, before anything is loaded:
`verify` against whatever checksum list came with the weights, then
the scan, then `loaders` over any code that touches them.

## the problem

A pickle is not a data format. It is a little stack program, and a
pickle loader is its interpreter. `GLOBAL` imports whatever module and
attribute the file names; `REDUCE` calls it with arguments the file
supplies. Arbitrary code execution is the *documented behaviour* of the
format, and the ecosystem distributes weights this way.

## what changed, and what did not

PyTorch 2.6 made `torch.load(weights_only=True)` the default
(2025-01-29), which makes the common case a refusal instead of a shell.
That is the biggest improvement to this problem that has happened, and
there is no version of this tool worth keeping that does not say so.

What is left: code that passes `weights_only=False`, projects pinned to
an older torch, Keras `Lambda` layers, ONNX custom operators,
`numpy.load(allow_pickle=True)`, joblib, and every file that already
shipped. `docs/weights-only.md` is the long version, and the
recommendation it arrives at is not "scan harder" -- it is **ship
safetensors, keep the loaders current, do not pass the opt-out.**

## this never unpickles anything

The analysis is a static walk of the opcode stream with
`pickletools.genops`, which parses without executing. Nothing here
imports a module a file names, constructs a class it names, or calls a
callable it names. A test monkeypatches `os.system`, `builtins.eval`
and `__import__`, scans the whole unsafe corpus, and fails if any is
reached. It is the most important test in the repository.

The alternative -- unpickle in a sandbox -- fails twice over: deciding
that executed code did nothing bad is harder than this entire problem,
and dynamic analysis only sees the branch it took, so a payload gated
on a hostname does nothing in a sandbox and everything on the target.

## what it reads

| format | can it execute at load |
|---|---|
| `.pt` / `.pth` / `.ckpt` / `.bin`, zip and legacy | **yes** |
| `.pkl`, joblib, `.sav` | **yes** |
| `.npy` / `.npz` object arrays | **yes**, with `allow_pickle=True` |
| Keras `.keras` / `.h5` | **yes**, via `Lambda` layers |
| ONNX | not in the file; needs a custom-op library from elsewhere |
| safetensors, GGUF | no -- header checks only |

`docs/formats.md` has the detail. Formats are identified by magic
bytes, never by extension, and a disagreement is its own finding.

## the allowlist is the product

Pointed at the checkpoint directory on this machine, the naive version
produced 1,900 findings from nine files, every one of them
`collections.OrderedDict` and `torch._utils._rebuild_tensor_v2`. A
state dict *is* an `OrderedDict` and a tensor *is* rebuilt through
`REDUCE`.

So `REDUCE` alone is not a finding. Every allowlist entry carries a
written reason -- a test enforces it -- because an entry is a promise
that calling that thing with attacker-chosen arguments is harmless, and
a promise I cannot write down should not be made.
`docs/working-on-this.md` has the five things an entry needs and the
modules no justification gets past.

## limitations

- **A clean report is not "safe".** It means no load-time code
  execution was reachable in what could be parsed. `CKPT-002` is a
  judgement call, and some allowlisted reconstruction helpers take
  sizes and strides a hostile file can make inconsistent -- a loader
  memory-safety concern this cannot see.
- **The allowlist is a liability.** Every entry is a place a payload
  could hide, and the list is the quality of the tool.
- **A format not recognised is not analysed.** It is reported as
  `CKPT-007`, never passed over quietly, but "not analysed" is not
  "clean".
- **No dynamic dispatch in the loader scan.** `getattr(torch, "load")`
  or a loader behind a registry is invisible to it.
- **It cannot tell intent.** A payload and a quirky serialiser look
  identical at the opcode level, which is why `CKPT-002` is MEDIUM and
  says "review it".
- **TensorFlow SavedModel is not covered.** A real gap. `.keras` and
  `.h5` are; a `saved_model.pb` graph is not.
- **It does not sandbox, trace or run anything.** By design, and that
  means a determined payload that stays within allowlisted callables is
  outside its reach. `docs/prior-art.md` says what to run alongside.

## why this exists at all

I did not need a new pickle scanner. Two already worked. The notes are
in `docs/prior-art.md`; the short version of what I reached for first
and why it was not enough:

| | what it is | why I am not just using it |
|---|---|---|
| the restricted unpickler | `weights_only=True`, the default since torch 2.6 | I am not: it is the first thing I check for. It removes the capability rather than detecting the problem, which is strictly stronger than anything here. |
| safetensors | a format that cannot execute | also not a competitor. It is what I tell people to publish. Scanning is for the files I did not choose. |
| picklescan (2023-02) | the original static pickle scanner, wired into the main model hub | right design, and its dangerous-globals list is better than mine because it has seen real abuse at a scale I never will. Torch-shaped, though, and the formats I keep meeting are the other four. |
| modelscan (2023-08) | broader format coverage, a company behind it | closest to what I wanted. No loader scan, no policy file where turning a rule off needs a written reason, and I needed both in a report. |

So: the non-torch formats, the loader call sites, SARIF I can feed into
my own tooling, and a config file that will not let me silence a rule
without saying why. Those four, and nothing else, are the reason this
is not a thin wrapper around somebody else's scanner.

## exit codes

| code | meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default: medium) |
| 1 | findings at or above it |
| 2 | usage, configuration or input error |

## docs

`docs/rules.md` (generated), `formats.md`, `weights-only.md`,
`loaders.md`, `keras.md`, `manifest.md`, `corpus.md`, `config.md`,
`performance.md`, `prior-art.md`, `taxonomy-map.md`,
`dependencies.md`, `failure-modes.md`, `triage.md`,
`working-on-this.md`, `stability.md`.
