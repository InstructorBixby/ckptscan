# Changelog

Keep a Changelog format, semver versions.

## [0.5.0]

### Added
- A rule registry. Every `CKPT-` id now has one documented entry
  with a title, a default severity, what was observed, why it
  matters and what to do. The severity of a rule had been living
  in three analysers and its documentation in none, and two of
  them had already drifted apart.
- `ckptscan rules`, and `docs/rules.md` generated from the
  registry with a CI check that fails when it is stale.
- JSON output, versioned, with the finding detail and the
  suppression list.
- SARIF 2.1.0 output. An internal location -- a zip member, a byte
  offset, a layer name -- goes in `logicalLocations` rather than
  being faked as a line number, because a fabricated line in a
  binary is worse than none. Severity survives the four-level
  mapping in `properties.severity` and `rank`.
- `ckptscan.toml`: `fail_on`, `[severity]` overrides,
  `[[suppress]]` and `[allow]`.
- **A suppression requires a justification**, with a minimum
  length, and a missing one is a configuration error rather than a
  warning. Suppressions appear in every output format with their
  reason attached.
- `--explain` prints the remediation with each finding;
  `--output`, `--no-color`, `NO_COLOR`.
- Two tests that keep the registry honest: every emitted rule id
  must be documented, and every documented id must be reachable.

## [0.4.0]

PyTorch 2.6 made `torch.load(weights_only=True)` the default
(released 2025-01-29). That is the largest improvement to this
problem that has happened and it makes the common case a refusal
instead of a shell. This release is about what is left.

### Added
- `ckptscan loaders`: an AST scan of Python source for load calls
  that turn the protection off. `weights_only=False` (`CKPT-013`),
  `numpy.load(allow_pickle=True)` (`CKPT-015`),
  `load_model(safe_mode=False)` (`CKPT-016`), and the bare
  pickle/joblib/dill loads that have no restricted mode at all
  (`CKPT-011`).
- Torch pin detection. Relying on the default is LOW on 2.6 or
  later and HIGH on an older pin, with the pin quoted in the
  message. An unknown pin changes nothing, because a guess must
  not lower a severity.
- Subcommands, with `ckptscan <path>` still meaning
  `ckptscan scan <path>`.
- `docs/weights-only.md`: an honest account of what the default
  fixes (most torch exposure by volume) and what it does not
  (opt-outs, old pins, Keras Lambda layers, ONNX custom ops, numpy
  object arrays, joblib, and everything already shipped).
- `docs/loaders.md`.

### Changed
- The README leads with what changed rather than implying nothing
  did, and the recommendation is now: ship safetensors, keep
  loaders current, do not pass the opt-out. Scanning is for the
  files you did not choose.

## [0.3.0]

### Added
- Keras saved models, which are the format where the code is not
  even hidden: a `Lambda` layer serialises a marshalled code
  object into the model config, and loading reconstructs it. No
  pickle is involved, so no amount of pickle hardening touches it.
  `CKPT-006`, critical, no benign reading.
- Both Keras containers. `.keras` is a zip holding `config.json`
  and is read precisely. `.h5` needs an HDF5 reader, which is the
  `ckptscan[keras]` extra; without it a raw-byte fallback finds
  the config string, and every finding it produces says that is
  what happened.
- `CKPT-018` for custom objects and registered names a loader has
  to resolve out of the importable world.
- ONNX: non-standard operator domains (`CKPT-007`) and custom-op
  libraries named in model metadata (`CKPT-018`). The risk here is
  not code in the file, it is that running the model as intended
  requires code from somewhere else.
- `docs/keras.md`, `docs/taxonomy-map.md`.

### Notes
- The ONNX reader is a minimal protobuf field walk over the two
  fields that matter, so the base install needs no `onnx`
  dependency. The fixtures are hand-written protobuf for the same
  reason.
- `docs/taxonomy-map.md` says plainly that most of these rules do
  not map onto `llm-redteam-notes` and explains why that is the
  right answer: that taxonomy is organised by the channel hostile
  text arrives through, and a pickle opcode never reaches a model.

## [0.2.0]

### Added
- Format detection from magic bytes, with the extension treated as
  a claim. A disagreement is `CKPT-008`, and a pickle named
  `.safetensors` is HIGH -- the name is usually the whole basis on
  which somebody decided a file was safe to load.
- Zip-based checkpoints: members opened without extracting,
  pickles analysed in place, member names checked for traversal
  (`CKPT-012`), implausible expansion ratios flagged
  (`CKPT-014`), and nested archives recursed into (`CKPT-010`).
- The legacy torch format, which is several pickle streams
  concatenated. `genops` stops at the first `STOP` -- the end of
  the magic number -- so the single-stream analysis read a long
  integer and reported clean while the payload sat in stream 2.
- `.npy` object-dtype detection (`CKPT-005`), and the pickle
  inside it analysed. `.npz` members too.
- joblib: the compressed containers unwrapped before analysis,
  since a format sniff on a zlib stream says nothing.
- safetensors header verification (`CKPT-017`) and GGUF header
  counts (`CKPT-019`). Both formats are safe by construction;
  neither has a code-execution rule, and neither exceeds MEDIUM.
- `docs/formats.md`, with a column for the only thing that matters.

### Notes
- The `.npy` header is parsed with `ast.literal_eval`. A header is
  attacker-controlled, and `eval` on it would be exactly the bug
  this tool exists to find, in this tool. A test asserts it.

## [0.1.0]

### Added
- Static pickle opcode analysis via `pickletools.genops`. Nothing
  is ever unpickled, imported or called, and there is a test that
  fails if that changes.
- A partial pickle stack model, so a call can be attributed to the
  global it calls rather than reported as a bare `REDUCE`. Handles
  `GLOBAL`, `STACK_GLOBAL` (which is what protocol 4 actually
  emits), `REDUCE`, `NEWOBJ`, `NEWOBJ_EX`, `INST`, `OBJ`, `BUILD`
  and the memo.
- An allowlist with a written reason on every entry, covering the
  callables that appear in every legitimate checkpoint:
  `collections.OrderedDict`, `torch._utils._rebuild_tensor_v2`,
  the storage and dtype markers, `copyreg._reconstructor`,
  `numpy.core.multiarray._reconstruct`, `argparse.Namespace`.
- Rules CKPT-001 through CKPT-004, with severities.
- `ckptscan` console script, `--fail-on`, exit codes 0/1/2.
- A fixture generator rather than committed payloads. Every
  payload is inert: it writes a marker file into a temporary
  directory and does nothing else.
