# Changelog

Keep a Changelog format, semver versions.

## [1.3.0]

### Added
- `docs/summary.md`: the three things to do instead of running a
  scanner, in order, and where scanning actually fits. A tool's
  own documentation is the wrong place to argue that the tool is
  the answer, and the mistake I see most often is a scanner in CI,
  a green build, and `weights_only=False` three directories away.

### Changed
- `docs/index.md` leads with the three documents worth reading
  before installing anything.

## [1.2.1]

### Fixed
- SARIF results carried no `partialFingerprints`. Because these
  results deliberately have no line number -- a fabricated line in
  a binary is worse than none -- a viewer was identifying them by
  location alone, so every finding in one file collapsed onto a
  single identity: two findings showed as one, and re-scanning a
  directory closed and reopened the same alert.

  The fingerprint is the rule, the artifact and the internal
  location, which is the identity a human would use. It
  deliberately excludes the message and the byte offset, since a
  message gets reworded between releases and an offset moves when
  a file is rebuilt, and either would make a viewer close an alert
  and open a new one for the same thing.

## [1.2.0]

Plumbing. No change to detection.

### Added
- `scripts/release.sh`: refuses to tag from a dirty tree, or when
  `pyproject.toml`, `__init__` and the changelog disagree about
  the version. I have tagged, pushed, and then found the version
  still said the old number. Twice.
- **The release script runs the corpus.** A version that cannot
  detect its own unsafe samples, or that fires on its own clean
  ones, does not get a tag. This has stopped me once, on a
  false-positive fix that quietly broke a detection.
- `scripts/image.sh` and a `Containerfile`: a local podman image
  with the format extras installed, running as a non-root user,
  for the boxes where I do not want to argue with the system
  Python. The build makes the image scan its own corpus through
  the entrypoint with `--network none`, which is a cheap way to
  keep the static-analysis claim honest.
- `ci/ckptscan.gitlab-ci.yml`: a job template the other
  repositories with weights in them can `include:`, with the ref
  pinned and the report kept as an artifact `when: always` -- a
  check that swallows its own evidence is worse than no check.
- `.pre-commit-hooks.yaml`, with `scan` and `loaders` as separate
  hooks.
- The docs build as a site, with `--strict` and with the generated
  rule reference checked for staleness first, so I can read them
  without a checkout.
- `docs/dependencies.md`, `docs/ci.md`, including what to set
  `--fail-on` to and in what order to tighten it.

## [1.1.0]

A month of pointing this at everything I own produced no true
positives and a great many false ones. A scanner that fires on
legitimate files gets switched off, and the person switching it
off is me, so this release is almost entirely about that.

### Fixed
- `numpy._core.multiarray._reconstruct`. numpy moved the module
  path; the old one was allowlisted and the new one was not, so
  every checkpoint built against a current numpy produced a
  finding. I looked at it on five separate files and talked
  myself out of it four times before noticing it was one name.

### Added
- Fourteen allowlist entries, each from a false positive on a
  file of my own:
  `torch._tensor._rebuild_from_type_v2`, the tensor-subclass
  rebuilders, `torch.nn.parameter.Parameter`, the pandas block and
  manager constructors, `sklearn.tree._tree.Tree`,
  `scipy.sparse._csr.csr_matrix`, `datetime`, `pathlib` path
  objects and `TrainingArguments`.
- `policy.ALLOW_SOURCES`: every entry records where it came from,
  `core` or the issue, so a wrong one can be traced to the
  reasoning.
- `[allow]` in `ckptscan.toml` is now honoured by the scanners, so
  a project's own classes stop being a finding four hundred times.
  A local entry can never silence a *dangerous* call.
- `--strict`: raises unrecognised calls to high, ignores `[allow]`
  from the config, and reports what the shipped allowlist waved
  through as `CKPT-020` (info) with the entry's source. For a
  one-off review of a file from a source you do not trust; the
  docs say plainly not to put it in CI.
- `docs/allowlist.md`: the policy, the four shapes the reports
  took, and the attacker-control question that settles an
  argument.

### Changed
- **`torch.storage._load_from_bytes` is now explicitly
  dangerous.** Somebody sent a patch allowlisting it: it is in the
  torch namespace, it has a leading underscore, and it appears in
  legitimate files. It calls `torch.load` on the bytes it is
  given, so allowlisting it would allowlist arbitrary execution
  behind a name that reads like a storage helper. The same applies
  to `torch.serialization.load`, `torch.jit.load` and
  `torch.hub.load_state_dict_from_url`.
- `functools.partial`, `functools.reduce` and `operator.call` are
  on the dangerous list as indirection.

## [1.0.0]

No new detection. The rule ids, the JSON schema, the exit codes
and the config file have been unchanged for months, and by now
enough of my own scripts shell out to this that a rename here
breaks my work three directories away. Version numbers only mean
something once they start making promises.

### Added
- Full packaging metadata, `py.typed`, and a declared public API
  re-exported from `ckptscan`.
- `mypy --strict` outside the command modules, coverage with a
  floor, Python 3.13 in the matrix, and a CI job that runs the
  suite *with* the optional readers installed as well as without.
  The suite has broken one way and not the other twice.
- LICENSE (MIT), and `docs/working-on-this.md` -- the loop, and
  the rules I hold myself to.
- **A written rule for adding an allowlist entry**, with the five
  things an entry needs and the list of modules no justification
  gets past. The allowlist is the product and I was extending it
  by vibes at midnight.
- `docs/prior-art.md`: what I looked at before writing this --
  picklescan (2023-02) and modelscan (2023-08), both of which got
  here first, and the restricted unpickler, which is better than
  any of them because it removes the capability instead of
  detecting the problem.
- `docs/stability.md`, `docs/install.md`, `docs/triage.md`,
  `docs/failure-modes.md`, `docs/dependencies.md`.

### Stability
- Fixed from here: rule ids, exit codes, the JSON schema and its
  `schema_version`, SARIF 2.1.0 conformance, the `ckptscan.toml`
  sections, the subcommand names, the re-exported Python API, and
  that the analysis is static -- which is a promise, not an
  implementation detail.
- A rule's *default severity* can change in a minor release. It is
  calibration, not interface; `[severity]` pins anything a
  pipeline of mine depends on, and a raise never happens in a
  patch.

## [0.7.0]

### Fixed
- **Out-of-memory on a sharded model.** Reported from somebody
  else's machine against a 70B checkpoint: a 9 GiB shard was being
  read whole so a function could look at the first few hundred
  opcodes of it. `pickletools.genops` accepts a file object and
  always did. Nothing now materialises a file to analyse it, and
  the same mistake in the archive analyser -- reading each zip
  member into bytes before parsing -- is gone too.
- The legacy-torch analyser seeks between concatenated streams
  instead of slicing the file, so it no longer needs the whole
  thing either.

### Added
- `--jobs`: parallel scanning for sharded models, with a thread
  pool. Output order does not depend on it, and a test asserts the
  serial and parallel JSON are byte-identical -- a report that
  shuffles between runs cannot be diffed, and diffing two reports
  is most of what anyone does with them.
- A file in a format that genuinely needs reading whole, above
  2 GiB, is reported as `CKPT-014` rather than attempted. A
  scanner that gets OOM-killed reports nothing at all.
- `docs/performance.md`, including what is actually slow (hashing
  in `verify`, not the opcode walk).

## [0.6.0]

### Added
- `ckptscan verify`: a directory against a published checksum
  list (`CKPT-009`). `sha256sum` output or JSON, in three shapes,
  with the algorithm taken from the digest length. The cheapest
  useful thing here and the one with the strongest answer -- a
  clean scan of the wrong file is worth nothing.
- A file present on disk and absent from the manifest is reported,
  not ignored. Adding a file to a verified directory changes no
  hash, and nothing stops a loader reading it. `--allow-extra`
  silences only that.
- Manifest hashing is streamed at 1 MiB, with a test asserting the
  read size. Reading a shard whole is the easiest way to turn a
  scanner into an out-of-memory kill in somebody's CI.
- `ckptscan-mkcorpus`: the sample corpus promoted out of the test
  fixtures. Twenty-odd checkpoints, generated on demand, never
  committed, with a manifest recording the rules each must
  produce.
- Every payload in the corpus is inert -- a marker write and
  nothing else -- and there is a test that greps the generator's
  own source for network and deletion calls.
- A CI job that generates the corpus, asserts every unsafe sample
  still fires through the installed console script, and asserts
  the clean half stays silent in the same run. A change that fixes
  a false positive by breaking a detection cannot pass.
- `docs/manifest.md`, `docs/corpus.md`.

### Changed
- The per-format test fixtures are gone; the tests use the
  corpus. Two sets of sample files meant two things to update and
  they had already diverged once.

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
