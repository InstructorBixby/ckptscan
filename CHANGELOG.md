# Changelog

Keep a Changelog format, semver versions.

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
