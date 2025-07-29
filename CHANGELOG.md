# Changelog

Keep a Changelog format, semver versions.

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
