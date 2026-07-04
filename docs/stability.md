# What I am not allowed to break

From 1.0, these are fixed and change only in a major version.

The reason this document exists is not an audience. It is that *my own
things call this*: the engagement scaffold shells out to `ckptscan` and
reads its exit code, the review notes template greps the JSON, a
handful of one-off scripts parse the SARIF, and two other repositories
import `scan_path` directly. Renaming a flag here breaks my own work
three directories away, at the worst possible moment, and I will have
forgotten this ever changed. So the shims stay.

## the things that are load-bearing

- **Rule ids.** `CKPT-001` means what `docs/rules.md` says it means,
  forever. An id is never reused for a different meaning and never
  renumbered. A retired rule stays in the registry marked retired.
- **Exit codes** 0, 1 and 2.
- **The JSON output schema**, and its `schema_version`. Fields may be
  added; existing fields keep their meaning.
- **The SARIF output** conforming to 2.1.0, with rule ids as `ruleId`.
- **`ckptscan.toml`**: the `fail_on`, `[severity]`, `[[suppress]]` and
  `[allow]` sections, and the mandatory justification.
- **The subcommand names** and the meaning of each.
- **The Python API** re-exported from `ckptscan`: `scan_file`,
  `scan_path`, `scan_loaders`, `Finding`, `Severity`, `Rule`, `RULES`,
  `Config`, `reach_of`. Importing a submodule directly is my own
  problem, which is why the list exists.
- **That the analysis is static.** This is a promise, not an
  implementation detail, and nothing will ever make it optional.

## not load-bearing

- the human-readable output text, beyond the rule id and the severity
  word
- `ckptscan.opcodes`, `ckptscan.policy`, `ckptscan.detect`,
  `ckptscan.analysers.*` -- internals, and expected to move
- anything under `ckptscan.commands`
- the exact *contents* of the allowlist, which will keep changing; what
  is stable is that every entry has a reason

## a default severity can change in a minor release

This is the one that looks wrong. A rule's default severity is
calibration, not interface: when a month of real files shows a rule is
noisier or more serious than I pitched it, the right move is to change
it, and waiting for a major release means living with a known-bad
calibration for a year.

What keeps that from biting: `[severity]` in `ckptscan.toml` pins any
rule I depend on, every change is called out under `### Changed` in the
changelog, and a *raise* never happens in a patch release. Any gate of
mine that cares about an exact level pins it in the engagement's own
config, not here.

## deprecation policy

| | |
|---|---|
| notice period | at least two minor releases, and at least one in which the replacement exists -- long enough that I will have run the old spelling at least once in between and seen the warning |
| a renamed CLI flag | the old spelling keeps working and prints one line to stderr |
| a renamed JSON field | both are emitted for the whole notice period; the old one goes in a major release |
| a retired rule | stays in the registry marked retired, emits nothing, and a config that mentions it keeps loading |
| a removed subcommand | kept as a stub that says what to run instead |
| a changed exit code | major only, no exceptions |

Deprecation warnings go to **stderr and never to stdout**. Something
parses stdout -- the SARIF goes into my own viewer, the JSON into the
report scaffold -- and a warning inside a JSON document is a breaking
change dressed as a courtesy. It cost me an afternoon once, in the
other direction, on a different tool. For the same reason a deprecation
never changes an exit code: a pipeline that starts failing over a
rename is a pipeline I switch off in irritation, and a switched-off
check catches nothing.
