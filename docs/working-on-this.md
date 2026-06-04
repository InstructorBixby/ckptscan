# Working on this

## the loop

    uv pip install -e ".[dev,all]"
    pytest -q
    ruff check .
    mypy
    python scripts/regen_rules.py --check

## adding an allowlist entry

The change with the highest consequence, so it gets written down. An
allowlist entry is a promise that calling that callable with arguments
an attacker chose is harmless. Getting one wrong means a payload
reports clean, and I will not find out.

Five things, every time, before an entry goes in:

1. **The dotted name**, exactly as the opcode stream names it. Not the
   import path I would write -- the one in the file. They differ more
   often than I expect.
2. **Where it comes from.** A framework, a widely-used library, or my
   own code. My own code goes in that project's `ckptscan.toml`, not in
   the shipped table: the shipped allowlist is for things everybody
   has, so it stays true on a machine that is not this one.
3. **What it does when called.** Specifically. "It is a reconstruction
   helper" is not an answer; "it allocates a tensor from a storage, a
   size, a stride and an offset, and calls nothing" is.
4. **What an attacker controls.** Every argument comes from the file.
   If the callable does anything with a path, a command, an import, an
   attribute lookup by name, or a nested load, the answer is no.
5. **A corpus sample.** A clean sample that would fire without the
   entry, so the entry is covered by the test that keeps the clean half
   quiet.

The reason text goes in the code, not in the commit message, because a
test asserts every entry has one and because a commit message is not
where I will look in two years.

**Entries that never go in**, whatever the justification: anything in
`os`, `subprocess`, `importlib`, `runpy`, `marshal`, `pickle`,
`builtins.eval`/`exec`/`getattr`/`open`, `functools.partial`, or
`operator.attrgetter`. These are reachable to arbitrary effect by
construction. If a legitimate checkpoint needs one, the checkpoint
format is the problem.

## adding a rule

A registry entry with all five fields, at least one corpus sample, and
an entry in `docs/rules.md` -- which is generated, so run
`scripts/regen_rules.py`. The two meta-tests fail if an emitted id is
undocumented or a documented id is unreachable.

Think hard about the default severity. The thing that kills a scanner
is not a missed finding, it is a MEDIUM that fires on every legitimate
file, because then every finding gets ignored together.

## adding a format

One module under `ckptscan/analysers/`, a `sniff` case in
`ckptscan/detect.py` if it has magic bytes, a dispatch entry, and
corpus samples -- clean and unsafe. Prefer a stream to bytes; see
`docs/performance.md` for why.

If it needs a third-party reader, it goes in an extra, and the base
install must still work with a documented fallback or a clear INFO
finding saying what was not analysed. Silently skipping a format is not
acceptable: it reads as clean.

## what never changes

**The analysis is static.** Nothing goes in that imports, constructs or
calls anything a scanned file names, in any code path, under any flag.
`tests/test_corpus.py` and the execution test exist to catch me doing
it and are the last tests to touch.

## style

ruff with the configured rules, 88 columns, `mypy --strict` outside
`ckptscan/commands/`. Commit messages: what changed and why, lowercase,
no prefix convention.
