# Scanning the call sites

    ckptscan loaders ./src
    ckptscan loaders ./src --project .      # where the torch pin lives

After the `weights_only` default flipped, the file stopped being the
most informative half of the finding. Almost every checkpoint in
existence is a pickle, and a current loader refuses to execute it. The
question that distinguishes an exposed project from a safe one is
whether its own code turns that off.

## what it looks for

| rule | what |
|---|---|
| `CKPT-013` | `torch.load` with `weights_only=False`, or relying on the default |
| `CKPT-015` | `numpy.load(allow_pickle=True)` |
| `CKPT-016` | `load_model(safe_mode=False)` -- deserialises Keras `Lambda` layers |
| `CKPT-011` | `pickle.load`, `joblib.load`, `dill.load`, `pandas.read_pickle` -- no restricted mode exists |

## the pin changes the severity

`torch.load(p)` with no `weights_only` is a refusal on 2.6 and later
and arbitrary execution on anything earlier. Reporting both at one
severity is useless in both directions, so this reads the project's
torch pin out of `pyproject.toml`, `requirements*.txt`,
`constraints*.txt` or a lockfile and adjusts:

| pin | severity of relying on the default |
|---|---|
| 2.6 or later | low |
| earlier than 2.6 | high, with the pin quoted in the message |
| unknown | low -- unchanged, because a guess must not lower anything |

The pin reader is crude on purpose. It takes the *oldest* torch any
file in the project would allow, since that is the one that decides
what happens in the worst case, and an unreadable pin is unknown rather
than assumed current.

## AST, not grep

`weights_only` can arrive as a keyword, in a `**kwargs` splat, through
a variable, or not at all, and those are four different findings. A
regex sees one. The AST walk reports:

- a literal `False`: HIGH, no ambiguity
- absent: LOW or HIGH depending on the pin
- a splat or a variable: MEDIUM, "cannot be determined from this call"

That last row is deliberate. Constant propagation across a module is a
different kind of tool, and a scanner that guesses a severity wrong is
worse than one that says it does not know.

## what it does not look for

Dynamic dispatch. `getattr(torch, "load")(p)`, a loader behind a
registry, a `functools.partial` built elsewhere. All findable in
principle and all a different project.

It also does not read vendored code: anything under `.venv`,
`site-packages`, `build`, `dist` or `node_modules` is skipped.
Reporting a library's internal `torch.load` to the person who installed
it is noise -- though if the library is the one you are auditing, point
it at the library's own source directory.

## the two halves

A `CKPT-002` in a checkpoint and a `CKPT-013` at the call site that
loads it are one finding written twice. The checkpoint scan tells you
what a file would do; this tells you whether your code would let it.
Neither on its own is a conclusion.
