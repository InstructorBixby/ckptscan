# The allowlist

## what happened when I pointed it at everything I had

I built this expecting the hard problem to be detection. It is not.
A month of running it over the whole model directory, the engagement
archives and two caches I had forgotten about produced no true
positives and a great many false ones, in four shapes:

1. **`numpy._core.multiarray._reconstruct`.** numpy moved the module
   path. The old one was allowlisted, the new one was not, and every
   checkpoint built against a current numpy produced a `CKPT-002`. I
   looked at it on five separate files and talked myself out of it four
   times -- *probably that project doing something odd* -- before
   noticing it was the same name every time. That is the failure mode
   to remember: a false positive I half-explain is worse than one that
   stops me, because I stop reading.
2. **Framework helpers I had not met.** `torch._tensor._rebuild_from_type_v2`,
   `torch._utils._rebuild_wrapper_subclass`,
   `pandas.core.internals.blocks.new_block`,
   `sklearn.tree._tree.Tree`. Each legitimate, each in every
   checkpoint from that framework, each a `CKPT-002` on a file I had no
   business thinking about.
3. **Project-local classes.** Somebody's own `Config` dataclass,
   pickled into every checkpoint a research repo produces. Correctly
   reported -- it is genuinely not something I can vouch for -- and
   genuinely not worth looking at four hundred times.
4. **Me, at the end of a week, about to turn `CKPT-002` off
   entirely.** Which is the reasonable response to the first three and
   the end of the tool's usefulness. That is the afternoon this
   document comes from.

A scanner that fires on legitimate files gets switched off, and the
person switching it off is me. So the work since has been almost
entirely here, and the three things that came out of it are the shipped
table growing one false positive at a time, `[allow]` in the config for
project-local names, and `--strict` for the sessions where I want none
of it.

## what goes in the shipped table

Something **everything has**: a callable a named framework emits, that
turns up in checkpoints I did not author. A name that only one project
produces goes in that project's `ckptscan.toml`, not here -- otherwise
the shipped table stops being true on a machine that is not this one.

Each entry needs the five things in `docs/working-on-this.md`, and the
one I skip when I am tired is the fourth: *what does an attacker
control*. Every argument to a callable in a pickle comes from the file.
So:

| the callable | verdict |
|---|---|
| allocates a container from values | fine |
| assigns numeric fields in `__setstate__` | fine |
| takes a dtype or layout marker | fine |
| takes a path, even to read | **no** |
| takes a module or attribute name | **no** |
| calls anything it was handed | **no** |
| re-enters a loader | **no**, and see below |

## the one I nearly got wrong

`torch.storage._load_from_bytes` looks exactly like the others: it is
in the torch namespace, it has a leading underscore, it turns up in
legitimate files, and it sat next to the reconstruction helpers in my
notes with a tick against it. I had the entry written.

It calls `torch.load` on the bytes it is given.

So an allowlist entry for it is an allowlist entry for *anything*: a
checkpoint reaches arbitrary execution through a callable that reads as
a storage helper, and a scanner that allowlists it reports clean. It is
on the dangerous list now, with that sentence as its reason, and it is
the best argument I have for why every entry gets the attacker-control
question answered rather than a glance at the module name.

Four of the five checks would have passed it. The fourth is the one
that exists.

## provenance

Entries record where they came from, so a wrong one leads back to the
reasoning rather than to a date. `policy.ALLOW_SOURCES` maps a dotted
name to `core` for the ones written from the format itself, or to the
numbered false positive in my notes that produced it. Six months on I
cannot otherwise remember whether an entry came from reading the source
or from wanting a quiet scan.

## `--strict`

Ignores `[allow]` from the config, raises `CKPT-002` to high, and
reports allowlisted calls at info so I can see what was waved through.
For a first look at a file I have no reason to trust, which is a
different job from the check that runs over the whole directory.

`--strict` does not go in a pipeline. It fires on every checkpoint any
framework produced, and the next thing I do is delete the job.
