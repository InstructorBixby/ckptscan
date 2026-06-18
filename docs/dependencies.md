# What this drags in

Written down because every dependency this has is one I inherit in
every virtualenv I install it into, and because the answer to "why is
this install 90MB" should not require archaeology.

| | |
|---|---|
| runtime dependencies, base install | none |
| optional | `h5py` (`keras` extra), `onnx` (`onnx` extra) |
| dev | pinned in `constraints-dev.txt` |
| build | `setuptools`, through `python -m build` |

The base install having nothing in it is deliberate and worth keeping
that way. This gets installed next to whatever else is in the venv --
a torch of some pinned vintage, a numpy I did not choose -- and a
scanner that forces a resolver conflict is a scanner I stop running.
The format readers are extras for the same reason: `h5py` wants a
matching HDF5, and that is a fine thing to opt into and a terrible
thing to require.

## the install

    uv pip install -e .
    uv pip install -e ".[all]"       # plus the format readers

Editable, from the checkout, every time. There is nowhere else it
comes from.

## the thing I would attack

Me. The checkout is on a machine I control and the tag is signed with
nothing. If somebody has my machine they have the tool, and they also
have every checkpoint I was scanning with it, so the tool is not the
interesting part of that compromise.

Which is the same point `docs/prior-art.md` makes about scanning: a
control reduces the ways something can go wrong. It does not make a
thing trustworthy, and a tool in this space should be the last one to
imply otherwise.

## what a scan costs

Nothing at runtime beyond reading the file. `verify` hashes, which
means it reads every byte and is the only subcommand whose cost scales
with the size of the weights rather than their structure --
`docs/performance.md` has the numbers.
