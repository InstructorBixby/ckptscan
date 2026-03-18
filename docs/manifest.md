# Verifying against a published manifest

    ckptscan verify ./model-dir --manifest SHA256SUMS
    ckptscan verify ./model-dir --manifest hashes.json

This is the cheapest useful thing the tool does and the one with the
strongest answer. Everything else here says what a file *would do*;
this says whether it is the file the publisher produced. A clean scan
of the wrong file is worth nothing, so do this first.

## what it accepts

| shape | example |
|---|---|
| `sha256sum` output | `9f2c...  model.safetensors` |
| JSON object | `{"model.safetensors": "9f2c..."}` |
| JSON object under `files` | `{"files": {"model.safetensors": {"sha256": "9f2c..."}}}` |
| JSON array | `[{"path": "model.safetensors", "sha256": "9f2c..."}]` |

The algorithm comes from the digest length -- md5, sha1, sha256,
sha512. md5 and sha1 are accepted because publishers still use them,
and a matching md5 is better than no check. It is not evidence against
a deliberate substitution, and if that is your threat model the
manifest needs to be signed, which is a different document.

## three findings, one rule

All three are `CKPT-009`, because the remediation for all three is "go
back to the publisher":

- **mismatch** -- the hash differs.
- **missing** -- the manifest lists it, the disk does not have it.
- **unlisted** -- the disk has it, the manifest does not list it.

The third is the one people want to switch off, and it is the one worth
keeping. Nothing stops a loader reading a file nobody published, and an
attacker who can add a file to a verified directory has not had to
change a single hash. `--allow-extra` exists because some publishers
genuinely ship a partial manifest, and it silences only that.

Dotfiles, dot-directories and the obvious companions -- `README.md`,
`LICENSE`, `.gitattributes` -- are not counted as unlisted.

## hashing is streamed

A 1 MiB chunk at a time. Reading a shard whole to hash it is the
easiest way to turn a scanner into an out-of-memory kill in somebody's
CI, and there is a test that asserts the read size.

## what a manifest does not tell you

That the publisher is honest. It binds the bytes you have to the bytes
they published, and if they published a pickle with `os.system` in it,
a matching hash confirms you received exactly that. Verify the manifest
*and* scan the contents; they answer different questions and neither
substitutes for the other.
