# Mapping these rules onto `llm-redteam-notes`

Short version: most of them do not map, and that is the correct answer
rather than a gap to be filled.

That taxonomy is organised by **the channel hostile text arrives
through** -- the user turn, retrieved content, a tool description, the
model's own output. A pickle opcode is not text in a context window. It
never reaches a model at all; it executes in the process that was
trying to load some weights. Forcing a mapping would make the ids mean
less, and the ids are quoted in reports.

So findings carry a `taxonomy` field, it is usually empty, and these
are the cases where it is not.

| rule | id | why it genuinely maps |
|---|---|---|
| `CKPT-006` | `OUT-003` | a Keras `Lambda` layer is a serialised code object that the loader reconstructs and executes. "Model output executed" is the same primitive one level up: content from an untrusted artefact becomes code in the host process. |
| any finding whose payload reaches a network primitive | `EX-004` | a load-time payload that resolves a name or opens a socket is using the same exfiltration channel as everything in that group, and the detection advice transfers directly. |

## defences that do map

The remediation side lines up much better than the finding side,
because the defences are about the system rather than the channel.

| this tool says | taxonomy entry | the connection |
|---|---|---|
| ship safetensors | `DEF-005` capability reduction | the loader loses the ability to execute, rather than gaining the ability to detect. The strongest form of the fix, and the one worth arguing for. |
| verify against a published checksum list | `DEF-007` provenance marking | the point is knowing where an artefact came from; a hash list is the crudest and most reliable version of that. |
| watch what a load does on the network | `DEF-011` egress control | `egress-ledger` over a `torch.load` in a container answers "did it phone anywhere", which is the one question static analysis cannot. Useful as a second opinion, never as the first. |

## why this document exists at all

Because the alternative is a column of invented ids in a report, and
because the question "where does this fit in your taxonomy" gets asked
every time both tools appear in the same engagement. The answer "it
does not, here is why, and here are the three places it does" is worth
more than a mapping table that is 80% fabricated.
