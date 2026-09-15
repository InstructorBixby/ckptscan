# In a pipeline

Three things, answering different questions. The first one always; the
other two when they apply.

## 1. the checkpoints a repo carries or vendors

    include:
      - project: panic/ckptscan
        ref: v1.2.0
        file: /ci/ckptscan.gitlab-ci.yml

    ckptscan:
      variables:
        CKPTSCAN_PATH: weights
        CKPTSCAN_FAIL_ON: high

The SARIF comes out as a job artifact with `when: always`, which
matters: the job fails on findings, and without it the report goes in
the bin with the container and I have a red pipeline and nothing to
look at. From there it gets pulled into my own viewer; the instance is
CE and has no idea what a SARIF file is.

## 2. the loader call sites

    - ckptscan loaders ./src --project .

After the `weights_only` default flipped, this is the more informative
half. It finds the `weights_only=False` I added at 2am to make a legacy
checkpoint load, and it reads the torch pin so relying on the default
is scored against the version actually installed.

## 3. a published manifest, on a schedule

    - ckptscan verify ./weights --manifest SHA256SUMS

Hashing reads every byte, so this belongs in a scheduled pipeline
rather than on every push. It also has the strongest answer of the
three: a clean scan of the wrong file is worth nothing.

## the container, on a box whose python I do not trust

    podman run --rm --network none -v "$PWD:/work:ro,Z" \
      ckptscan:1.2.0 /work/weights

`--network none` works, because the scan is static and reads files.
Running it that way is the cheapest way to keep that claim honest.

## pin the include

A rule's *default severity* can change in a minor release --
`docs/stability.md`; it is calibration, not interface. In a pipeline
that means an unpinned include turns a recalibration into a red build
nobody asked for, and the response to that is deleting the job. Pin the
`ref`, and pin the rules that matter with `[severity]` in
`ckptscan.toml`.

## what to set fail-on to

| | |
|---|---|
| `critical` | a dangerous callable reached by a call. Almost no false positives; almost no coverage either. |
| `high` | adds staged imports, object arrays, Keras `Lambda`, loader opt-outs, traversing members. **The sensible default.** |
| `medium` | adds `CKPT-002` and the header checks. Correct for a review, noisy for a pipeline until the allowlist is tuned to that repository. |

Start at `high`, read the `medium` findings by hand for a week, move
the ones that are legitimately that repo's own into `[allow]` with a
reason, then drop to `medium` if it is worth it. In that order.

## --strict does not go in a pipeline

It raises every unrecognised call to high and ignores `[allow]`, so it
fires on every checkpoint any framework produced. It is a review
posture, not a pipeline posture. I will delete the job, and I will be
right to.
