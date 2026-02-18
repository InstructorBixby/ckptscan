# `ckptscan.toml`

Optional. Found in the working directory or any parent, or named with
`--config`, or ignored entirely with `--no-config`.

    fail_on = "high"

    [severity]
    "CKPT-002" = "low"

    [[suppress]]
    rule = "CKPT-002"
    paths = ["vendor/*.pt"]
    justification = '''
    Vendor ships its own serialiser classes in these checkpoints.
    Reviewed against their source in ticket PLT-412; the constructors
    take only numbers. Re-review when the vendor version changes.
    '''

    [allow]
    "ourpkg.serial.TensorBox" = '''
    Our own container class. __setstate__ assigns three numeric
    fields and calls nothing. Covered by a unit test.
    '''

## a justification is mandatory

Every scanner that has ever shipped has a config file full of disabled
rules, and nobody can remember which were disabled because the rule was
wrong and which because somebody wanted a green build on a Friday. Six
months later those two are indistinguishable, and the second kind is
how a real finding gets lost.

So `justification` is required, it has a minimum length, and a
suppression without one is a configuration error rather than a warning
-- the scan refuses to run. The same applies to an `[allow]` entry,
which is a stronger claim still: that calling this thing with arguments
an attacker chose is harmless.

Both appear in the output. `SUPPRESSED` lines in the human report and a
`suppressed` array in the JSON, each carrying its reason, so a report
shows what was hidden and why.

## writing one that is worth reading

The sentence you want in six months answers three things: what the
thing is, why calling it is harmless, and what would change that. The
third is the one people leave out and the only one that makes a
suppression expire. "Noisy" answers none of them and is rejected on
length alone, which is a crude proxy for effort and the best one
available.

## severity overrides

`[severity]` changes a rule's level for your repository. The honest use
is risk appetite: a research group that pickles its own classes
constantly may well run `CKPT-002` at `low` and mean it. The dishonest
use is lowering something to get under `fail_on`, which is why the
override is visible in the report rather than silently applied.

## order of operations

1. Suppressions are matched first. A suppressed finding never gets a
   severity.
2. Surviving findings get their configured severity.
3. `fail_on` is applied to the result.

Which means a suppression hides a finding from the report, and a
severity override only changes where it sits. Those are different acts
and the config keeps them separate.

## what cannot be configured

That the analysis is static. There is no setting that makes this tool
load a file, and there will not be.
