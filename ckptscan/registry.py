"""Every rule, in one place, with its default severity and its fix.

Rule ids were being defined by whichever analyser emitted them, which
meant the severity of `CKPT-013` lived in three files and the
documentation lived in none. A rule id gets quoted in a ticket and in a
policy file, so it is a public interface.

Each entry carries:
  title        one line, for a report heading
  default      the severity an analyser emits unless it has a reason
  what         what was observed
  why          why it matters, or why it might not
  fix          what to actually do, in order of preference
"""
from __future__ import annotations

from dataclasses import dataclass

from ckptscan.findings import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    default: str
    what: str
    why: str
    fix: str

    @property
    def number(self) -> int:
        return int(self.id.rsplit("-", 1)[-1])


def _rule(rid, title, default, what, why, fix) -> Rule:
    return Rule(id=rid, title=title, default=default, what=what,
                why=why, fix=fix)


RULES: dict[str, Rule] = {r.id: r for r in [
    _rule("CKPT-001", "Call to a known-dangerous callable",
          Severity.CRITICAL,
          "A call opcode in a pickle stream reaches a callable on the "
          "dangerous list -- os.system, subprocess, eval, a network "
          "primitive, a nested unpickler.",
          "This is not a heuristic. Loading the file with an "
          "unrestricted unpickler runs that call with arguments the "
          "file chose. There is no legitimate reason for a weights "
          "file to do this.",
          "Do not load it. Obtain the weights from a source you can "
          "verify, or convert from a copy you trust to safetensors. If "
          "this is your own file, find what put it there."),
    _rule("CKPT-002", "Call to a callable that is not on the allowlist",
          Severity.MEDIUM,
          "A call opcode reaches a callable this tool does not "
          "recognise.",
          "Often legitimate: a project with its own classes pickles "
          "them, and no allowlist can know every project's classes. "
          "Also exactly what a payload looks like when it reaches "
          "execution through something unusual. The point of the rule "
          "is to put the decision in front of a human.",
          "Look at the name. If it belongs to the project that "
          "produced the checkpoint, add it to a local allowlist with "
          "a written reason. If you cannot account for it, treat it as "
          "CKPT-001."),
    _rule("CKPT-003", "Import of a dangerous module, not called here",
          Severity.HIGH,
          "A dangerous module is imported by the stream but no call "
          "opcode in this stream consumes it.",
          "An import is not nothing: it executes the module's top "
          "level. It is also how a payload is staged, with the call in "
          "another stream or another member of the same archive.",
          "Treat as CKPT-001 unless you can account for the import."),
    _rule("CKPT-004", "Stream truncated, malformed or unparseable",
          Severity.LOW,
          "The opcode stream ended early, hit the opcode budget, or "
          "could not be parsed at all.",
          "Usually a corrupt download or a format this tool guessed "
          "wrong about. Occasionally deliberate: a stream that a "
          "parser rejects and a loader accepts is a way past a "
          "scanner.",
          "Re-download and re-scan. If it is reproducible, the file is "
          "not loadable either and should be treated as hostile until "
          "explained."),
    _rule("CKPT-005", "Object-dtype numpy array",
          Severity.HIGH,
          "An .npy or .npz member whose dtype is object, which means "
          "its contents are a pickle.",
          "Loading it requires allow_pickle=True, and then it "
          "executes. An array of numbers never needs this.",
          "Re-save the data with a numeric dtype. If the array really "
          "holds Python objects, that is a data-format problem, not a "
          "loader flag to set."),
    _rule("CKPT-006", "Keras Lambda layer",
          Severity.CRITICAL,
          "A Lambda, TFOpLambda or SlicingOpLambda layer in a saved "
          "model config.",
          "The config carries a marshalled code object. Loading the "
          "model reconstructs it and it becomes callable. No pickle is "
          "involved, so pickle hardening does not touch it.",
          "Rebuild the layer as a Layer subclass that lives in your "
          "own code, and load with safe_mode on. Do not pass "
          "safe_mode=False to make the error go away."),
    _rule("CKPT-007", "Unrecognised format or non-standard operator "
          "domain",
          Severity.MEDIUM,
          "Either a file whose format could not be identified, or an "
          "ONNX operator domain no standard runtime implements.",
          "An unidentified file was not analysed, which is not the "
          "same as clean. A custom operator domain means running the "
          "model as intended requires a shared library from "
          "somewhere.",
          "For a format: identify it, and note it down if it should "
          "be supported. For a domain: find out what provides it "
          "before installing anything."),
    _rule("CKPT-008", "Declared format does not match the magic bytes",
          Severity.MEDIUM,
          "The extension claims one format and the bytes are another.",
          "Sometimes harmless -- a .bin is a zip about half the time. "
          "The interesting direction is a pickle named .safetensors, "
          "because the name is usually the entire basis on which "
          "somebody decided the file was safe to load. That direction "
          "is HIGH.",
          "Rename it to what it is, then scan it again as that."),
    _rule("CKPT-010", "Nested archive inside a checkpoint",
          Severity.MEDIUM,
          "An archive member that is itself an archive, with findings "
          "inside it.",
          "There is no legitimate reason for a checkpoint to be "
          "wrapped this way. The structure is evidence independently "
          "of what is inside it: it is what you build when you know a "
          "scanner looks one level deep.",
          "Treat the inner findings at their own severity and treat "
          "the nesting as a reason to distrust the source."),
    _rule("CKPT-011", "Unrestricted deserialisation call",
          Severity.MEDIUM,
          "pickle.load, joblib.load, dill.load or pandas.read_pickle "
          "in source code.",
          "No restricted mode exists for these calls. Whatever they "
          "are given executes. Whether that matters depends entirely "
          "on where the input comes from, which this cannot see.",
          "Change the format. For sklearn, ONNX or skops; for arrays, "
          "safetensors or a numeric npy. If the input is genuinely "
          "trusted, say so in a comment next to the call and silence "
          "the rule with a justification."),
    _rule("CKPT-012", "Archive member escapes the archive root",
          Severity.HIGH,
          "A zip member whose name is absolute or contains a .. "
          "segment.",
          "Any loader that extracts rather than streams will write "
          "outside the destination. This tool only reads, so the "
          "finding is about the loader downstream.",
          "Do not extract it. If you must, use a loader that rejects "
          "absolute and traversing member names."),
    _rule("CKPT-013", "Loader opts out of the restricted unpickler",
          Severity.HIGH,
          "torch.load with weights_only=False, or relying on the "
          "default where the project pins a torch older than the one "
          "that made it restricted.",
          "The restricted unpickler is the single most effective "
          "control available for this class, and this is the code that "
          "turns it off. Usually added to make a legacy checkpoint "
          "load.",
          "Re-save the checkpoint as tensors only, or as safetensors, "
          "then remove the flag. If the checkpoint must carry objects, "
          "load it once in an isolated environment and convert it."),
    _rule("CKPT-014", "Implausible archive member size",
          Severity.LOW,
          "A member whose declared size is enormous, or whose "
          "expansion ratio is extreme.",
          "A loader that reads the member whole may not survive it. "
          "Not code execution; a resource problem with a cheap fix.",
          "Cap what the loader will read. This tool declines to read "
          "it either, so the member was not analysed."),
    _rule("CKPT-015", "numpy.load with allow_pickle=True",
          Severity.HIGH,
          "A call that enables pickle execution inside numpy's "
          "loader.",
          "Equivalent to weights_only=False, for numpy. Normally added "
          "because an array turned out to hold objects.",
          "Fix the data so the array has a numeric dtype, then remove "
          "the flag."),
    _rule("CKPT-016", "Keras loader with safe_mode=False",
          Severity.HIGH,
          "load_model, model_from_json or model_from_config with "
          "safe_mode=False.",
          "This is what deserialises a Lambda layer, which is what "
          "runs the code object in the model config. Widely "
          "recommended on the internet as the fix for a load error, "
          "which is the whole problem.",
          "Rebuild the Lambda layers as real layers in your own code. "
          "The error is the control working."),
    _rule("CKPT-017", "safetensors header inconsistency",
          Severity.MEDIUM,
          "Tensor offsets outside the payload, overlapping spans, a "
          "header longer than the file, or a header that is not a JSON "
          "object.",
          "The format cannot execute anything, so this is never code "
          "execution. It is a parser problem for whatever reads it "
          "next, and a sign the file is corrupt or hand-made.",
          "Re-save or re-download. Deliberately capped below HIGH: "
          "treating a header quirk in a safe format as seriously as "
          "os.system in a pickle would make this tool's own "
          "recommendation unusable."),
    _rule("CKPT-018", "Loader must resolve something from outside",
          Severity.HIGH,
          "A Keras registered_name or custom object, or an ONNX "
          "custom-op library named in model metadata.",
          "Loading the artefact as intended means importing or loading "
          "code the artefact names but does not contain. Where that "
          "code comes from is the finding.",
          "Establish what provides it and whether you trust that, "
          "before installing anything. Prefer an artefact that uses "
          "only framework-provided components."),
    _rule("CKPT-019", "GGUF header inconsistency",
          Severity.MEDIUM,
          "Tensor or metadata counts that do not fit the file, or a "
          "version this tool does not read.",
          "Like CKPT-017: the format cannot execute anything, so this "
          "is corruption or a hand-made file, not execution.",
          "Re-download. If the counts are deliberate, the file will "
          "not load either."),
_rule("CKPT-009", "File does not match the published manifest",
      Severity.HIGH,
      "A checksum mismatch against a manifest, a file in the "
      "manifest that is missing on disk, or a file on disk that "
      "the manifest does not mention.",
      "Static analysis answers 'what would this file do'. It "
      "cannot answer 'is this the file they published', and that "
      "is the cheaper question with the stronger answer. An extra "
      "file beside a verified set matters as much as a changed "
      "one: nothing stops a loader reading it.",
      "Re-download from the publisher and compare again. Do not "
      "proceed on a mismatch because the content looks fine -- a "
      "clean scan of the wrong file is worth nothing."),
]}


def default_severity(rule_id: str) -> str:
    rule = RULES.get(rule_id)
    return rule.default if rule else Severity.MEDIUM


def unknown_ids(ids) -> list:
    return sorted(set(ids) - set(RULES))
