"""What is dangerous, and what is normal.

Two tables, and they are not symmetrical.

DANGEROUS is partly a convenience: it lets a report say "this calls
os.system" rather than "something I do not recognise", and it drives a
higher severity. It is NOT the detector -- a payload reaching execution
through something not on this list is still a finding, because the
actual rule is "not on the allowlist". It is also partly load-bearing:
a few entries are there specifically because they *look* allowlistable
and are not.

ALLOW is the product. Every entry is a promise that calling that
callable with arguments an attacker chose is harmless, so each carries
a written reason and a record of where it came from. See
docs/allowlist.md for the reasoning and docs/working-on-this.md for the
five things an entry needs before it goes in.
"""
from __future__ import annotations

DANGEROUS: dict[tuple[str, str], str] = {}


def _danger(module: str, attrs: str, why: str) -> None:
    for attr in attrs.split():
        DANGEROUS[(module, attr)] = why


_danger("os", "system popen execv execve execl execlp spawnl spawnv "
        "fork forkpty posix_spawn remove unlink rmdir rename chmod "
        "putenv", "operating-system call")
_danger("posix", "system execv fork spawnv", "operating-system call")
_danger("nt", "system spawnv", "operating-system call")
_danger("subprocess", "Popen run call check_call check_output "
        "getoutput getstatusoutput", "process execution")
_danger("builtins", "eval exec compile __import__ open getattr "
        "setattr input breakpoint memoryview",
        "arbitrary evaluation or attribute reach")
_danger("__builtin__", "eval exec compile __import__ open getattr "
        "apply execfile", "arbitrary evaluation (python 2 names)")
_danger("importlib", "import_module __import__", "dynamic import")
_danger("runpy", "_run_code _run_module_code run_path run_module",
        "module execution")
_danger("pty", "spawn", "process execution")
_danger("socket", "socket create_connection", "network")
_danger("urllib.request", "urlopen urlretrieve", "network fetch")
_danger("requests", "get post request", "network fetch")
_danger("httplib", "HTTPConnection", "network")
_danger("http.client", "HTTPConnection HTTPSConnection", "network")
_danger("ftplib", "FTP", "network")
_danger("smtplib", "SMTP", "network")
_danger("shutil", "copy copyfile move rmtree chown",
        "filesystem modification")
_danger("pickle", "load loads Unpickler", "nested unpickling")
_danger("dill", "load loads", "nested unpickling")
_danger("base64", "b64decode decodebytes",
        "stage two of a decode-then-execute chain")
_danger("codecs", "decode encode", "decode chain")
_danger("marshal", "loads load", "code-object loading")
_danger("types", "CodeType FunctionType",
        "constructs a callable from parts")
_danger("functools", "partial reduce",
        "indirection to another callable")
_danger("operator", "attrgetter itemgetter methodcaller call",
        "attribute reach")
_danger("sys", "modules exit", "interpreter state")
_danger("webbrowser", "open", "launches a program")
_danger("timeit", "timeit", "evaluates a string")
_danger("platform", "popen", "process execution")
_danger("bdb", "set_trace", "debugger entry")
_danger("pdb", "run runeval set_trace", "evaluates a string")

# Deliberately here rather than on the allowlist. I had the allowlist
# entry written: it is in the torch namespace, it has a leading
# underscore, and it turns up in legitimate files, so it reads exactly
# like the reconstruction helpers next to it.
#
# It calls torch.load on the bytes it is given. An allowlist entry for
# it is an allowlist entry for anything.
_danger("torch.storage", "_load_from_bytes",
        "calls torch.load on bytes from the file, so allowlisting it "
        "would allowlist arbitrary execution behind a name that looks "
        "like a storage helper (docs/allowlist.md)")
_danger("torch.serialization", "load _load",
        "re-enters the loader from inside the stream being loaded")
_danger("torch.jit", "load", "loads and runs a TorchScript module")
_danger("torch.hub", "load load_state_dict_from_url",
        "fetches and loads from a URL the file chooses")


#: (module, attr) -> why this is safe to be called by a checkpoint.
ALLOW: dict[tuple[str, str], str] = {}
#: (module, attr) -> where it came from. "core", or the numbered
#: false positive in my own notes that produced the entry.
ALLOW_SOURCES: dict[tuple[str, str], str] = {}


def _allow(module: str, attrs: str, why: str,
           source: str = "core") -> None:
    for attr in attrs.split():
        ALLOW[(module, attr)] = why
        ALLOW_SOURCES[(module, attr)] = source


_allow("collections", "OrderedDict defaultdict deque Counter",
       "container construction; a state dict IS an OrderedDict and "
       "every real PyTorch checkpoint calls this")
_allow("builtins", "dict list set tuple frozenset bytearray bytes "
       "str int float bool complex", "builtin container or scalar")
_allow("__builtin__", "dict list set tuple frozenset object",
       "builtin container (python 2 names)")
_allow("copyreg", "_reconstructor",
       "the standard reconstruction helper; takes a class, a base and "
       "a state, and the class it is handed is itself resolved and "
       "checked as a global")
_allow("torch._utils", "_rebuild_tensor _rebuild_tensor_v2 "
       "_rebuild_parameter _rebuild_sparse_tensor "
       "_rebuild_sparse_csr_tensor _rebuild_meta_tensor_no_storage "
       "_rebuild_qtensor _rebuild_device_tensor_from_numpy",
       "tensor reconstruction; appears hundreds of times in any real "
       "checkpoint. Takes sizes, strides and a storage offset, which "
       "a hostile file can make inconsistent -- that is a loader "
       "memory-safety concern, not code execution, and it is why a "
       "clean report says 'no load-time execution reachable' rather "
       "than 'safe'")
_allow("torch", "FloatStorage DoubleStorage HalfStorage BFloat16Storage "
       "LongStorage IntStorage ShortStorage CharStorage ByteStorage "
       "BoolStorage ComplexFloatStorage ComplexDoubleStorage "
       "float32 float64 float16 bfloat16 int64 int32 int16 int8 uint8 "
       "bool device Size", "storage and dtype markers, pure data")
_allow("torch.serialization", "_get_layout", "layout marker")
_allow("numpy.core.multiarray", "_reconstruct scalar",
       "the numpy array reconstruction helper, present in essentially "
       "every checkpoint that stores a numpy array")
_allow("numpy", "ndarray dtype float32 float64 int64 int32 bool_",
       "array type and dtype markers")
_allow("argparse", "Namespace",
       "training scripts routinely pickle their parsed arguments "
       "into the checkpoint; Namespace construction is data")

# --- added one at a time, each from a false positive on a file of
# --- mine. The numbers are the entries in my own notes.

_allow("numpy._core.multiarray", "_reconstruct scalar",
       "the same reconstruction helper under the module path numpy "
       "moved it to. I looked at this on five separate files and "
       "half-explained it away four times before noticing it was one "
       "name, which is the exact shape of false positive that trains "
       "me to stop reading",
       source="fp-12")
_allow("numpy._core.numeric", "_frombuffer",
       "builds an array from a buffer, a dtype and a shape; calls "
       "nothing and reads only the buffer it is handed",
       source="fp-12")
_allow("torch._tensor", "_rebuild_from_type_v2",
       "the reconstruction path for tensor subclasses. Takes a "
       "callable as its first argument -- which would normally be "
       "disqualifying -- but that callable is itself pushed as a "
       "global and so is resolved and classified independently, so "
       "the indirection is visible rather than hidden",
       source="fp-19")
_allow("torch._utils", "_rebuild_wrapper_subclass "
       "_rebuild_qtensor_from_dtype",
       "tensor-subclass reconstruction; sizes, strides, dtypes and a "
       "storage, same shape as _rebuild_tensor_v2",
       source="fp-19")
_allow("torch.nn.parameter", "Parameter UninitializedParameter",
       "wraps a tensor; constructor takes a tensor and a bool",
       source="fp-23")
_allow("pandas.core.internals.blocks", "new_block",
       "pandas block construction, in every pickled DataFrame. Takes "
       "values, a placement and a ndim; calls nothing",
       source="fp-27")
_allow("pandas.core.internals.managers", "BlockManager "
       "SingleBlockManager",
       "the manager object a pickled DataFrame reconstructs through",
       source="fp-27")
_allow("pandas", "Series DataFrame Index RangeIndex Timestamp",
       "pandas container and scalar types",
       source="fp-27")
_allow("sklearn.tree._tree", "Tree",
       "a fitted decision tree's array container; the constructor "
       "takes feature counts and class counts as integers",
       source="fp-31")
_allow("sklearn.utils._bunch", "Bunch",
       "a dict subclass; construction is data",
       source="fp-31")
_allow("scipy.sparse._csr", "csr_matrix",
       "sparse matrix construction from arrays and a shape",
       source="fp-34")
_allow("datetime", "datetime date time timedelta timezone",
       "pickled timestamps in training metadata; constructors parse "
       "bytes into integer fields and call nothing",
       source="fp-38")
_allow("pathlib", "PosixPath WindowsPath PurePosixPath",
       "a path OBJECT, not a filesystem operation. Constructing one "
       "touches nothing. Appears in checkpoints because training "
       "scripts pickle their arguments, which is also why it is worth "
       "noticing that the path itself is attacker-chosen if anything "
       "downstream uses it",
       source="fp-41")
_allow("transformers.training_args", "TrainingArguments",
       "a dataclass of training hyperparameters, pickled into "
       "checkpoints by the standard trainer",
       source="fp-44")


#: Modules where any attribute is dangerous, listed or not.
BLANKET_DANGEROUS = {"os", "posix", "nt", "subprocess", "runpy", "pty",
                     "importlib", "marshal", "pickle", "dill",
                     "commands", "popen2"}


def classify(module: str, attr: str, *, extra=None,
             strict: bool = False) -> str:
    """'dangerous' | 'allowed' | 'unknown'.

    `extra` is a project-local allowlist from `ckptscan.toml`.
    `strict` ignores it: the config cannot make a scan quieter than
    the shipped tables when somebody has asked for strict.
    """
    key = (module, attr)
    if key in DANGEROUS:
        return "dangerous"
    if module in BLANKET_DANGEROUS:
        # `os.anything` is not something a checkpoint has any business
        # calling, listed individually or not.
        return "dangerous"
    if key in ALLOW:
        return "allowed"
    if not strict and extra and key in extra:
        return "allowed"
    return "unknown"


def reason(module: str, attr: str, *, extra=None) -> str:
    key = (module, attr)
    if key in DANGEROUS:
        return DANGEROUS[key]
    if key in ALLOW:
        return ALLOW[key]
    if extra and key in extra:
        return f"allowed locally: {extra[key]}"
    if module in BLANKET_DANGEROUS:
        return (f"attribute of {module}, which a checkpoint has no "
                f"reason to call")
    return "not on the allowlist"


def source_of(module: str, attr: str) -> str:
    return ALLOW_SOURCES.get((module, attr), "")
