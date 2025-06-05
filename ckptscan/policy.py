"""What is dangerous, and what is normal.

Two tables, and they are not symmetrical.

DANGEROUS is a convenience. It exists so a report can say "this calls
os.system" rather than "this calls something I do not recognise", and
so severity can be higher for the obvious cases. It is NOT the
detector: a payload that reaches code execution through something not
on this list is still a finding, because the actual rule is "not on the
allowlist".

ALLOW is the product. Every entry is a promise that calling that
callable with arguments an attacker chose is harmless. An entry whose
reason I cannot write down does not go in, so the reason is part of the
data structure rather than a comment.
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
_danger("functools", "partial", "indirection to another callable")
_danger("operator", "attrgetter itemgetter methodcaller",
        "attribute reach")
_danger("sys", "modules exit", "interpreter state")
_danger("webbrowser", "open", "launches a program")
_danger("timeit", "timeit", "evaluates a string")
_danger("platform", "popen", "process execution")
_danger("bdb", "set_trace", "debugger entry")
_danger("pdb", "run runeval set_trace", "evaluates a string")


#: (module, attr) -> why this is safe to be called by a checkpoint.
ALLOW: dict[tuple[str, str], str] = {}


def _allow(module: str, attrs: str, why: str) -> None:
    for attr in attrs.split():
        ALLOW[(module, attr)] = why


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
_allow("numpy._core.multiarray", "_reconstruct scalar",
       "same helper, renamed module path in later numpy")
_allow("numpy", "ndarray dtype float32 float64 int64 int32 bool_",
       "array type and dtype markers")
_allow("argparse", "Namespace",
       "training scripts routinely pickle their parsed arguments "
       "into the checkpoint; Namespace construction is data")


def classify(module: str, attr: str) -> str:
    """'dangerous' | 'allowed' | 'unknown'."""
    key = (module, attr)
    if key in DANGEROUS:
        return "dangerous"
    if key in ALLOW:
        return "allowed"
    # A dangerous module with an attribute not individually listed is
    # still dangerous: `os.anything` is not something a checkpoint has
    # any business calling.
    if module in {"os", "posix", "nt", "subprocess", "runpy", "pty",
                  "importlib", "marshal", "pickle", "dill"}:
        return "dangerous"
    return "unknown"


def reason(module: str, attr: str) -> str:
    key = (module, attr)
    if key in DANGEROUS:
        return DANGEROUS[key]
    if key in ALLOW:
        return ALLOW[key]
    if module in {"os", "posix", "nt", "subprocess", "runpy", "pty",
                  "importlib", "marshal", "pickle", "dill"}:
        return f"attribute of {module}, which a checkpoint has no "\
               f"reason to call"
    return "not on the allowlist"
