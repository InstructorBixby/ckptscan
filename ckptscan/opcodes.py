"""Parse a pickle stream into something analysable, without running it.

`pickletools.genops` gives opcodes. Turning those into "which callable
does this REDUCE call" needs a model of the pickle stack, because the
callable is pushed by an earlier opcode and consumed by a later one.

This is a *partial* interpreter and deliberately so. It tracks enough
of the stack to answer "what is under the top of the stack when REDUCE
happens", and it models everything it does not understand as an opaque
Unknown. Nothing it does can call anything the stream names: the only
things that ever go on this stack are strings, numbers, None, marks and
Unknown placeholders.
"""
from __future__ import annotations

import pickletools
from dataclasses import dataclass, field


class ParseError(Exception):
    pass


@dataclass(frozen=True)
class GlobalRef:
    """A module/attribute pair the stream asks to import."""
    module: str
    attr: str
    pos: int

    @property
    def dotted(self) -> str:
        return f"{self.module}.{self.attr}"


@dataclass(frozen=True)
class Unknown:
    """Something on the stack this partial interpreter did not model."""
    why: str = ""


MARK = object()

# Opcodes that push a literal string.
_STR = {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8",
        "STRING", "BINSTRING", "SHORT_BINSTRING", "BINBYTES",
        "SHORT_BINBYTES", "BINBYTES8"}
# Opcodes that push some other scalar nobody needs the value of.
_SCALAR = {"INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1",
           "LONG4", "FLOAT", "BINFLOAT", "NONE", "NEWTRUE",
           "NEWFALSE", "PERSID", "BINPERSID", "BYTEARRAY8",
           "NEXT_BUFFER", "READONLY_BUFFER"}
# Opcodes that pop a mark and push one aggregate.
_BUILD_SEQ = {"TUPLE", "LIST", "DICT", "SET", "FROZENSET"}
_FIXED_TUPLE = {"TUPLE1": 1, "TUPLE2": 2, "TUPLE3": 3}


@dataclass
class Stream:
    """The analysable summary of one pickle stream."""
    protocol: int = 0
    globals: list = field(default_factory=list)
    # (GlobalRef | Unknown, opcode name, pos) for each call-like opcode
    calls: list = field(default_factory=list)
    opcodes: list = field(default_factory=list)
    truncated: bool = False

    @property
    def opcode_names(self) -> set:
        return {name for name, _ in self.opcodes}


def parse(data: bytes, *, max_opcodes: int = 2_000_000) -> Stream:
    """Walk the stream. Never imports, never constructs, never calls."""
    out = Stream()
    stack: list = []
    memo: dict = {}
    count = 0

    def pop():
        return stack.pop() if stack else Unknown("stack underflow")

    def pop_to_mark():
        items = []
        while stack:
            item = stack.pop()
            if item is MARK:
                return items
            items.append(item)
        return items

    try:
        ops = pickletools.genops(data)
        for op, arg, pos in ops:
            count += 1
            if count > max_opcodes:
                out.truncated = True
                break
            name = op.name
            out.opcodes.append((name, pos))

            if name == "PROTO":
                out.protocol = int(arg or 0)
            elif name == "FRAME":
                pass
            elif name == "MARK":
                stack.append(MARK)
            elif name in _STR:
                stack.append(str(arg))
            elif name in _SCALAR:
                stack.append(Unknown(name))
            elif name == "GLOBAL":
                mod, _, attr = str(arg).partition(" ")
                ref = GlobalRef(mod, attr, pos)
                out.globals.append(ref)
                stack.append(ref)
            elif name == "STACK_GLOBAL":
                attr, mod = pop(), pop()
                ref = GlobalRef(
                    mod if isinstance(mod, str) else "?",
                    attr if isinstance(attr, str) else "?", pos)
                out.globals.append(ref)
                stack.append(ref)
            elif name in ("REDUCE", "NEWOBJ", "NEWOBJ_EX"):
                if name == "NEWOBJ_EX":
                    pop()      # kwargs
                pop()          # args tuple
                callee = pop()
                out.calls.append((callee, name, pos))
                stack.append(Unknown(name))
            elif name in ("INST", "OBJ"):
                if name == "INST":
                    mod, _, attr = str(arg).partition(" ")
                    ref = GlobalRef(mod, attr, pos)
                    out.globals.append(ref)
                    pop_to_mark()
                    out.calls.append((ref, name, pos))
                else:
                    items = pop_to_mark()
                    callee = items[-1] if items else Unknown("OBJ")
                    out.calls.append((callee, name, pos))
                stack.append(Unknown(name))
            elif name == "BUILD":
                state = pop()
                obj = pop()
                out.calls.append((obj, name, pos))
                stack.append(obj if not isinstance(state, str) else obj)
            elif name in _BUILD_SEQ:
                pop_to_mark()
                stack.append(Unknown(name))
            elif name in _FIXED_TUPLE:
                for _ in range(_FIXED_TUPLE[name]):
                    pop()
                stack.append(Unknown(name))
            elif name == "EMPTY_TUPLE":
                stack.append(Unknown(name))
            elif name in ("EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET"):
                stack.append(Unknown(name))
            elif name in ("PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"):
                key = arg if name != "MEMOIZE" else len(memo)
                if stack:
                    memo[key] = stack[-1]
            elif name in ("GET", "BINGET", "LONG_BINGET"):
                stack.append(memo.get(arg, Unknown("memo miss")))
            elif name in ("APPEND", "SETITEM"):
                pop()
                if name == "SETITEM":
                    pop()
            elif name in ("APPENDS", "SETITEMS", "ADDITEMS"):
                pop_to_mark()
            elif name == "POP":
                pop()
            elif name == "POP_MARK":
                pop_to_mark()
            elif name == "DUP":
                if stack:
                    stack.append(stack[-1])
            elif name == "STOP":
                break
            else:
                stack.append(Unknown(name))
    except Exception as exc:
        # A truncated or malformed stream is a finding in its own right
        # later on, not a crash. Keep what was parsed.
        out.truncated = True
        if not out.opcodes:
            raise ParseError(str(exc)) from exc
    return out
