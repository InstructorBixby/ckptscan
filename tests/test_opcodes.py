import pickle

from ckptscan import opcodes


def refs(data):
    return {(g.module, g.attr) for g in opcodes.parse(data).globals}


def calls(data):
    out = set()
    for callee, op, _ in opcodes.parse(data).calls:
        if isinstance(callee, opcodes.GlobalRef):
            out.add((callee.module, callee.attr, op))
    return out


def test_records_the_protocol():
    for proto in (2, 3, 4, 5):
        data = pickle.dumps({"a": 1}, protocol=proto)
        assert opcodes.parse(data).protocol == proto


def test_a_plain_dict_has_no_globals():
    assert refs(pickle.dumps({"a": [1, 2, 3]}, protocol=4)) == set()


def test_resolves_a_protocol_2_global():
    import collections
    data = pickle.dumps(collections.OrderedDict(a=1), protocol=2)
    assert ("collections", "OrderedDict") in refs(data)


def test_resolves_a_stack_global():
    import collections
    data = pickle.dumps(collections.OrderedDict(a=1), protocol=4)
    assert ("collections", "OrderedDict") in refs(data)


def test_attributes_the_call_to_the_right_global():
    import collections
    data = pickle.dumps(collections.OrderedDict(a=1), protocol=4)
    assert any(m == "collections" and a == "OrderedDict"
               for m, a, _ in calls(data))


def test_a_memoised_global_is_still_resolved():
    import collections
    obj = [collections.OrderedDict(a=1), collections.OrderedDict(b=2)]
    data = pickle.dumps(obj, protocol=4)
    assert ("collections", "OrderedDict") in refs(data)


def test_truncation_is_reported_not_raised():
    data = pickle.dumps({"a": 1}, protocol=4)[:-4]
    stream = opcodes.parse(data)
    assert stream.truncated


def test_garbage_raises_parse_error():
    import pytest
    with pytest.raises(opcodes.ParseError):
        opcodes.parse(b"\xff\xfe\xfd not a pickle")


def test_the_opcode_budget_is_honoured():
    data = pickle.dumps(list(range(5000)), protocol=4)
    stream = opcodes.parse(data, max_opcodes=50)
    assert stream.truncated
