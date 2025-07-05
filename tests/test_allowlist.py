import collections
import pickle

from ckptscan import policy
from ckptscan.analysers import pickles


def rules(data, path="x.pkl"):
    return sorted(f.rule for f in pickles.analyse(data, path=path))


def test_an_ordinary_state_dict_is_clean():
    # The finding that made the naive version useless.
    obj = collections.OrderedDict(
        [("layer.weight", [0.0, 1.0]), ("layer.bias", [0.0])])
    assert rules(pickle.dumps(obj, protocol=4)) == []


def test_a_nested_ordereddict_is_still_clean():
    obj = {"state_dict": collections.OrderedDict(a=[1.0]),
           "epoch": 7, "args": {"lr": 0.001}}
    assert rules(pickle.dumps(obj, protocol=4)) == []


def test_os_system_is_critical(fixtures):
    data = (fixtures / "system_p4.pkl").read_bytes()
    findings = pickles.analyse(data, path="m.pkl")
    assert [f.rule for f in findings] == ["CKPT-001"]
    assert findings[0].severity == "critical"
    assert "os.system" in findings[0].message


def test_os_system_is_critical_under_protocol_2(fixtures):
    data = (fixtures / "system_p2.pkl").read_bytes()
    assert rules(data) == ["CKPT-001"]


def test_eval_is_critical(fixtures):
    data = (fixtures / "eval_p4.pkl").read_bytes()
    assert rules(data) == ["CKPT-001"]


def test_an_unrecognised_callable_is_medium():
    class Custom:
        def __reduce__(self):
            return (collections.namedtuple, ("P", "x"))

    findings = pickles.analyse(pickle.dumps(Custom(), protocol=4),
                               path="m.pkl")
    assert [f.rule for f in findings] == ["CKPT-002"]
    assert findings[0].severity == "medium"


def test_classify():
    assert policy.classify("os", "system") == "dangerous"
    assert policy.classify("os", "whatever_new") == "dangerous"
    assert policy.classify("collections", "OrderedDict") == "allowed"
    assert policy.classify("mypkg", "Thing") == "unknown"


def test_every_allowlist_entry_has_a_reason():
    # The rule that keeps the allowlist honest.
    for key, why in policy.ALLOW.items():
        assert why.strip(), key
        assert len(why) > 15, key


def test_nothing_is_both_allowed_and_dangerous():
    assert not set(policy.ALLOW) & set(policy.DANGEROUS)
