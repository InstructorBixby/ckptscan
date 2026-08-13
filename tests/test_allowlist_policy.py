"""The tests that keep the allowlist honest.

Every entry is a promise. These check the promises are at least
written down, attributed, and not quietly contradicting the
dangerous list.
"""
from ckptscan import policy


def test_every_entry_has_a_reason():
    for key, why in policy.ALLOW.items():
        assert why.strip(), key
        assert len(why) > 20, key


def test_every_entry_has_a_source():
    for key in policy.ALLOW:
        assert policy.ALLOW_SOURCES.get(key), key


def test_nothing_is_both_allowed_and_dangerous():
    assert not set(policy.ALLOW) & set(policy.DANGEROUS)


def test_no_entry_is_in_a_blanket_dangerous_module():
    for module, _ in policy.ALLOW:
        assert module not in policy.BLANKET_DANGEROUS, module


def test_the_load_from_bytes_trap_is_denied():
    """It is in the torch namespace, it has a leading underscore, and
    it calls torch.load on bytes from the file. I had the allowlist
    entry written before I read the source."""
    assert policy.classify("torch.storage",
                           "_load_from_bytes") == "dangerous"
    why = policy.reason("torch.storage", "_load_from_bytes")
    assert "torch.load" in why


def test_the_other_loader_re_entries_are_denied():
    for module, attr in [("torch.serialization", "load"),
                         ("torch.jit", "load"),
                         ("torch.hub", "load_state_dict_from_url"),
                         ("pickle", "loads"),
                         ("dill", "load")]:
        assert policy.classify(module, attr) == "dangerous", \
            f"{module}.{attr}"


def test_both_numpy_module_paths_are_allowed():
    for module in ("numpy.core.multiarray", "numpy._core.multiarray"):
        assert policy.classify(module, "_reconstruct") == "allowed"


def test_an_unlisted_attribute_of_a_dangerous_module_is_dangerous():
    assert policy.classify("os", "something_new_in_3_15") \
        == "dangerous"


def test_the_subclass_rebuilder_entry_explains_the_indirection():
    why = policy.ALLOW[("torch._tensor", "_rebuild_from_type_v2")]
    assert "resolved and classified independently" in why
