import os
import pickle
import socket

from ckptscan.analysers import pickles
from ckptscan.registry import RULES


class Egress:
    def __reduce__(self):
        return (socket.create_connection, (("example.invalid", 80),))


class Local:
    def __reduce__(self):
        return (os.system, ("true",))


def test_a_network_payload_carries_the_exfiltration_id():
    data = pickle.dumps(Egress(), protocol=4)
    findings = pickles.analyse(data, path="m.pkl")
    assert findings[0].taxonomy == ("EX-004",)


def test_a_local_payload_carries_no_id():
    # Most of these rules do not map onto a channel-organised
    # taxonomy, and inventing an id would make the ids mean less.
    data = pickle.dumps(Local(), protocol=4)
    findings = pickles.analyse(data, path="m.pkl")
    assert findings[0].taxonomy == ()


def test_every_taxonomy_id_is_well_formed():
    seen = set()
    for rule in RULES.values():
        assert rule.id
    data = pickle.dumps(Egress(), protocol=4)
    for f in pickles.analyse(data, path="m.pkl"):
        seen |= set(f.taxonomy)
    for tid in seen:
        group, _, number = tid.partition("-")
        assert group.isupper()
        assert number.isdigit() and len(number) == 3
