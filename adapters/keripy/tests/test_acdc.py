"""acdc.verify on keripy main: the bundle is delivered to keripy, the registry head is keripy's own
regeventing.vet, and the verdict is never valid, because keripy main has no entry point that judges
an ACDC 2.00 against a bundle (README.md, "acdc.verify").

keripy main only; keripy 1.2.14 does not declare the operation (test_exchange_onex.py).
"""

import pytest
from conftest import GENERATION

pytestmark = pytest.mark.main

if GENERATION == "main":
    import bundles as b

    from kcs_adapter_keripy import acdc, kel


def result(response):
    return response["result"]


class World:
    """An issuer with a registry incepted and anchored, an ACDC naming it, and an issued update
    anchored, as keripy's own builders make them."""

    def __init__(self, anchor_rip=True, anchor_bup=True, rip_issuer=None):
        self.issuer = b.Issuer(1, 2)
        self.rip = b.registry(rip_issuer or self.issuer.pre)
        self.acdc = b.acdc(self.issuer.pre, rd=self.rip.said)
        self.blinder, self.bup = b.update(self.rip, self.rip, self.acdc.said, "issued", 1)
        self.rip_at = self.issuer.anchor(self.rip) if anchor_rip else None
        self.bup_at = self.issuer.anchor(self.bup) if anchor_bup else None

    def rip_stream(self):
        return b.attached(self.rip, *([b.source(self.rip_at)] if self.rip_at else []))

    def bup_stream(self, disclose=True):
        bonds = [b.source(self.bup_at)] if self.bup_at else []
        return b.attached(self.bup, *bonds, *([self.blinder.data] if disclose else []))

    def verify(self, registry=None, kels=None, presented=None):
        registry = [self.rip_stream(), self.bup_stream()] if registry is None else registry
        return b.verify(presented or b.attached(self.acdc),
                        kels=self.issuer.kel() if kels is None else kels,
                        registry_streams=registry)


def test_a_bundle_keripy_can_parse_is_incomplete_never_valid():
    world = World()
    got = result(world.verify())
    assert got["verdict"] == "incomplete"
    assert acdc.REASON_NO_VERIFIER in got["reason"]
    assert got["edges"] == []


def test_the_registry_head_is_keripys_vetted_head_with_its_disclosed_state():
    world = World()
    assert result(world.verify())["registry"] == {
        "rd": world.rip.said, "n": 1, "d": world.bup.said, "td": world.acdc.said, "ts": "issued"}


def test_a_blinded_head_without_a_disclosure_reports_unknown_state():
    world = World()
    got = result(world.verify(registry=[world.rip_stream(), world.bup_stream(disclose=False)]))
    assert got["registry"] == {"rd": world.rip.said, "n": 1, "d": world.bup.said,
                               "td": None, "ts": None}


def test_a_disclosure_that_does_not_reproduce_the_blid_is_not_a_disclosure():
    world = World()
    other, _ = b.update(world.rip, world.rip, world.acdc.said, "revoked", 1)
    stream = b.attached(world.bup, b.source(world.bup_at), other.data)
    got = result(world.verify(registry=[world.rip_stream(), stream]))
    assert (got["registry"]["td"], got["registry"]["ts"]) == (None, None)


def test_a_registry_of_only_its_inception_reports_sequence_number_zero():
    world = World(anchor_bup=False)
    got = result(world.verify(registry=[world.rip_stream()]))
    assert got["registry"] == {"rd": world.rip.said, "n": 0, "d": world.rip.said,
                               "td": None, "ts": None}


def test_an_unanchored_registry_is_not_reported():
    world = World(anchor_rip=False, anchor_bup=False)
    assert result(world.verify())["registry"] is None


def test_an_unanchored_update_makes_keripy_report_no_registry():
    # keripy's vet refuses the whole chain when any presented event is unanchored, where the
    # design's verified chain would stop before it; the adapter reports what keripy holds.
    world = World(anchor_bup=False)
    assert result(world.verify())["registry"] is None


def test_a_registry_incepted_by_another_aid_is_withheld():
    other = b.Issuer(5, 6)
    world = World(anchor_rip=False, anchor_bup=False, rip_issuer=other.pre)
    other.anchor(world.rip)
    got = result(world.verify(registry=[b.attached(world.rip)], kels=world.issuer.kel()
                              + other.kel()))
    assert got["registry"] is None


def test_an_acdc_without_rd_reports_no_registry():
    world = World()
    plain = b.attached(b.acdc(world.issuer.pre))
    assert result(world.verify(presented=plain))["registry"] is None


def test_a_registry_without_its_inception_reports_none_and_unreadable_events_are_dropped():
    world = World()
    got = result(world.verify(registry=[b"garbage", world.bup_stream()]))
    assert got["registry"] is None


def test_registry_events_of_other_registries_are_ignored():
    world = World()
    stranger = b.registry(world.issuer.pre, uuid=b.UUID1)
    got = result(world.verify(registry=[b.attached(stranger), world.rip_stream(),
                                        world.bup_stream()]))
    assert got["registry"]["d"] == world.bup.said


def test_an_unparseable_presented_acdc_is_invalid():
    got = result(World().verify(presented=b"not an acdc"))
    assert (got["verdict"], got["registry"], got["edges"]) == ("invalid", None, [])


def test_a_presented_message_that_is_not_a_disclosed_acdc_is_invalid():
    world = World()
    got = result(world.verify(presented=world.rip_stream()))
    assert got["verdict"] == "invalid"
    got = result(world.verify(presented=world.issuer.kel()[0]))
    assert got["verdict"] == "invalid"


def test_a_bare_acdc_without_an_attachment_group_is_one_keripy_cannot_parse():
    world = World()
    got = result(world.verify(presented=b.GENUS + bytes(world.acdc.raw)))
    assert got["verdict"] == "invalid"


def test_a_presented_stream_with_bytes_after_its_acdc_is_unframeable_and_invalid():
    world = World()
    got = result(world.verify(presented=b.attached(world.acdc) + b"garbage"))
    assert (got["verdict"], got["reason"]) == ("invalid", acdc.REASON_UNREADABLE)
    got = result(world.verify(presented=b.attached(world.acdc) + b.attached(world.acdc)))
    assert got["verdict"] == "invalid"


def test_a_registry_stream_with_bytes_after_its_event_is_dropped():
    world = World()
    got = result(world.verify(registry=[world.rip_stream() + b"garbage", world.bup_stream()]))
    assert got["registry"] is None
    got = result(world.verify(registry=[world.rip_stream(), world.bup_stream() + b"garbage"]))
    assert (got["registry"]["n"], got["registry"]["d"]) == (0, world.rip.said)


def test_a_kel_stream_with_bytes_after_its_event_is_not_delivered(capsys):
    world = World()
    icp, *rest = world.issuer.kel()
    assert result(world.verify(kels=[icp + b"garbage", *rest]))["registry"] is None
    assert "not exactly one message" in capsys.readouterr().err


def test_requests_are_independent():
    world = World()
    assert result(world.verify())["registry"] is not None
    assert result(world.verify(kels=[]))["registry"] is None


def test_schemas_and_far_nodes_are_accepted_and_do_not_change_the_answer():
    world = World()
    got = result(b.verify(b.attached(world.acdc), kels=world.issuer.kel(),
                          registry_streams=[world.rip_stream(), world.bup_stream()],
                          acdcs=[b.attached(b.acdc(world.issuer.pre))],
                          schemas=[b'{"$id":""}'], expect_schema="EAbc"))
    assert got["verdict"] == "incomplete"


@pytest.mark.parametrize("fields,match", [
    ({"kels": "x"}, '"kels"'),
    ({"registry": [{"stream": "zz"}]}, '"stream"'),
    ({"schemas": ["zz"]}, '"schemas"'),
    ({"schemas": None}, '"schemas"'),
    ({"acdcs": [1]}, '"acdcs"'),
    ({"presented": "00"}, '"presented"'),
    ({"presented": {"stream": 1}}, '"stream"'),
    ({"perspective": "validator"}, '"perspective"'),
])
def test_malformed_requests_are_harness_errors(fields, match):
    response = b.handle({"id": 7, "op": "acdc.verify", "perspective": {"role": "validator"},
                         "kels": [], "registry": [], "schemas": [], "acdcs": [],
                         "presented": {"stream": ""}, **fields})
    assert response["error"]["kind"] == "harness"
    assert match in response["error"]["message"]


def test_a_perspective_other_than_validator_is_unsupported():
    response = b.verify(b"", perspective={"role": "witness"})
    assert response["error"]["kind"] == "unsupported"
    assert kel.E_PERSPECTIVE in response["error"]["message"]


def test_a_keripy_failure_vetting_the_registry_withholds_it(monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise acdc.kering.ValidationError("refused")

    monkeypatch.setattr(acdc.regeventing, "vet", refuse)
    assert result(World().verify())["registry"] is None
    assert "keripy did not verify registry" in capsys.readouterr().err


def test_a_disclosure_keripy_cannot_rebuild_is_skipped(monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise acdc.kering.InvalidValueError("refused")

    monkeypatch.setattr(acdc, "Blinder", refuse)
    world = World()
    got = result(world.verify())
    assert (got["registry"]["d"], got["registry"]["td"]) == (world.bup.said, None)
    assert "keripy cannot rebuild a disclosure: InvalidValueError" in capsys.readouterr().err
