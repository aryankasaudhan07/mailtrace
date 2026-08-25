"""
M2 tests. The passing ones cover what is already implemented; the skipped ones
are the SPEC for Track A. Remove the skip marker as you implement each check --
these tests are your definition of done.
"""

from pathlib import Path

import pytest

from app.analyzers.m2_headers import is_public_ip, is_unroutable_ip, parse_hops
from app.ingest.parser import parse_email

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def hops_for(name: str):
    return parse_hops(parse_email((SAMPLES / name).read_bytes()))


def test_hops_are_ordered_origin_first():
    hops = hops_for("bec-injected-hop.eml")
    assert len(hops) == 4
    assert hops[0].seq == 0
    # seq 0 is the CLAIMED origin (bottom of the header block)
    assert hops[0].from_ip == "10.0.0.5"
    # highest seq is final delivery into our own MX
    assert hops[-1].by_host == "mx.example.ac.in"


def test_extracts_ips_hosts_and_protocol():
    hops = hops_for("bec-injected-hop.eml")
    assert hops[1].from_ip == "198.51.100.77"
    assert hops[2].from_ip == "203.0.113.44"
    assert hops[2].protocol == "ESMTPS"


def test_parses_timestamps_in_ascending_order():
    hops = [h for h in hops_for("bec-injected-hop.eml") if h.timestamp]
    stamps = [h.timestamp for h in hops]
    assert stamps == sorted(stamps), "transmission order must be chronological"


def test_unroutable_ip_classification():
    """
    Regression guard. An early version used ipaddress.is_global here, which
    flags the RFC 5737 documentation ranges as unroutable -- so every test
    fixture and every sanitised corpus sample "detected" a forged hop, including
    the benign control. Documentation ranges MUST pass.
    """
    # cannot appear in public transit -> injected hop
    assert is_unroutable_ip("10.0.0.5") is True
    assert is_unroutable_ip("192.168.1.10") is True
    assert is_unroutable_ip("172.16.4.4") is True
    assert is_unroutable_ip("127.0.0.1") is True
    assert is_unroutable_ip("169.254.1.1") is True
    assert is_unroutable_ip("100.64.0.1") is True      # CGNAT
    # acceptable in a relay chain
    assert is_unroutable_ip("203.0.113.44") is False   # RFC 5737 docs
    assert is_unroutable_ip("198.51.100.77") is False  # RFC 5737 docs
    assert is_unroutable_ip("8.8.8.8") is False
    assert is_unroutable_ip("2606:4700::1111") is False
    # garbage and absence
    assert is_unroutable_ip(None) is False
    assert is_unroutable_ip("not-an-ip") is False
    assert is_public_ip("203.0.113.44") is True
    assert is_public_ip("10.0.0.5") is False


# ---------------------------------------------------------------------------
# SPEC FOR TRACK A -- delete the skip marker as you implement each one.
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="TODO-A: implement resolve_trust_boundary")
def test_boundary_is_the_last_hop_we_can_authenticate():
    from app.analyzers.m2_headers import resolve_trust_boundary
    from app.schemas.email import HopTrust

    hops = hops_for("bec-injected-hop.eml")
    boundary = resolve_trust_boundary(
        hops, trusted_hosts={"mx.example.ac.in"}, trusted_cidrs=["203.0.113.0/24"]
    )
    # hop 2 handed the message to our MX -- the IP it received FROM is the
    # highest-confidence origin we can defend.
    assert boundary is not None and boundary.seq == 2
    assert boundary.trust is HopTrust.BOUNDARY
    assert hops[3].trust is HopTrust.TRUSTED
    assert hops[0].trust is HopTrust.UNVERIFIED
    assert hops[1].trust is HopTrust.UNVERIFIED


@pytest.mark.skip(reason="TODO-A: implement forged_received_hop")
def test_injected_hop_below_boundary_is_flagged():
    """
    The whole product hangs off this. A naive tool reports 10.0.0.5 as the
    origin; we must report hop 2's IP and flag hops 0-1 as injected.
    """
    ...


@pytest.mark.skip(reason="TODO-A: implement chain_discontinuity")
def test_chain_discontinuity_detected():
    """hop N's `by` host must equal hop N+1's `from` host."""
    ...


@pytest.mark.skip(reason="TODO-A: implement rdns_mismatch")
def test_rdns_mismatch_detected():
    """Announced hostname does not resolve to the connecting IP."""
    ...


@pytest.mark.skip(reason="TODO-A: implement message_id_domain_divergence")
def test_message_id_domain_divergence_detected():
    """Message-ID right-hand side matches neither sender nor any relay."""
    ...


@pytest.mark.skip(reason="TODO-A: no hops at all must not crash the lane")
def test_email_with_no_received_headers():
    ...
