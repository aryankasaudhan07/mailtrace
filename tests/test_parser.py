"""M1 tests. These pass today -- keep them passing."""

from pathlib import Path

from app.ingest.parser import parse_email

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def load(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def test_parses_addresses_and_subject():
    e = parse_email(load("bec-injected-hop.eml"))
    assert e.from_addr == "accounts@example-lnstitute.example"
    assert e.from_display_name == "Accounts Section"
    assert e.reply_to == "institute.accounts.dept@mail.example"
    assert "INV-2291" in (e.subject or "")


def test_preserves_received_order_and_duplicates():
    """
    The single most important property of the parser. Received: headers are
    prepended by each MTA, so their ORDER is the transmission path. A dict
    would destroy the evidence M2 depends on.
    """
    e = parse_email(load("bec-injected-hop.eml"))
    received = e.header_values("Received")
    assert len(received) == 4
    assert "mx.example.ac.in with LMTP" in received[0]     # last hop, top of file
    assert "10.0.0.5" in received[-1]                       # claimed origin, bottom


def test_hash_is_over_original_bytes():
    raw = load("benign-control.eml")
    import hashlib

    assert parse_email(raw).sha256 == hashlib.sha256(raw).hexdigest()


def test_extracts_urls_and_flags_shortener():
    e = parse_email(load("bec-injected-hop.eml"))
    assert any(u.is_shortened for u in e.urls), "bit.ly should be flagged"
    assert any(u.mismatched_anchor for u in e.urls), \
        "anchor text names a different domain than the href"


def test_benign_sample_has_no_reply_to():
    e = parse_email(load("benign-control.eml"))
    assert e.reply_to is None
