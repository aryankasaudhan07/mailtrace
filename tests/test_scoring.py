"""M8 tests. The scorer is the integration point -- these must never break."""

from uuid import uuid4

from app.schemas.evidence import Analyzer, Evidence, Status
from app.schemas.verdict import Band
from app.scoring.engine import load_rules, score_case


def test_every_signal_has_weight_label_and_rationale():
    """A signal without a rationale cannot be defended to a judge."""
    rules = load_rules()
    for name, rule in rules.signals.items():
        assert isinstance(rule["weight"], int), name
        assert rule.get("label"), f"{name} has no label"
        assert rule.get("rationale"), f"{name} has no rationale"
        assert rule.get("analyzer"), f"{name} has no analyzer"


def test_no_evidence_is_benign():
    v = score_case(uuid4(), [])
    assert v.score == 0
    assert v.band is Band.BENIGN


def test_additive_and_capped_at_100():
    cid = uuid4()
    ev = [
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "forged_received_hop"),      # 30
        Evidence.triggered(cid, Analyzer.M3_AUTH, "dmarc_fail_strict"),           # 28
        Evidence.triggered(cid, Analyzer.M6_DOMAIN, "brand_lookalike_domain"),    # 26
        Evidence.triggered(cid, Analyzer.M5_NETWORK, "attachment_hash_malicious"),# 22
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "reply_to_domain_mismatch"), # 20
    ]
    v = score_case(cid, ev)
    assert v.score == 100, "126 raw must clamp to 100"
    assert v.band is Band.CRITICAL


def test_dkim_pulls_the_score_down():
    """
    A negative weight must actually reduce risk, or the model is one-directional.

    Note the signals chosen: `spf_fail_hard` and `obfuscated_url` are weak
    corroborating signals, NOT deception signals, so suppression does not apply.
    Using `reply_to_domain_mismatch` here would (correctly) suppress the DKIM
    credit -- see the v1.1.0 suppression tests at the bottom of this file.
    """
    cid = uuid4()
    without = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M3_AUTH, "spf_fail_hard"),
        Evidence.triggered(cid, Analyzer.M5_NETWORK, "obfuscated_url"),
    ]).score
    with_dkim = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M3_AUTH, "spf_fail_hard"),
        Evidence.triggered(cid, Analyzer.M5_NETWORK, "obfuscated_url"),
        Evidence.triggered(cid, Analyzer.M3_AUTH, "dkim_valid_aligned"),
    ]).score
    assert with_dkim < without


def test_confidence_scales_points():
    cid = uuid4()
    full = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M4_CONTENT, "classifier_phishing_high",
                           confidence=1.0)]).score
    half = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M4_CONTENT, "classifier_phishing_high",
                           confidence=0.5)]).score
    assert half < full


def test_clear_records_do_not_score():
    cid = uuid4()
    v = score_case(cid, [
        Evidence.clear(cid, Analyzer.M2_HEADERS, "forged_received_hop"),
        Evidence.clear(cid, Analyzer.M3_AUTH, "dmarc_fail_strict"),
    ])
    assert v.score == 0


def test_unavailable_lane_lowers_confidence_not_score():
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "forged_received_hop"),
        Evidence.unavailable(cid, Analyzer.M5_NETWORK, "origin_ip_blocklisted", "offline"),
        Evidence.unavailable(cid, Analyzer.M6_DOMAIN, "domain_age_lt_30d", "offline"),
    ])
    assert v.score == 30
    assert v.confidence < 1.0
    assert Analyzer.M5_NETWORK in v.lanes_unavailable


def test_duplicate_signal_counted_once():
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "forged_received_hop"),
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "forged_received_hop"),
    ])
    assert v.score == 30, "a signal firing twice must not double-count"


def test_unknown_signal_is_ignored_not_fatal():
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "signal_that_does_not_exist"),
    ])
    assert v.score == 0


def test_error_status_does_not_score():
    cid = uuid4()
    v = score_case(cid, [Evidence(
        case_id=cid, analyzer=Analyzer.M2_HEADERS, signal="forged_received_hop",
        status=Status.ERROR, confidence=0.0)])
    assert v.score == 0


def test_contributions_ranked_by_magnitude():
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M5_NETWORK, "obfuscated_url"),       # 10
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "forged_received_hop"),  # 30
    ])
    assert v.contributions[0].signal == "forged_received_hop"


def test_every_contribution_carries_its_explanation():
    """The UI and the PDF both render these. Empty rationale = unusable report."""
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "forged_received_hop")])
    assert v.contributions[0].rationale
    assert v.contributions[0].label
    assert v.scorer_version


# ---------------------------------------------------------------------------
# v1.1.0 -- negative-weight suppression.
#
# Regression tests for a real bug found while writing docs/THREAT-MODEL.md.
# Thread hijacking, account takeover, vendor email compromise and
# trusted-platform abuse ALL produce a valid aligned DKIM signature, because the
# real mailbox really did send the message. Thread hijacking alone is ~28% of
# BEC. Crediting -25 for that meant the more damaging the attack class, the lower
# we scored it. These tests exist so nobody removes the fix.
# ---------------------------------------------------------------------------


def test_valid_dkim_still_reduces_score_on_a_clean_message():
    """The negative weight must keep working when there is no deception signal."""
    cid = uuid4()
    without = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M5_NETWORK, "obfuscated_url"),          # +10
    ]).score
    with_dkim = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M5_NETWORK, "obfuscated_url"),          # +10
        Evidence.triggered(cid, Analyzer.M3_AUTH, "dkim_valid_aligned"),         # -18
    ]).score
    assert with_dkim < without


def test_valid_dkim_cannot_mask_a_forged_hop():
    """
    The thread-hijack / ATO case. A compromised mailbox signs validly, so DKIM
    credit must not cancel evidence of forgery.
    """
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "forged_received_hop"),     # +30
        Evidence.triggered(cid, Analyzer.M3_AUTH, "dkim_valid_aligned"),         # -18, suppressed
    ])
    assert v.score == 30, "DKIM credit must be withheld when forgery is present"
    assert "dkim_valid_aligned" in v.suppressed_negatives
    assert "forged_received_hop" in v.suppressed_by


def test_known_correspondent_cannot_mask_impersonation():
    """Baseline poisoning: a known correspondent is the hijacker's own position."""
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M6_DOMAIN, "brand_lookalike_domain"),   # +26
        Evidence.triggered(cid, Analyzer.M7_GRAPH, "known_correspondent"),       # -14, suppressed
    ])
    assert v.score == 26
    assert "known_correspondent" in v.suppressed_negatives


def test_suppression_is_reported_not_silent():
    """
    An analyst must be able to see the message DID authenticate and why that did
    not help. Silently dropping the signal would be worse than not having it.
    """
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M2_HEADERS, "reply_to_domain_mismatch"),
        Evidence.triggered(cid, Analyzer.M3_AUTH, "dkim_valid_aligned"),
    ])
    assert v.suppressed_negatives, "suppression must be visible in the verdict"
    assert v.suppressed_by
    assert "authenticated correctly" in v.summary


def test_every_suppressor_is_a_real_signal():
    """A typo in the suppressor list would silently disable the whole mechanism."""
    rules = load_rules()
    for name in rules.suppressors:
        assert name in rules.signals, f"suppressor {name!r} is not a defined signal"
        assert rules.signals[name]["weight"] > 0, f"suppressor {name!r} is not positive"


def test_no_deception_means_no_suppression():
    cid = uuid4()
    v = score_case(cid, [
        Evidence.triggered(cid, Analyzer.M3_AUTH, "dkim_valid_aligned"),
    ])
    assert v.suppressed_negatives == []
    assert v.suppressed_by == []
