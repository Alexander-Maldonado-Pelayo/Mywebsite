"""Processing rules: every false-positive rule fires for the right reason."""

import os
from datetime import datetime, timedelta, timezone

from ctilib.indicators import (
    NO_CONTEXT_PENALTY,
    UNKNOWN_CONFIDENCE,
    Indicator,
    load_feed,
    process_feed,
    technique_counts,
)

NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)
SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "sample_indicator_feed.json")


def make(pattern="[ipv4-addr:value = '203.0.113.1']", age_days=1, valid_days=30, confidence=80, techniques=(), groups=()):
    created = NOW - timedelta(days=age_days)
    return Indicator(
        id=f"indicator--{pattern}",
        pattern=pattern,
        pattern_type="stix",
        created=created,
        valid_from=created,
        valid_until=NOW + timedelta(days=valid_days) if valid_days is not None else None,
        confidence=confidence,
        techniques=set(techniques),
        groups=set(groups),
    )


def test_expired_indicator_is_dropped():
    result = process_feed([make(valid_days=-1, techniques={"T1078"})], now=NOW)
    assert result.kept == []
    assert len(result.dropped["expired"]) == 1


def test_stale_indicator_is_dropped():
    result = process_feed([make(age_days=120, valid_days=None, techniques={"T1078"})], max_age_days=90, now=NOW)
    assert len(result.dropped["stale"]) == 1


def test_low_confidence_is_dropped_and_no_context_is_penalized():
    with_context = make(confidence=60, techniques={"T1078"})
    without_context = make(pattern="[domain-name:value = 'x.example']", confidence=60)
    assert with_context.effective_confidence() == 60
    assert without_context.effective_confidence() == 60 - NO_CONTEXT_PENALTY
    result = process_feed([with_context, without_context], min_confidence=50, now=NOW)
    assert result.kept == [with_context]
    assert result.dropped["low confidence"] == [without_context]


def test_unknown_confidence_is_treated_as_unknown_not_good():
    ind = make(confidence=None, techniques={"T1078"})
    assert ind.effective_confidence() == UNKNOWN_CONFIDENCE


def test_duplicate_pattern_is_dropped():
    first = make(techniques={"T1078"})
    second = make(techniques={"T1078"})
    result = process_feed([first, second], now=NOW)
    assert result.kept == [first]
    assert result.dropped["duplicate"] == [second]


def test_reduction_metric():
    result = process_feed([make(techniques={"T1078"}), make(valid_days=-5), make(valid_days=-5)], now=NOW)
    assert result.total == 3
    assert result.dropped_count == 2
    assert result.reduction_percent() == 66.7


def test_sample_feed_maps_relationships_to_attack_context():
    feed = load_feed(SAMPLE)
    assert len(feed) == 14
    by_pattern = {ind.pattern: ind for ind in feed}
    apt29_hash = next(ind for ind in feed if "3f5d0d6e" in ind.pattern)
    assert apt29_hash.techniques == {"T1566.001"}
    assert apt29_hash.groups == {"APT29"}
    assert by_pattern["[domain-name:value = 'cdn-static-assets.example']"].has_context is False


def test_sample_feed_processing_outcome():
    """The sample feed was built so each rule rejects something. Dates are relative
    to the day the sample was generated, so we pin `now` to that day."""
    feed = load_feed(SAMPLE)
    generated = max(ind.created for ind in feed)
    result = process_feed(feed, now=generated + timedelta(hours=1))
    assert len(result.kept) == 6
    assert {k: len(v) for k, v in result.dropped.items()} == {"expired": 2, "stale": 2, "low confidence": 3, "duplicate": 1}
    counts = technique_counts(result.kept)
    assert counts["T1071.001"] == 2
    assert counts["T1566.001"] == 2
