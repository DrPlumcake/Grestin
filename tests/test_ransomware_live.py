"""Incident pillar tests.

Two properties are being pinned: the 12-month window actually discriminates,
and a name-only match never reaches `strong`. The last test is the one that
matters most for the thesis - it is section 6.4 as an assertion.
"""

from datetime import UTC, datetime, timedelta

import pytest

from grestin.config import Config
from grestin.hub.scoring import score
from grestin.models import Raw, SignalStrength, Source, Target, Verdict
from grestin.pillars.incident.ransomware_live import (
    RansomwareLiveCollector,
    normalise_name,
    parse_date,
    registrable,
)

REFERENCE = datetime(2026, 8, 14, tzinfo=UTC)


@pytest.fixture
def collector():
    return RansomwareLiveCollector(client=None, config=Config.load(), stats=None,
                                   reference_date=REFERENCE)


@pytest.fixture
def target():
    return Target(legal_name="Acme RAN S.p.A.", aliases=["Acme RAN"],
                  domains=["acme-ran.example"], country="IT",
                  declared_breach_12m=False)


def victims(*items):
    return Raw(source=Source.RANSOMWARE_LIVE, kind="victim_search", subject="q",
               payload={"query": "q", "victims": list(items)}, evidence_ref="dd" * 32)


def victim(name="Acme RAN S.p.A.", domain="acme-ran.example", group="lockbit3",
           days_ago=45):
    return {"victim": name, "domain": domain, "group": group,
            "published": (REFERENCE - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")}


# --- normalisation helpers --------------------------------------------------
@pytest.mark.parametrize("raw_name,expected", [
    ("Acme RAN S.p.A.", "acme ran"),
    ("ACME RAN Spa", "acme ran"),
    ("Acme Ran S.r.l.", "acme ran"),
    ("Acme RAN Holdings Ltd", "acme ran"),
    ("Acme RAN", "acme ran"),
])
def test_legal_forms_are_stripped_before_comparing(raw_name, expected):
    assert normalise_name(raw_name) == expected


@pytest.mark.parametrize("value,expected", [
    ("https://www.acme-ran.example/path", "acme-ran.example"),
    ("vpn.acme-ran.example", "acme-ran.example"),
    ("ACME-RAN.EXAMPLE", "acme-ran.example"),
])
def test_registrable_domain_extraction(value, expected):
    assert registrable(value) == expected


def test_unparseable_dates_do_not_crash_the_run():
    assert parse_date("not a date") is None
    assert parse_date(None) is None
    assert parse_date("2026-06-30").year == 2026


# --- the window -------------------------------------------------------------
def test_domain_match_inside_the_window_is_strong(collector, target):
    f = collector.analyze([victims(victim(days_ago=45))], target)[0]
    assert f.type == "dls_listing"
    assert f.signal_strength is SignalStrength.STRONG
    assert f.evidence["matched_on"] == "domain"
    assert f.evidence["age_days"] == 45
    assert "contradicts the supplier's declaration" in f.note


def test_domain_match_outside_the_window_drops_to_weak(collector, target):
    f = collector.analyze([victims(victim(days_ago=820))], target)[0]
    assert f.type == "dls_listing_stale"
    assert f.signal_strength is SignalStrength.WEAK


def test_the_boundary_is_the_configured_window(collector, target):
    window = int(Config.load().threshold("dls_window_days"))
    inside = collector.analyze([victims(victim(days_ago=window))], target)[0]
    outside = collector.analyze([victims(victim(days_ago=window + 1))], target)[0]
    assert inside.type == "dls_listing"
    assert outside.type == "dls_listing_stale"


def test_the_window_does_not_drift_with_the_clock(target):
    """A replayed run must classify a listing exactly as the original did."""
    early = RansomwareLiveCollector(None, Config.load(), None,
                                    reference_date=REFERENCE)
    late = RansomwareLiveCollector(None, Config.load(), None,
                                   reference_date=REFERENCE + timedelta(days=400))
    listing = [victims(victim(days_ago=45))]
    assert early.analyze(listing, target)[0].type == "dls_listing"
    assert late.analyze(listing, target)[0].type == "dls_listing_stale"


# --- attribution ------------------------------------------------------------
def test_name_match_without_a_domain_is_capped_at_moderate(collector, target):
    f = collector.analyze([victims(victim(name="ACME RAN Spa", domain=""))], target)[0]
    assert f.type == "dls_listing_name_only"
    assert f.signal_strength is SignalStrength.MODERATE
    assert f.needs_followup.value == "human_review"
    assert "homonym" in f.note


def test_an_unrelated_victim_is_ignored(collector, target):
    assert collector.analyze(
        [victims(victim(name="Other Company Ltd", domain="other.example"))], target) == []


def test_a_similar_but_different_name_is_not_matched(collector, target):
    assert collector.analyze(
        [victims(victim(name="Acme RAN Logistics", domain=""))], target) == []


def test_the_same_listing_returned_by_two_queries_is_counted_once(collector, target):
    one = victim()
    assert len(collector.analyze([victims(one), victims(dict(one))], target)) == 1


def test_the_limitation_travels_with_the_evidence(collector, target):
    f = collector.analyze([victims(victim())], target)[0]
    assert "not a verified incident" in f.evidence["limitation"]
    assert "absence from leak sites" in f.evidence["limitation"]


def test_no_listings_yields_no_findings(collector, target):
    assert collector.analyze([victims()], target) == []


# --- section 6.4, as an assertion ------------------------------------------
def test_two_independent_pillars_converge_on_the_same_risk(collector, target):
    """The technical pillar finds a KEV entry used in ransomware campaigns; this
    pillar independently finds the supplier on a leak site. Neither queried the
    other, and the hub records the convergence."""
    cfg = Config.load()
    technical = cfg.make_finding(
        type="kev_ransomware_flag", source=Source.KEV, subject="CVE-2024-3400",
        evidence={}, strength=SignalStrength.MODERATE)
    incident = collector.analyze([victims(victim())], target)

    summary = score([technical, *incident], cfg)
    drivers = {c["driver"]: c for c in summary.corroborations}
    assert set(drivers) == {"vuln_exposure_mgmt", "data_breach_12m"}
    for entry in drivers.values():
        assert entry["pillars"] == ["incident", "technical"]

    breach = next(v for v in summary.verdicts if v.driver_id == "data_breach_12m")
    assert breach.verdict is Verdict.SUGGEST_YES

    # And the point of R3: the technical driver rises too, although its own
    # strongest signal is only `moderate`. Alone it would have been a REVIEW;
    # the independent confirmation from the other pillar is what promotes it.
    vuln = next(v for v in summary.verdicts if v.driver_id == "vuln_exposure_mgmt")
    assert vuln.max_strength is SignalStrength.MODERATE
    assert vuln.verdict is Verdict.SUGGEST_YES
    assert score([technical], cfg).verdicts[0] is not None
    assert next(v for v in score([technical], cfg).verdicts
                if v.driver_id == "vuln_exposure_mgmt").verdict is Verdict.REVIEW

    assert summary.suggested_weight == 0.18      # 0.11 + 0.07
