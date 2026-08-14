"""Corporate pillar tests.

Most of these exist to pin one property: this pillar must not be able to
accuse a company on the strength of a name. `strong` requires a shared
registration identifier, and every finding escalates to a human.
"""

import pytest

from grestin.config import Config
from grestin.hub.scoring import score
from grestin.models import Raw, SignalStrength, Source, Target, Verdict
from grestin.pillars.corporate.opensanctions import OpenSanctionsCollector


@pytest.fixture
def collector():
    return OpenSanctionsCollector(client=None, config=Config.load(), stats=None)


@pytest.fixture
def target():
    return Target(legal_name="Acme RAN S.p.A.", aliases=["Acme RAN"], country="IT",
                  identifiers={"registrationNumber": "RM-1234567"})


def result(caption="Acme RAN S.p.A.", score_=0.96, match=True, topics=(),
           country="it", reg=None, entity_id="NK-x"):
    props = {"name": [caption], "country": [country], "topics": list(topics)}
    if reg:
        props["registrationNumber"] = [reg]
    return {"id": entity_id, "caption": caption, "schema": "Company",
            "score": score_, "match": match, "datasets": ["eu_fsf"], "properties": props}


def matches(*results):
    return Raw(source=Source.OPENSANCTIONS, kind="match_results", subject="Acme RAN S.p.A.",
               payload={"query": {}, "results": list(results)}, evidence_ref="ab" * 32)


def chain(country="cn", owner="Zeta Invest Group", depth=1):
    return Raw(source=Source.OPENSANCTIONS, kind="ownership_chain",
               subject="Acme RAN S.p.A.",
               payload={"root_id": "NK-acme", "chain": [
                   {"depth": depth, "owner_id": "NK-zeta", "owner": owner,
                    "countries": [country.upper()], "topics": [], "percentage": ["62"]}]})


# --- the discipline ---------------------------------------------------------
def test_name_similarity_alone_can_never_reach_strong(collector, target):
    """The candidate is sanctioned and the API says match, but no shared
    registration identifier: it stays fuzzy."""
    findings = collector.analyze(
        [matches(result(topics=["sanction"], match=True, reg="9988776"))], target)
    f = findings[0]
    assert f.type == "sanctions_match_fuzzy"
    assert f.signal_strength is SignalStrength.MODERATE
    assert f.evidence["identifier_match"] is False


def test_shared_identifier_promotes_to_exact(collector, target):
    findings = collector.analyze(
        [matches(result(topics=["sanction"], match=True, reg="RM-1234567"))], target)
    f = findings[0]
    assert f.type == "sanctions_match_exact"
    assert f.signal_strength is SignalStrength.STRONG


def test_without_our_own_identifiers_strong_is_unreachable(collector):
    """A procurement file with no VAT or registration number caps the pillar at
    moderate. That is the correct outcome, not a gap."""
    bare = Target(legal_name="Acme RAN S.p.A.", country="IT")
    findings = collector.analyze(
        [matches(result(topics=["sanction"], match=True, reg="RM-1234567"))], bare)
    assert findings[0].type == "sanctions_match_fuzzy"


def test_every_finding_of_this_pillar_goes_to_a_human(collector, target):
    findings = collector.analyze(
        [matches(result(topics=["sanction"], reg="RM-1234567"),
                 result(topics=["role.pep"], entity_id="NK-y", score_=0.9),
                 result(topics=["crime"], entity_id="NK-z", score_=0.88)),
         chain()], target)
    assert findings
    assert all(f.needs_followup.value == "human_review" for f in findings)


def test_the_limitation_travels_with_the_evidence(collector, target):
    findings = collector.analyze([matches(result(topics=["sanction"]))], target)
    assert "not an identification" in findings[0].evidence["limitation"]


def test_low_scoring_candidates_are_discarded(collector, target):
    """Below the configured floor the candidate never becomes a finding."""
    assert collector.analyze([matches(result(topics=["sanction"], score_=0.40))], target) == []


# --- classification ---------------------------------------------------------
def test_pep_topic_produces_a_pep_finding(collector, target):
    f = collector.analyze([matches(result(topics=["role.pep"]))], target)[0]
    assert f.type == "pep_match" and f.signal_strength is SignalStrength.MODERATE


def test_adverse_topic_is_only_weak(collector, target):
    f = collector.analyze([matches(result(topics=["crime.fin"]))], target)[0]
    assert f.type == "adverse_media_match" and f.signal_strength is SignalStrength.WEAK


def test_clean_candidate_produces_nothing(collector, target):
    assert collector.analyze([matches(result(topics=[]))], target) == []


# --- ownership --------------------------------------------------------------
def test_non_eea_owner_flags_two_drivers(collector, target):
    findings = collector.analyze([chain(country="cn")], target)
    by_driver = {f.driver_hint: f for f in findings}
    assert by_driver["ownership_due_diligence"].signal_strength is SignalStrength.MODERATE
    assert by_driver["golden_power"].signal_strength is SignalStrength.WEAK
    assert "D.L. 21/2012" in by_driver["golden_power"].evidence["legal_ref"]


@pytest.mark.parametrize("country", ["de", "it", "ch", "gb"])
def test_eea_and_adequacy_owners_are_not_flagged(collector, target, country):
    assert collector.analyze([chain(country=country)], target) == []


def test_bounded_traversal_is_declared_as_bounded(collector, target):
    f = collector.analyze([chain()], target)[0]
    assert f.evidence["traversal_depth_limit"] == 2
    assert "not evidence that no further control exists" in f.evidence["limitation"]


# --- interaction with the hub ----------------------------------------------
def test_two_moderate_findings_in_one_pillar_do_not_corroborate(collector, target):
    """R3 needs two *pillars*. A sanctions candidate plus a foreign owner are
    both corporate, so the driver stops at REVIEW."""
    cfg = Config.load()
    findings = collector.analyze(
        [matches(result(topics=["sanction"])), chain()], target)
    verdict = next(v for v in score(findings, cfg).verdicts
                   if v.driver_id == "ownership_due_diligence")
    assert verdict.verdict is Verdict.REVIEW
    assert verdict.max_strength is SignalStrength.MODERATE
