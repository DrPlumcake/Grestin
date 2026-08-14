"""Stage 4 tests. The rule being pinned here is the one the whole architecture
rests on: KEV, and only KEV, lets a single pillar reach `strong`."""

import pytest

from grestin.config import Config
from grestin.hub.scoring import score
from grestin.models import Raw, SignalStrength, Source, Target, Verdict
from grestin.pillars.technical.vulns import VulnsCollector


@pytest.fixture
def collector():
    return VulnsCollector(client=None, config=Config.load(), stats=None)


@pytest.fixture
def target():
    return Target(legal_name="Acme RAN S.p.A.", domains=["acme-ran.example"])


SEEN = [{"address": "203.0.113.7", "ports": [443],
         "hostnames": ["vpn.acme-ran.example"]}]


def detail(cve, cvss=None, kev=None, epss=None, seen=SEEN):
    return Raw(source=Source.NVD, kind="cve_detail", subject=cve,
               payload={"detail": {"cvss_v3": cvss, "summary": "x"} if cvss else {},
                        "kev": kev, "epss": epss, "observed_on": seen})


KEV_ENTRY = {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks",
             "product": "PAN-OS", "dateAdded": "2024-04-12", "dueDate": "2024-04-19",
             "requiredAction": "Apply mitigations.", "knownRansomwareCampaignUse": "Known"}


# --- the strong case --------------------------------------------------------
def test_kev_hit_is_the_only_single_pillar_strong(collector, target):
    findings = collector.analyze([detail("CVE-2024-3400", 10.0, kev=KEV_ENTRY)], target)
    kev = next(f for f in findings if f.type == "kev_on_exposed_service")
    assert kev.signal_strength is SignalStrength.STRONG
    assert kev.driver_hint == "vuln_exposure_mgmt"
    assert kev.evidence["kev_date_added"] == "2024-04-12"


def test_kev_hit_moves_the_driver_to_suggest_yes(collector, target):
    """End of the chain: the 0.11 driver finally moves, and only here."""
    cfg = Config.load()
    summary = score(collector.analyze([detail("CVE-2024-3400", 10.0, kev=KEV_ENTRY)], target), cfg)
    verdict = next(v for v in summary.verdicts if v.driver_id == "vuln_exposure_mgmt")
    assert verdict.verdict is Verdict.SUGGEST_YES
    assert summary.suggested_weight == 0.11


def test_ransomware_flag_is_emitted_separately_for_corroboration(collector, target):
    types = {f.type for f in collector.analyze(
        [detail("CVE-2024-3400", 10.0, kev=KEV_ENTRY)], target)}
    assert types == {"kev_on_exposed_service", "kev_ransomware_flag"}


def test_kev_without_ransomware_use_emits_one_finding(collector, target):
    kev = KEV_ENTRY | {"cveID": "CVE-2024-23897", "knownRansomwareCampaignUse": "Unknown"}
    types = {f.type for f in collector.analyze(
        [detail("CVE-2024-23897", 9.8, kev=kev)], target)}
    assert types == {"kev_on_exposed_service"}


# --- the weaker qualifications ---------------------------------------------
def test_high_epss_without_kev_is_only_moderate(collector, target):
    findings = collector.analyze(
        [detail("CVE-2023-1234", 8.1, epss={"epss": "0.42", "percentile": "0.95"})], target)
    f = findings[0]
    assert f.type == "high_epss_on_exposed_service"
    assert f.signal_strength is SignalStrength.MODERATE
    assert "does not evidence exploitation" in f.note


def test_high_cvss_alone_is_the_weakest_qualification(collector, target):
    findings = collector.analyze(
        [detail("CVE-2023-46589", 7.5, epss={"epss": "0.02", "percentile": "0.61"})], target)
    assert findings[0].type == "cve_on_exposed_service"
    assert findings[0].signal_strength is SignalStrength.MODERATE


def test_low_severity_low_epss_produces_nothing(collector, target):
    assert collector.analyze(
        [detail("CVE-2023-9999", 4.2, epss={"epss": "0.001"})], target) == []


def test_kev_supersedes_the_weaker_qualifications(collector, target):
    """A KEV hit must not also produce an EPSS finding: one signal, one claim."""
    findings = collector.analyze(
        [detail("CVE-2024-3400", 10.0, kev=KEV_ENTRY,
                epss={"epss": "0.94", "percentile": "0.99"})], target)
    assert "high_epss_on_exposed_service" not in {f.type for f in findings}


# --- honesty about the method ----------------------------------------------
def test_every_finding_carries_the_backport_limitation(collector, target):
    findings = collector.analyze([
        detail("CVE-2024-3400", 10.0, kev=KEV_ENTRY),
        detail("CVE-2023-46589", 7.5),
    ], target)
    assert findings
    for f in findings:
        assert "backported" in f.evidence["limitation"]


def test_subject_names_the_host_not_just_the_cve(collector, target):
    f = collector.analyze([detail("CVE-2024-3400", 10.0, kev=KEV_ENTRY)], target)[0]
    assert "vpn.acme-ran.example" in f.subject and "203.0.113.7" in f.subject


def test_subject_degrades_gracefully_without_context(collector, target):
    f = collector.analyze([detail("CVE-2024-3400", 10.0, kev=KEV_ENTRY, seen=[])], target)[0]
    assert "attributed to the third party" in f.subject


# --- handoff normalisation --------------------------------------------------
def test_observations_accept_a_mapping_or_a_bare_list(collector):
    collector.inputs = {"CVE-1": SEEN}
    assert collector.observations["CVE-1"] == SEEN
    collector.inputs = ["CVE-1", "CVE-2"]
    assert collector.observations == {"CVE-1": [], "CVE-2": []}


def test_non_cve_raws_are_ignored_by_analyze(collector, target):
    catalogue = Raw(source=Source.KEV, kind="kev_catalogue", subject="cisa-kev",
                    payload={"count": 1400})
    assert collector.analyze([catalogue], target) == []
