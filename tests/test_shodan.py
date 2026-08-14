"""Stage 3 tests. `analyze` and `_merge` are pure, so the whole interpretation
layer is exercised on fabricated responses with no key and no network."""

import pytest

from grestin.config import Config
from grestin.http import SECRET_PARAMS, redact
from grestin.models import Raw, SignalStrength, Source, Target
from grestin.pillars.technical.shodan import ShodanCollector


@pytest.fixture
def collector():
    return ShodanCollector(client=None, config=Config.load(), stats=None)


@pytest.fixture
def target():
    return Target(legal_name="Acme RAN S.p.A.", domains=["acme-ran.example"],
                  country="IT", declared_extra_eu=False)


def raw(ip, idb=None, host=None):
    return Raw(source=Source.SHODAN, kind="host_lookup", subject=ip,
               payload={"internetdb": idb, "host": host, "has_api_key": host is not None},
               evidence_ref="feedface" * 8)


# --- credential handling ----------------------------------------------------
def test_api_key_is_redacted_before_it_can_be_stored():
    url = "https://api.shodan.io/shodan/host/203.0.113.7?key=SUPERSECRET&minify=false"
    out = redact(url)
    assert "SUPERSECRET" not in out
    assert "key=REDACTED" in out
    assert "minify=false" in out          # non-secret parameters survive


def test_redaction_leaves_ordinary_urls_untouched():
    url = "https://crt.sh/?q=example.com&output=json"
    assert redact(url) == url


def test_redaction_does_not_re_encode_urls_without_credentials():
    """Regression: re-encoding changed the evidence key of the EPSS batch URL
    (literal commas) and of crt.sh queries (percent escapes), which broke the
    offline replay for those endpoints."""
    for url in (
        "https://api.first.org/data/v1/epss?cve=CVE-2024-3400,CVE-2024-23897",
        "https://crt.sh/?q=%25.acme-ran.example&output=json&exclude=expired",
    ):
        assert redact(url) == url


@pytest.mark.parametrize("param", SECRET_PARAMS)
def test_every_declared_secret_parameter_is_covered(param):
    assert "s3cr3t" not in redact(f"https://api.example.com/x?{param}=s3cr3t")


# --- merging the two endpoints ---------------------------------------------
def test_merge_prefers_the_detailed_record_but_keeps_free_ports(collector):
    view = collector._merge({
        "internetdb": {"ports": [443, 3389], "vulns": ["CVE-2024-3400"], "cpes": [],
                       "hostnames": ["vpn.acme-ran.example"], "tags": ["vpn"]},
        "host": {"country_code": "IT", "org": "Acme",
                 "data": [{"port": 443, "product": "PAN-OS", "version": "10.2.4"}],
                 "vulns": []},
    })
    assert view["ports"] == [443, 3389]           # 3389 known only to internetdb
    assert view["country"] == "IT"
    detail = next(s for s in view["services"] if s["port"] == 443)
    assert detail["product"] == "PAN-OS" and detail["version"] == "10.2.4"
    assert view["cves"] == ["CVE-2024-3400"]      # union of both sources


def test_merge_works_without_an_api_key(collector):
    view = collector._merge({"internetdb": {"ports": [80], "vulns": []}, "host": None})
    assert view["ports"] == [80]
    assert view["country"] is None                # geolocation needs the keyed endpoint


# --- analyze ----------------------------------------------------------------
def test_open_services_are_weak_and_aggregated(collector, target):
    raws = [raw("203.0.113.10", {"ports": [80, 443], "vulns": []}),
            raw("203.0.113.12", {"ports": [25], "vulns": []})]
    findings = collector.analyze(raws, target)
    surface = next(f for f in findings if f.type == "open_service_observed")
    assert surface.signal_strength is SignalStrength.WEAK
    assert surface.evidence["open_ports_total"] == 3
    assert surface.driver_hint == "vuln_exposure_mgmt"


def test_management_port_escalates_to_moderate(collector, target):
    raws = [raw("203.0.113.7", {"ports": [443, 3389], "vulns": [],
                                "hostnames": ["vpn.acme-ran.example"]})]
    mgmt = next(f for f in collector.analyze(raws, target)
                if f.type == "management_service_exposed")
    assert mgmt.signal_strength is SignalStrength.MODERATE
    assert mgmt.evidence["services"][0]["service"] == "rdp"
    assert mgmt.needs_followup.value == "next_tool"


def test_ordinary_web_ports_do_not_escalate(collector, target):
    raws = [raw("203.0.113.10", {"ports": [80, 443], "vulns": []})]
    assert not any(f.type == "management_service_exposed"
                   for f in collector.analyze(raws, target))


def test_non_eea_hosting_is_flagged_against_the_declaration(collector, target):
    raws = [raw("203.0.113.11", {"ports": [443], "vulns": []},
                {"country_code": "SG", "org": "Cloud Provider APAC", "data": []})]
    geo = next(f for f in collector.analyze(raws, target) if f.type == "hosting_outside_eea")
    assert geo.signal_strength is SignalStrength.MODERATE
    assert geo.driver_hint == "extra_eu_data"
    assert "contradicts" in geo.note                     # declared_extra_eu is False
    assert "legal basis" in geo.evidence["limitation"]   # the caveat travels with the finding


@pytest.mark.parametrize("country", ["IT", "DE", "CH", "GB"])
def test_eea_and_adequacy_countries_are_not_flagged(collector, target, country):
    raws = [raw("203.0.113.10", {"ports": [443], "vulns": []},
                {"country_code": country, "data": []})]
    assert not any(f.type == "hosting_outside_eea" for f in collector.analyze(raws, target))


def test_no_data_yields_no_findings(collector, target):
    assert collector.analyze([], target) == []


# --- handoff ----------------------------------------------------------------
def test_candidate_cves_record_where_they_were_seen(collector):
    raws = [raw("203.0.113.7", {"ports": [443], "vulns": ["CVE-2024-3400"],
                                "hostnames": ["vpn.acme-ran.example"]}),
            raw("203.0.113.23", {"ports": [8080], "vulns": ["CVE-2024-23897"]})]
    cves = collector.candidate_cves(raws)
    assert set(cves) == {"CVE-2024-3400", "CVE-2024-23897"}
    assert cves["CVE-2024-3400"][0]["address"] == "203.0.113.7"


def test_shodan_never_produces_a_cve_finding_itself(collector, target):
    """Stage 3 hands CVEs to stage 4; it must not claim exploitability."""
    raws = [raw("203.0.113.7", {"ports": [443], "vulns": ["CVE-2024-3400"]})]
    types = {f.type for f in collector.analyze(raws, target)}
    assert not types & {"cve_on_exposed_service", "kev_on_exposed_service"}
    assert max((f.signal_strength for f in collector.analyze(raws, target)),
               default=SignalStrength.INFO) < SignalStrength.STRONG
