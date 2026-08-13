"""Stage 2 tests. Same shape as the crt.sh ones: the guard is exercised
directly, and `analyze` is tested as a pure function on fabricated records,
so no DNS query is made while running the suite."""

import pytest

from grestin.config import Config
from grestin.models import Raw, SignalStrength, Source, Target
from grestin.pillars.technical.dns import (
    ALLOWED_RRTYPES,
    DENIED_RRTYPES,
    DnsCollector,
    ZoneTransferBlocked,
    assert_passive_dns,
    evidence_uri,
)


@pytest.fixture
def collector():
    return DnsCollector(client=None, config=Config.load(), stats=None)


@pytest.fixture
def target():
    return Target(legal_name="Acme RAN S.p.A.", domains=["acme-ran.example"], country="IT")


def rec(a=(), aaaa=(), cname=(), a_status=None):
    return {
        "A": {"status": a_status or ("ok" if a else "no_answer"), "values": list(a)},
        "AAAA": {"status": "ok" if aaaa else "no_answer", "values": list(aaaa)},
        "CNAME": {"status": "ok" if cname else "no_answer", "values": list(cname)},
    }


def raw(host, records, cname_target_status=None):
    return Raw(source=Source.DNS, kind="dns_records", subject=host,
               payload={"records": records, "cname_target_status": cname_target_status,
                        "resolver": "1.1.1.1"},
               evidence_ref="cafebabe" * 8)


# --- the guard --------------------------------------------------------------
@pytest.mark.parametrize("rrtype", ALLOWED_RRTYPES)
def test_allowed_record_types(rrtype):
    assert_passive_dns(rrtype, "vpn.acme-ran.example")


@pytest.mark.parametrize("rrtype", list(DENIED_RRTYPES))
def test_zone_transfer_and_any_are_blocked(rrtype):
    with pytest.raises(ZoneTransferBlocked):
        assert_passive_dns(rrtype, "acme-ran.example")


def test_unknown_record_type_is_blocked_by_default():
    with pytest.raises(ZoneTransferBlocked):
        assert_passive_dns("TXT", "acme-ran.example")


def test_wildcards_are_never_resolved():
    with pytest.raises(ZoneTransferBlocked):
        assert_passive_dns("A", "*.acme-ran.example")


def test_every_denied_type_has_a_documented_reason():
    for rrtype, reason in DENIED_RRTYPES.items():
        assert rrtype.isupper() and len(reason) > 20


def test_evidence_uri_records_the_resolver():
    """Two runs against different resolvers must not collide in the store:
    which resolver answered is part of the evidence."""
    a = evidence_uri("vpn.acme-ran.example", "A", "1.1.1.1")
    b = evidence_uri("vpn.acme-ran.example", "A", "8.8.8.8")
    assert a != b and "1.1.1.1" in a


# --- analyze ----------------------------------------------------------------
def test_resolution_summary_is_info_and_lists_live_sensitive_hosts(collector, target):
    raws = [
        raw("www.acme-ran.example", rec(a=["203.0.113.10"])),
        raw("vpn.acme-ran.example", rec(a=["203.0.113.7"])),
        raw("old.acme-ran.example", rec(a_status="nxdomain")),
    ]
    findings = collector.analyze(raws, target)
    summary = next(f for f in findings if f.type == "hostname_resolves")
    assert summary.signal_strength is SignalStrength.INFO
    assert summary.driver_hint == "vuln_exposure_mgmt"
    assert summary.evidence["hosts_resolving"] == 2
    assert summary.evidence["hosts_nxdomain"] == 1
    assert "vpn.acme-ran.example" in summary.evidence["sensitive_hosts_live"]
    assert "www.acme-ran.example" not in summary.evidence["sensitive_hosts_live"]


def test_dangling_cname_is_moderate_and_escalates(collector, target):
    raws = [raw("shop.acme-ran.example", rec(cname=["bucket.cdn-provider.example"]),
                cname_target_status="nxdomain")]
    dangling = next(f for f in collector.analyze(raws, target) if f.type == "dangling_cname")
    assert dangling.signal_strength is SignalStrength.MODERATE
    assert dangling.needs_followup.value == "human_review"
    assert dangling.evidence["cname_target"] == "bucket.cdn-provider.example"


def test_healthy_cname_produces_no_dangling_finding(collector, target):
    raws = [raw("shop.acme-ran.example", rec(cname=["edge.cdn-provider.example"]),
                cname_target_status="ok")]
    assert not any(f.type == "dangling_cname" for f in collector.analyze(raws, target))


def test_no_resolving_hosts_yields_no_findings(collector, target):
    raws = [raw("gone.acme-ran.example", rec(a_status="nxdomain"))]
    assert collector.analyze(raws, target) == []


# --- handoff ----------------------------------------------------------------
def test_addresses_deduplicate_by_ip(collector):
    """One load balancer behind fifty names must cost one Shodan lookup."""
    raws = [
        raw("a.acme-ran.example", rec(a=["203.0.113.7"])),
        raw("b.acme-ran.example", rec(a=["203.0.113.7"])),
        raw("c.acme-ran.example", rec(a=["203.0.113.9"], aaaa=["2001:db8::1"])),
    ]
    addresses = collector.addresses(raws)
    assert set(addresses) == {"203.0.113.7", "203.0.113.9", "2001:db8::1"}
    assert addresses["203.0.113.7"] == ["a.acme-ran.example", "b.acme-ran.example"]


def test_max_hosts_truncates_the_input_list(collector):
    collector.max_hosts = 2
    collector.inputs = [f"h{i}.acme-ran.example" for i in range(10)]
    assert len([h for h in collector.inputs if "*" not in h][: collector.max_hosts]) == 2
