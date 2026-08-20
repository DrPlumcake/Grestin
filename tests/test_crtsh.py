"""`analyze` is a pure function, so the stage-1 interpretation is testable with
no network at all. This is also what makes the whole run replayable offline."""

import json
from pathlib import Path

import pytest

from grestin.config import Config
from grestin.models import Raw, SignalStrength, Source, Target
from grestin.pillars.technical.crtsh import CrtShCollector

FIXTURE = Path(__file__).parent / "fixtures" / "crtsh_acme.json"


@pytest.fixture
def collector():
    # The fixture certificates are from 2025; pin the horizon so the run is
    # reproducible instead of depending on today's date.
    return CrtShCollector(client=None, config=Config.load(), stats=None,
                          horizon="2025-01-01")


@pytest.fixture
def raws():
    entries = json.loads(FIXTURE.read_text())
    return [Raw(source=Source.CRTSH, kind="certificate_entries", subject="acme-ran.example",
                payload={"query": "%.acme-ran.example", "entries": entries},
                evidence_ref="deadbeef" * 8)]


@pytest.fixture
def target():
    return Target(legal_name="Acme RAN S.p.A.", domains=["acme-ran.example"], country="IT")


def test_inventory_finding_is_info_and_scoped(collector, raws, target):
    findings = collector.analyze(raws, target)
    inv = next(f for f in findings if f.type == "subdomain_observed")
    assert inv.signal_strength is SignalStrength.INFO
    assert inv.driver_hint == "vuln_exposure_mgmt"
    assert inv.needs_followup.value == "next_tool"
    # out-of-scope SAN from a shared certificate must not be counted
    assert "shop.partner-unrelated.example" not in inv.evidence["sample"]
    # wildcard recorded separately, never as a host
    assert inv.evidence["wildcards_observed"] == ["*.acme-ran.example"]


def test_case_and_trailing_dot_are_normalised(collector, raws, target):
    hosts = collector.resolvable_hosts(raws, target)
    assert hosts.count("api.acme-ran.example") == 1
    assert all(h == h.lower() and not h.endswith(".") for h in hosts)
    assert not any("*" in h for h in hosts)


def test_sensitive_hostnames_are_flagged_by_category(collector, raws, target):
    findings = collector.analyze(raws, target)
    sens = next(f for f in findings if f.type == "sensitive_hostname_observed")
    cats = sens.evidence["by_category"]
    assert "vpn.acme-ran.example" in cats["remote_access"]
    assert "jenkins.acme-ran.example" in cats["devops"]
    assert "uat-portal.acme-ran.example" in cats["non_production"]
    assert "sso.acme-ran.example" in cats["identity"]
    assert sens.signal_strength is SignalStrength.WEAK   # never higher on names alone


def test_strength_ceiling_cannot_be_exceeded(collector, target):
    """A collector asking for `strong` on an inventory finding gets `info`."""
    cfg = Config.load()
    f = cfg.make_finding(
        type="subdomain_observed", source=Source.CRTSH, subject="x",
        evidence={}, strength=SignalStrength.STRONG,
    )
    assert f.signal_strength is SignalStrength.INFO
    assert "capped" in f.note


def test_undeclared_finding_type_is_rejected():
    cfg = Config.load()
    with pytest.raises(KeyError):
        cfg.make_finding(type="something_i_invented", source=Source.CRTSH,
                         subject="x", evidence={}, strength="weak")


def test_surface_anomaly_only_when_declared(collector, raws, target):
    assert not any(f.type == "surface_scale_anomaly" for f in collector.analyze(raws, target))
    target.declared_hosts = 2          # 9 observed / 2 declared = 4.5x >= 3.0
    findings = collector.analyze(raws, target)
    anomaly = next(f for f in findings if f.type == "surface_scale_anomaly")
    assert anomaly.evidence["ratio"] >= 3.0
    assert anomaly.needs_followup.value == "human_review"


def test_analyze_is_deterministic(collector, raws, target):
    a = [f.fingerprint for f in collector.analyze(raws, target)]
    b = [f.fingerprint for f in collector.analyze(raws, target)]
    assert a == b


def test_empty_response_yields_no_findings(collector, target):
    empty = [Raw(source=Source.CRTSH, kind="certificate_entries", subject="acme-ran.example",
                 payload={"query": "%.acme-ran.example", "entries": []})]
    assert collector.analyze(empty, target) == []


def test_expired_certificates_are_filtered_client_side(raws, target):
    """crt.sh's `exclude=expired` makes the query far heavier server-side, so
    the collector falls back to the unfiltered form when it times out. The
    inventory must come out the same either way, which means the expiry filter
    has to exist here too."""
    late = CrtShCollector(client=None, config=Config.load(), stats=None,
                          horizon="2026-01-01")
    assert late.analyze(raws, target) == []          # every fixture cert expired in 2025

    early = CrtShCollector(client=None, config=Config.load(), stats=None,
                           horizon="2025-01-01")
    inventory = next(f for f in early.analyze(raws, target)
                     if f.type == "subdomain_observed")
    assert inventory.evidence["hosts_observed"] == 10


# --- resilience of stage 1 --------------------------------------------------
def test_certspotter_adapter_produces_crtsh_shaped_entries():
    """The fallback must not require `analyze` to know where data came from."""
    entries = CrtShCollector._from_certspotter([{
        "dns_names": ["vpn.acme-ran.example", "sso.acme-ran.example"],
        "issuer": {"name": "C=US, O=Let's Encrypt, CN=R3"},
        "not_before": "2025-02-10T09:00:00", "not_after": "2025-05-11T09:00:00",
    }])
    assert entries[0]["common_name"] == "vpn.acme-ran.example"
    assert "sso.acme-ran.example" in entries[0]["name_value"]
    assert entries[0]["not_after"] == "2025-05-11T09:00:00"


def test_both_interfaces_yield_the_same_inventory(target):
    """Same logs, different operator: the findings must not depend on which
    interface answered."""
    cfg = Config.load()
    crtsh_entries = json.loads(FIXTURE.read_text())
    spotter_entries = CrtShCollector._from_certspotter([
        {"dns_names": [n for n in str(e.get("name_value", "")).splitlines() if n],
         "issuer": {"name": e.get("issuer_name", "")},
         "not_before": e.get("not_before"), "not_after": e.get("not_after")}
        for e in crtsh_entries
    ])
    collector = CrtShCollector(None, cfg, None, horizon="2025-01-01")
    a = collector.analyze([Raw(source=Source.CRTSH, kind="certificate_entries",
                               subject="acme-ran.example",
                               payload={"query": "%.acme-ran.example",
                                        "entries": crtsh_entries})], target)
    b = collector.analyze([Raw(source=Source.CRTSH, kind="certificate_entries",
                               subject="acme-ran.example",
                               payload={"query": "%.acme-ran.example",
                                        "entries": spotter_entries})], target)
    inv_a = next(f for f in a if f.type == "subdomain_observed")
    inv_b = next(f for f in b if f.type == "subdomain_observed")
    assert inv_a.evidence["hosts_observed"] == inv_b.evidence["hosts_observed"] == 10


def test_expired_certificates_are_not_handed_to_the_resolver():
    """CT is append-only, so an unfiltered query returns the whole issuance
    history. Without the horizon the resolver received names drawn from
    certificates that expired years ago, and `hosts_observed` and
    `hosts_for_dns` described different populations."""
    col = CrtShCollector(client=None, config=Config.load(), horizon="2026-01-01")
    raw = Raw(source=Source.CRTSH, kind="certificate_entries", subject="example.com",
              payload={"query": "%.example.com", "entries": [
                  {"common_name": "live.example.com", "name_value": "live.example.com",
                   "not_before": "2025-06-01", "not_after": "2026-06-01"},
                  {"common_name": "gone.example.com", "name_value": "gone.example.com",
                   "not_before": "2019-01-01", "not_after": "2020-01-01"},
              ]})
    target = Target(legal_name="Example", domains=["example.com"])
    assert col.resolvable_hosts([raw], target) == ["live.example.com"]
    assert {f.type for f in col.analyze([raw], target)} == {"subdomain_observed"}
