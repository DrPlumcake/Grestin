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
    return CrtShCollector(client=None, config=Config.load(), stats=None)


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
