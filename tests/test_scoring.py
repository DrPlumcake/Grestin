"""The three hub rules, as tests. R1 in particular is the methodological core:
the layer must be structurally incapable of certifying that a driver is clean."""

import pytest

from grestin.config import Config
from grestin.hub.scoring import projected_score, score
from grestin.models import SignalStrength, Source, Verdict


@pytest.fixture
def cfg():
    return Config.load()


def mk(cfg, ftype, source, subject="x", strength="strong"):
    return cfg.make_finding(type=ftype, source=source, subject=subject,
                            evidence={}, strength=strength)


def verdict_for(summary, driver_id):
    return next(v for v in summary.verdicts if v.driver_id == driver_id)


# --- R1 ---------------------------------------------------------------------
def test_no_findings_never_produces_no(cfg):
    summary = score([], cfg)
    assert {v.verdict for v in summary.verdicts} == {Verdict.NOT_OBSERVABLE}
    assert "NO" not in {v.verdict.value for v in summary.verdicts}
    assert summary.suggested_weight == 0.0


def test_not_observable_carries_the_reason(cfg):
    summary = score([], cfg)
    assert "absence" in verdict_for(summary, "vuln_exposure_mgmt").rationale
    assert verdict_for(summary, "nis2_scope").rationale.startswith("Legal scoping")


# --- R2 ---------------------------------------------------------------------
def test_strong_single_pillar_suggests_yes(cfg):
    summary = score([mk(cfg, "kev_on_exposed_service", Source.KEV, "CVE-2024-3400")], cfg)
    v = verdict_for(summary, "vuln_exposure_mgmt")
    assert v.verdict is Verdict.SUGGEST_YES
    assert v.max_strength is SignalStrength.STRONG
    assert summary.suggested_weight == 0.11


def test_info_only_stays_not_observable(cfg):
    summary = score([mk(cfg, "subdomain_observed", Source.CRTSH, strength="info")], cfg)
    assert verdict_for(summary, "vuln_exposure_mgmt").verdict is Verdict.NOT_OBSERVABLE


def test_three_weak_signals_escalate_to_review(cfg):
    findings = [mk(cfg, "sensitive_hostname_observed", Source.CRTSH, f"h{i}", "weak")
                for i in range(3)]
    v = verdict_for(score(findings, cfg), "vuln_exposure_mgmt")
    assert v.verdict is Verdict.REVIEW


# --- R3 ---------------------------------------------------------------------
def test_moderate_alone_is_review_not_yes(cfg):
    summary = score([mk(cfg, "sanctions_match_fuzzy", Source.OPENSANCTIONS, "Acme Ltd")], cfg)
    v = verdict_for(summary, "ownership_due_diligence")
    assert v.verdict is Verdict.REVIEW
    assert summary.suggested_weight == 0.0
    assert summary.review_weight == 0.10


def test_declared_corroboration_pair_promotes_to_yes(cfg):
    """kev_ransomware_flag + dls_listing: the convergence case of section 6.4."""
    findings = [
        mk(cfg, "kev_ransomware_flag", Source.KEV, "CVE-2023-4966", "moderate"),
        mk(cfg, "dls_listing", Source.RANSOMWARE_LIVE, "acme-ran.example", "strong"),
    ]
    summary = score(findings, cfg)
    assert verdict_for(summary, "data_breach_12m").verdict is Verdict.SUGGEST_YES
    assert summary.corroborations


def test_addressable_weight_is_reported(cfg):
    assert score([], cfg).addressable_weight == 0.38


# --- projection -------------------------------------------------------------
def test_projection_shows_the_delta_without_overwriting(cfg):
    declared = {"systems_access": "MAINTENANCE", "data_classification": "C4 - Strictly Confidential"}
    summary = score([mk(cfg, "kev_on_exposed_service", Source.KEV, "CVE-2024-3400")], cfg)
    proj = projected_score(summary, cfg, declared)
    assert proj["declared_score"] == 0.24
    assert proj["declared_level"] == "NOT CRITICAL"
    assert proj["projected_score"] == 0.35
    assert proj["projected_level"] == "SIGNIFICANT"
    assert proj["delta"] == 0.11


def test_projection_flags_crossing_the_phase2_threshold(cfg):
    declared = {"systems_access": "ADMINISTRATIVE ACCESS",
                "data_classification": "C4 - Strictly Confidential",
                "operational_continuity": "YES", "supply_concentration": "YES"}
    findings = [
        mk(cfg, "kev_on_exposed_service", Source.KEV, "CVE-2024-3400"),
        mk(cfg, "sanctions_match_exact", Source.OPENSANCTIONS, "Acme Holding"),
    ]
    proj = projected_score(score(findings, cfg), cfg, declared)
    assert proj["declared_score"] == 0.41            # SIGNIFICANT: no Phase 2
    assert proj["projected_score"] == 0.62           # CRITICAL: Phase 2 triggered
    assert proj["crosses_phase2_threshold"] is True


def test_declared_yes_is_not_double_counted(cfg):
    """If the compiler already answered YES, the CTI suggestion adds nothing."""
    declared = {"vuln_exposure_mgmt": "YES"}
    summary = score([mk(cfg, "kev_on_exposed_service", Source.KEV, "CVE-1")], cfg)
    proj = projected_score(summary, cfg, declared)
    assert proj["declared_score"] == 0.11
    assert proj["delta"] == 0.0
