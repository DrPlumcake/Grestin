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
    # neither a contradiction nor a gap: the answer on record already agrees
    assert proj["contradicted_drivers"] == []
    assert proj["unanswered_drivers"] == []


def test_a_contradicted_no_still_moves_the_projection(cfg):
    """The flagship case. The compiler answered NO, the layer found a KEV CVE
    on an exposed service. `read_declared_answers` drops "-" but keeps "NO", so
    a projection that skipped every driver already present in the declared dict
    would report a delta of zero on precisely the dissonance the layer exists
    to surface."""
    declared = {"vuln_exposure_mgmt": "NO"}
    summary = score([mk(cfg, "kev_on_exposed_service", Source.KEV, "CVE-1")], cfg)
    proj = projected_score(summary, cfg, declared)
    assert proj["declared_score"] == 0.0
    assert proj["projected_score"] == 0.11
    assert proj["delta"] == 0.11
    assert proj["contradicted_drivers"] == ["vuln_exposure_mgmt"]
    assert proj["unanswered_drivers"] == []


def test_a_contradiction_is_reported_apart_from_a_gap(cfg):
    """Same arithmetic, different follow-up: a contradicted NO is a question to
    put to the supplier, an empty cell is only an unanswered question."""
    declared = {"vuln_exposure_mgmt": "NO"}          # ownership left blank
    findings = [
        mk(cfg, "kev_on_exposed_service", Source.KEV, "CVE-1"),
        mk(cfg, "sanctions_match_exact", Source.OPENSANCTIONS, "Acme Holding"),
    ]
    proj = projected_score(score(findings, cfg), cfg, declared)
    assert proj["delta"] == 0.21                      # 0.11 + 0.10
    assert proj["contradicted_drivers"] == ["vuln_exposure_mgmt"]
    assert proj["unanswered_drivers"] == ["ownership_due_diligence"]


def test_a_contradicted_no_can_be_what_triggers_phase_2(cfg):
    """The consequence that matters operationally: the supplier's own answers
    keep it below the Phase 2 threshold, the contradicted drivers push it over."""
    declared = {"systems_access": "ADMINISTRATIVE ACCESS",
                "data_classification": "C4 - Strictly Confidential",
                "operational_continuity": "YES",
                "vuln_exposure_mgmt": "NO",
                "data_breach_12m": "NO"}
    findings = [
        mk(cfg, "kev_on_exposed_service", Source.KEV, "CVE-1"),
        mk(cfg, "dls_listing", Source.RANSOMWARE_LIVE, "acme.example"),
    ]
    proj = projected_score(score(findings, cfg), cfg, declared)
    assert proj["declared_score"] == 0.33             # SIGNIFICANT: no Phase 2
    assert proj["projected_score"] == 0.51            # CRITICAL: Phase 2
    assert proj["crosses_phase2_threshold"] is True
    assert sorted(proj["contradicted_drivers"]) == ["data_breach_12m", "vuln_exposure_mgmt"]


def test_the_projection_ignores_a_declared_answer_for_an_unknown_driver(cfg):
    """A stale YAML must not inflate the declared baseline."""
    proj = projected_score(score([], cfg), cfg, {"driver_that_was_removed": "YES"})
    assert proj["declared_score"] == 0.0


# --- run integrity: R1 applied to the run itself ----------------------------
def test_a_failed_stage_is_never_reported_as_a_clean_result():
    """The Nokia case, from a real run: crt.sh aborted, the whole technical
    chain produced nothing, and the summary line was indistinguishable from a
    supplier with no exposed surface. A run must carry its own integrity."""
    from grestin.models import RunStats

    stats = RunStats(run_id="x", target="Nokia Corporation")
    stats.record_stage("crtsh", RunStats.FAILED, raws=0, findings=0, errors=2)
    assert stats.integrity == "invalid"
    assert stats.failed_stages == ["crtsh"]
    assert stats.to_dict()["integrity"] == "invalid"


def test_a_stage_that_answered_with_nothing_is_not_a_failure():
    from grestin.models import RunStats

    stats = RunStats(run_id="x", target="y")
    stats.record_stage("crtsh", RunStats.OK, raws=2, findings=3)
    stats.record_stage("ransomware_live", RunStats.EMPTY)
    assert stats.integrity == "complete"
    assert stats.failed_stages == []


def test_an_http_failure_no_stage_reported_still_downgrades_the_run():
    """A request that exhausted its retries is a hole in the collection even
    when the collector routed around it through a fallback interface and
    recorded no error of its own. The stage statuses cannot see that, so a run
    with an unreachable endpoint would otherwise be presented as complete and
    its zero findings read as a clean supplier."""
    from grestin.models import RunStats

    stats = RunStats(run_id="x", target="y")
    stats.record_stage("crtsh", RunStats.OK, raws=1, findings=0)
    assert stats.integrity == "complete"
    stats.http["failures"] = 2
    assert stats.integrity == "degraded"


def test_a_failed_stage_outranks_an_http_failure():
    """Degrading is the weaker verdict: it must not mask an invalid run."""
    from grestin.models import RunStats

    stats = RunStats(run_id="x", target="y")
    stats.record_stage("crtsh", RunStats.FAILED, raws=0, findings=0, errors=1)
    stats.http["failures"] = 1
    assert stats.integrity == "invalid"


def test_partial_data_marks_the_run_degraded():
    from grestin.models import RunStats

    stats = RunStats(run_id="x", target="y")
    stats.record_stage("crtsh", RunStats.OK, raws=2, findings=3)
    stats.record_stage("dns", RunStats.DEGRADED, raws=40, findings=1, errors=6)
    assert stats.integrity == "degraded"
    assert stats.failed_stages == ["dns"]


# --- target hygiene ---------------------------------------------------------
def test_domains_pasted_as_urls_are_normalised_and_reported():
    """A real target file listed three browser URLs. crt.sh answered 200 with
    an empty result set and the run looked successful."""
    from grestin.models import Target

    t = Target(legal_name="Sapienza", domains=[
        "https://www.uniroma1.it/",
        "https://www.uniroma1.it/en/pagina-strutturale/home",
        "UNIROMA1.IT",
    ])
    assert t.domains == ["uniroma1.it"]
    assert len(t.domain_warnings) >= 2


def test_unusable_domain_is_dropped_with_a_warning():
    from grestin.models import Target

    t = Target(legal_name="X", domains=["localhost", "acme.example"])
    assert t.domains == ["acme.example"]
    assert any("not a usable domain" in w for w in t.domain_warnings)
