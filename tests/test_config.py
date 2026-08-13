"""drivers.yaml is a transcription of a spreadsheet. These tests are what stop
the transcription from silently diverging from the tool - and from the thesis."""

import yaml

from grestin.config import CONFIG_DIR, Config
from grestin.models import SignalStrength


def test_weights_sum_to_one():
    """0.88 fixed + 0.12 max data classification = 1.00, per the tool."""
    cfg = Config.load()                   # validate() raises if it does not
    fixed = sum(d.weight for d in cfg.drivers.values() if d.weight is not None)
    assert round(fixed, 6) == 0.88
    assert len(cfg.drivers) == 13


def test_heaviest_driver_is_systems_access():
    """Guards against the claim, wrong in an early draft, that the heaviest
    Phase 1 driver is sub-supplier transparency."""
    cfg = Config.load()
    heaviest = max(cfg.drivers.values(), key=lambda d: d.max_weight)
    assert heaviest.id == "systems_access"
    assert heaviest.weight == 0.12
    assert cfg.drivers["subsupplier_transparency"].weight == 0.06


def test_data_classification_weight_map():
    cfg = Config.load()
    wm = cfg.drivers["data_classification"].weight_map
    assert wm == {
        "C1 - Public": 0.02,
        "C2 - Internal Use": 0.04,
        "C3 - Confidential": 0.09,
        "C4 - Strictly Confidential": 0.12,
    }


def test_addressable_coverage_matches_documented_value():
    cfg = Config.load()
    declared = yaml.safe_load((CONFIG_DIR / "drivers.yaml").read_text())["expected_coverage"]
    assert cfg.addressable_weight == declared["addressable_weight"] == 0.38


def test_risk_levels_match_the_workbook_thresholds():
    cfg = Config.load()
    assert cfg.risk_level(0.80) == "VERY CRITICAL"
    assert cfg.risk_level(0.75) == "VERY CRITICAL"
    assert cfg.risk_level(0.50) == "CRITICAL"
    assert cfg.risk_level(0.26) == "SIGNIFICANT"
    assert cfg.risk_level(0.16) == "NOT CRITICAL"


def test_every_mapping_targets_a_real_driver_and_a_valid_strength():
    cfg = Config.load()
    for ftype, spec in cfg.mapping.items():
        assert spec["driver"] in cfg.drivers, ftype
        SignalStrength(spec["strength_ceiling"])


def test_only_declared_tools_can_reach_strong():
    """R2: `strong` is reserved for the end of a chain or an exact match."""
    cfg = Config.load()
    strong = {f for f, s in cfg.mapping.items()
              if s["strength_ceiling"] == SignalStrength.STRONG.value}
    assert strong == {"kev_on_exposed_service", "kev_ransomware_flag",
                      "sanctions_match_exact", "dls_listing"}


def test_answer_cells_are_unique_and_in_the_answer_column():
    cfg = Config.load()
    cells = [d.answer_cell for d in cfg.drivers.values()]
    assert len(set(cells)) == len(cells)
    assert all(c.startswith("G") for c in cells)


def test_sensitive_hostname_matching():
    cfg = Config.load()
    assert "remote_access" in cfg.sensitive_categories("vpn.example.com")
    assert "devops" in cfg.sensitive_categories("jenkins-ci.example.com")
    assert "non_production" in cfg.sensitive_categories("uat.api.example.com")
    assert cfg.sensitive_categories("www.example.com") == []
