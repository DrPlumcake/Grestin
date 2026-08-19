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
    """All thirteen answers live in one column, whichever column that is.

    Pinning the letter was a mistake: tool v2.1 inserted an ENISA 5G column
    before ANSWER and the answers moved from G to H. What matters is not which
    letter it is but that there is exactly one - the moment two drivers sit in
    different columns, the advisory columns derived from `answer_cell` would
    land on top of a populated cell for at least one of them."""
    cfg = Config.load()
    cells = [d.answer_cell for d in cfg.drivers.values()]
    assert len(set(cells)) == len(cells)
    columns = {"".join(c for c in cell if c.isalpha()) for cell in cells}
    assert len(columns) == 1, f"answers spread across columns: {sorted(columns)}"


def test_suggestion_columns_sit_to_the_right_of_the_answers():
    """The three advisory columns must never overlap the answer column: that
    would write verdict strings past the data validation and into the range the
    score formula reads."""
    from openpyxl.utils import column_index_from_string

    from grestin.hub.prefill import suggestion_cols

    cfg = Config.load()
    answer_col = column_index_from_string(
        "".join(c for c in next(iter(cfg.drivers.values())).answer_cell if c.isalpha()))
    cols = suggestion_cols(cfg)
    assert min(cols.values()) > answer_col
    assert sorted(cols.values()) == list(range(answer_col + 1, answer_col + 4))


def test_sensitive_hostname_matching():
    cfg = Config.load()
    assert "remote_access" in cfg.sensitive_categories("vpn.example.com")
    assert "devops" in cfg.sensitive_categories("jenkins-ci.example.com")
    assert "non_production" in cfg.sensitive_categories("uat.api.example.com")
    assert cfg.sensitive_categories("www.example.com") == []
