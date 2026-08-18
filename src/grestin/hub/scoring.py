"""The hub: findings -> proposed answers for the Phase 1 driver matrix.

This is where the architecture's central claim becomes an algorithm. Three
rules, all of them defensible in fifteen minutes:

R1  The layer never answers NO. Passive OSINT can raise a driver
    (SUGGEST_YES), or ask a human to look (REVIEW), or admit it saw nothing
    (NOT_OBSERVABLE). Reading NOT_OBSERVABLE as NO would turn absence of
    evidence into evidence of absence, which is the single easiest way to make
    an automated layer dangerous. The compiler of the tool still owns the cell.

R2  Strength is capped per finding type (enforced in config.make_finding), so
    a driver reaches SUGGEST_YES only when a finding type that is *allowed* to
    be strong actually is - i.e. at the end of the technical chain (KEV on an
    exposed service), on an exact sanctions identifier match, or on a
    leak-site listing inside the 12-month window.

R3  A `moderate` maximum is promoted to SUGGEST_YES only with corroboration
    from a different pillar (or an explicit `corroborates` pair in
    mapping.yaml). This is the formal version of "two pillars that do not
    communicate point at the same risk".

The output is an *advisory delta*, never a score that overwrites the tool's.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ..config import Config, Driver
from ..models import DriverVerdict, Finding, SignalStrength, Verdict


@dataclass
class ScoreSummary:
    """Aggregate numbers for the report, the slides and stats.json."""

    addressable_weight: float
    suggested_weight: float          # sum of weights of SUGGEST_YES drivers
    review_weight: float             # sum of weights of REVIEW drivers
    verdicts: list[DriverVerdict] = field(default_factory=list)
    corroborations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def suggest_yes(self) -> list[DriverVerdict]:
        return [v for v in self.verdicts if v.verdict is Verdict.SUGGEST_YES]

    @property
    def review(self) -> list[DriverVerdict]:
        return [v for v in self.verdicts if v.verdict is Verdict.REVIEW]

    def to_dict(self) -> dict[str, Any]:
        return {
            "addressable_weight": self.addressable_weight,
            "suggested_weight": round(self.suggested_weight, 4),
            "review_weight": round(self.review_weight, 4),
            "counts": {
                "suggest_yes": len(self.suggest_yes),
                "review": len(self.review),
                "not_observable": len([v for v in self.verdicts
                                       if v.verdict is Verdict.NOT_OBSERVABLE]),
            },
            "corroborations": self.corroborations,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


def _corroboration_links(config: Config) -> dict[str, set[str]]:
    """Symmetric closure of the `corroborates:` declarations in mapping.yaml.

    Declaring the pair once is enough; the graph is made undirected here so a
    convergence is detected from either side.
    """
    links: dict[str, set[str]] = {}
    for ftype, spec in config.mapping.items():
        for other in spec.get("corroborates", []) or []:
            links.setdefault(ftype, set()).add(other)
            links.setdefault(other, set()).add(ftype)
    return links


def _corroborated(
    findings: list[Finding],
    config: Config,
    global_types: dict[str, set[str]],
    links: dict[str, set[str]],
) -> tuple[bool, list[str]]:
    """Corroboration in the sense of section 6.4, in two forms.

    (a) *Within* a driver: two findings of >= moderate from different pillars
        point at the same driver.
    (b) *Across* drivers: a finding type declares a `corroborates` partner in
        mapping.yaml and that partner is present in the run at >= moderate,
        from a different pillar. This is the KEV-with-ransomware-flag /
        leak-site-listing case: the two signals bear on different drivers
        (vulnerability management and data breach) yet each raises the
        confidence of the other, which is precisely why the design is
        hub-and-spoke with independent spokes.

    `global_types` maps finding type -> set of pillars that produced it at
    >= moderate anywhere in the run.
    """
    considered = [f for f in findings if f.signal_strength >= SignalStrength.MODERATE]
    pillars = {f.pillar.value for f in considered}

    if len(pillars) >= 2:
        return True, sorted(pillars)

    for f in considered:
        for partner in links.get(f.type, set()):
            other_pillars = global_types.get(partner, set()) - {f.pillar.value}
            if other_pillars:
                return True, sorted(pillars | other_pillars)
    return False, sorted(pillars)


def score(findings: Iterable[Finding], config: Config) -> ScoreSummary:
    """Turn a flat finding list into one verdict per CTI-observable driver."""
    findings = list(findings)
    by_driver: dict[str, list[Finding]] = defaultdict(list)
    global_types: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        by_driver[f.driver_hint].append(f)
        if f.signal_strength >= SignalStrength.MODERATE:
            global_types[f.type].add(f.pillar.value)
    links = _corroboration_links(config)

    verdicts: list[DriverVerdict] = []
    corroborations: list[dict[str, Any]] = []
    suggested = review_w = 0.0

    for driver_id, driver in config.drivers.items():
        fs = by_driver.get(driver_id, [])
        weight = driver.max_weight if driver.weight is not None else None

        if not fs:
            verdicts.append(DriverVerdict(
                driver_id=driver_id,
                driver_name=driver.name,
                weight=weight,
                verdict=Verdict.NOT_OBSERVABLE,
                max_strength=None,
                rationale=(driver.cti_note.strip() if not driver.cti_observable
                           else "no passive signal observed in this run; "
                                "absence of evidence is not evidence of absence"),
            ))
            continue

        max_strength = max(f.signal_strength for f in fs)
        corr, pillars = _corroborated(fs, config, global_types, links)
        weak_count = len([f for f in fs if f.signal_strength >= SignalStrength.WEAK])

        if max_strength is SignalStrength.STRONG:
            verdict = Verdict.SUGGEST_YES
            why = (f"{max_strength.value} signal from "
                   f"{', '.join(sorted({f.source.value for f in fs}))}")
        elif max_strength is SignalStrength.MODERATE and corr:
            verdict = Verdict.SUGGEST_YES
            why = f"moderate signal corroborated across pillars: {', '.join(pillars)}"
        elif max_strength is SignalStrength.MODERATE:
            verdict = Verdict.REVIEW
            why = "moderate signal, uncorroborated: human adjudication required"
        elif weak_count >= 3:
            verdict = Verdict.REVIEW
            why = f"{weak_count} weak signals accumulate into a question for the supplier"
        elif weak_count:
            verdict = Verdict.NOT_OBSERVABLE
            why = (f"{weak_count} weak signal(s), below the threshold of 3: recorded in "
                   "the report but not enough to put a question to the supplier")
        else:
            verdict = Verdict.NOT_OBSERVABLE
            why = "only informational signals; nothing to put to the supplier"

        if corr:
            corroborations.append({
                "driver": driver_id,
                "pillars": pillars,
                "finding_types": sorted({f.type for f in fs
                                         if f.signal_strength >= SignalStrength.MODERATE}),
            })

        if weight is not None:
            if verdict is Verdict.SUGGEST_YES:
                suggested += weight
            elif verdict is Verdict.REVIEW:
                review_w += weight

        verdicts.append(DriverVerdict(
            driver_id=driver_id,
            driver_name=driver.name,
            weight=weight,
            verdict=verdict,
            max_strength=max_strength,
            findings=sorted(fs, key=lambda f: -f.signal_strength.rank),
            rationale=why,
            corroborating_pillars=pillars if corr else [],
        ))

    # R1, asserted rather than assumed: no code path may emit "NO".
    assert all(v.verdict is not None for v in verdicts)
    assert "NO" not in {v.verdict.value for v in verdicts}

    return ScoreSummary(
        addressable_weight=config.addressable_weight,
        suggested_weight=suggested,
        review_weight=review_w,
        verdicts=verdicts,
        corroborations=corroborations,
    )


def _declared_weight(driver: Driver, answer: str | None) -> float:
    """The weight one declared answer contributes, mirroring the workbook.

    'Driver Configuration'!G2 is
        SUM(weight WHERE answer == "YES") + weight(data_classification)
    so three shapes of answer exist: a weight_map driver (data classification,
    which always contributes something), a driver with an explicit
    `risk_values` list (systems access, where the risk condition is one of
    several access levels), and the plain YES/NO majority.

    This predicate is deliberately the *only* place that knows the workbook's
    arithmetic, because `projected_score` needs to ask the same question twice
    - "what does the declared answer contribute?" and "does the CTI suggestion
    add anything on top?" - and the two answers must not be able to drift.
    """
    if answer is None:
        return 0.0
    if driver.weight_map:
        return driver.weight_map.get(answer, 0.0)
    if driver.risk_values:
        return (driver.weight or 0.0) if answer in driver.risk_values else 0.0
    return (driver.weight or 0.0) if str(answer).upper() == "YES" else 0.0


def projected_score(summary: ScoreSummary, config: Config,
                    declared_answers: dict[str, str] | None = None) -> dict[str, Any]:
    """What the tool would compute if the compiler accepted every SUGGEST_YES.

    Presented as a *projection*, side by side with the declared-only score, so
    the report shows the delta the CTI layer would introduce instead of
    silently changing a number.

    The condition for adding a weight is **not** "the compiler has not answered
    this driver" but "the answer on record does not already carry that weight".
    The difference is the whole point of the layer: `read_declared_answers`
    drops empty and "-" cells but keeps an explicit "NO", so under the weaker
    condition the flagship case - the supplier declares NO and the layer finds
    evidence to the contrary - would silently project a delta of zero, i.e. the
    one case the architecture exists to surface would be the one case it could
    not show. Both cases add the weight; they are reported apart, because a
    contradicted NO is a question for the supplier while an unanswered cell is
    only a gap in the questionnaire.

    Drivers scored through a `weight_map` (data classification) are skipped:
    they always contribute, they are never CTI-observable, and "already at
    risk" is not defined for them.
    """
    declared = declared_answers or {}

    base = 0.0
    for driver_id, driver in config.drivers.items():
        base += _declared_weight(driver, declared.get(driver_id))

    projected = base
    contradicted: list[str] = []   # declared NO, evidence says otherwise
    unanswered: list[str] = []     # cell still empty, the layer proposes a value
    for v in summary.suggest_yes:
        driver = config.drivers.get(v.driver_id)
        if driver is None or not v.weight or driver.weight_map:
            continue
        answer = declared.get(v.driver_id)
        if _declared_weight(driver, answer) > 0.0:
            continue               # the weight is already in `base`
        projected += v.weight
        (contradicted if answer is not None else unanswered).append(v.driver_id)

    return {
        "declared_score": round(base, 4),
        "declared_level": config.risk_level(base),
        "projected_score": round(projected, 4),
        "projected_level": config.risk_level(projected),
        "delta": round(projected - base, 4),
        "crosses_phase2_threshold": (
            config.risk_level(projected) in ("VERY CRITICAL", "CRITICAL")
            and config.risk_level(base) not in ("VERY CRITICAL", "CRITICAL")
        ),
        #: SUGGEST_YES on a driver the compiler explicitly answered NO. This is
        #: the dissonance the thesis is about; the report should name it.
        "contradicted_drivers": contradicted,
        #: SUGGEST_YES on a driver left blank: a gap, not a contradiction.
        "unanswered_drivers": unanswered,
    }