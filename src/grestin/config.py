"""Configuration loader.

Also the single place where a Finding is allowed to be built, because that is
where rule R2 of mapping.yaml is enforced: a collector *asks* for a strength
and gets `min(asked, ceiling)`. A tool therefore cannot promote its own output
to `strong` by accident, which is the property Chapter 6 claims when it says
almost no single-tool finding reaches strong on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Finding, FollowUp, Pillar, SignalStrength, Source

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@dataclass
class Driver:
    id: str
    name: str
    category: str
    weight: float | None
    answer_cell: str
    fncdp: list[str] = field(default_factory=list)
    nist_t26: list[str] = field(default_factory=list)
    cti_observable: bool = False
    cti_sources: list[str] = field(default_factory=list)
    cti_note: str = ""
    weight_map: dict[str, float] = field(default_factory=dict)
    risk_values: list[str] = field(default_factory=list)
    answer_domain: list[str] = field(default_factory=list)

    @property
    def max_weight(self) -> float:
        if self.weight is not None:
            return self.weight
        return max(self.weight_map.values()) if self.weight_map else 0.0


@dataclass
class Config:
    drivers: dict[str, Driver]
    mapping: dict[str, dict[str, Any]]
    patterns: dict[str, Any]
    risk_levels: list[dict[str, Any]]
    verdict_rules: dict[str, Any]
    meta: dict[str, Any]

    # -- loading -----------------------------------------------------------
    @classmethod
    def load(cls, config_dir: str | Path = CONFIG_DIR) -> Config:
        d = Path(config_dir)
        drivers_raw = yaml.safe_load((d / "drivers.yaml").read_text(encoding="utf-8"))
        mapping_raw = yaml.safe_load((d / "mapping.yaml").read_text(encoding="utf-8"))
        patterns = yaml.safe_load((d / "patterns.yaml").read_text(encoding="utf-8"))

        drivers: dict[str, Driver] = {}
        for item in drivers_raw["drivers"]:
            w = item.get("weight")
            drivers[item["id"]] = Driver(
                id=item["id"],
                name=item["name"],
                category=item.get("category", ""),
                weight=None if w == "variable" else float(w),
                answer_cell=item["answer_cell"],
                fncdp=item.get("fncdp", []) or [],
                nist_t26=item.get("nist_t26", []) or [],
                cti_observable=bool(item.get("cti_observable", False)),
                cti_sources=item.get("cti_sources", []) or [],
                cti_note=item.get("cti_note", ""),
                weight_map=item.get("weight_map", {}) or {},
                risk_values=item.get("risk_values", []) or [],
                answer_domain=item.get("answer_domain", []) or [],
            )

        cfg = cls(
            drivers=drivers,
            mapping=mapping_raw["finding_types"],
            patterns=patterns,
            risk_levels=drivers_raw["risk_levels"],
            verdict_rules=mapping_raw["verdict_rules"],
            meta=drivers_raw["meta"],
        )
        cfg.validate()
        return cfg

    # -- integrity ---------------------------------------------------------
    def validate(self) -> None:
        """Fail loudly on config drift. Called at load time on purpose: a
        mapping that points at a driver the tool does not have is a thesis
        error, not a runtime warning."""
        fixed = sum(d.weight for d in self.drivers.values() if d.weight is not None)
        variable = max(
            (max(d.weight_map.values()) for d in self.drivers.values() if d.weight_map),
            default=0.0,
        )
        total = round(fixed + variable, 6)
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                f"driver weights sum to {total}, expected 1.00 - drivers.yaml is out of "
                "sync with the Third Parties Risk Evaluation Tool"
            )
        for ftype, spec in self.mapping.items():
            if spec["driver"] not in self.drivers:
                raise ValueError(f"mapping {ftype!r} -> unknown driver {spec['driver']!r}")
            SignalStrength(spec["strength_ceiling"])  # raises on typo

    # -- accessors ---------------------------------------------------------
    @property
    def addressable_weight(self) -> float:
        return round(sum(d.max_weight for d in self.drivers.values() if d.cti_observable), 6)

    def threshold(self, name: str) -> Any:
        return self.patterns["thresholds"][name]

    def risk_level(self, score: float) -> str:
        for lvl in self.risk_levels:
            if score >= lvl["min"]:
                return lvl["label"]
        return self.risk_levels[-1]["label"]

    def sensitive_categories(self, hostname: str) -> list[str]:
        """Which sensitive-hostname categories a hostname matches."""
        labels = hostname.lower().split(".")
        head = labels[:-2] if len(labels) > 2 else labels[:1]
        hit: list[str] = []
        for category, tokens in self.patterns["sensitive_hostnames"].items():
            for tok in tokens:
                if any(tok == lbl or tok in lbl.split("-") or tok in lbl for lbl in head):
                    hit.append(category)
                    break
        return hit

    # -- the only Finding factory -----------------------------------------
    def make_finding(
        self,
        *,
        type: str,
        source: Source,
        subject: str,
        evidence: dict[str, Any],
        strength: SignalStrength | str,
        note: str = "",
        evidence_refs: list[str] | None = None,
        source_default: Pillar | None = None,
    ) -> Finding:
        try:
            spec = self.mapping[type]
        except KeyError as exc:  # pragma: no cover - programmer error
            raise KeyError(
                f"finding type {type!r} is not declared in config/mapping.yaml; "
                "an undeclared type would bypass the driver mapping"
            ) from exc

        asked = SignalStrength(strength)
        ceiling = SignalStrength(spec["strength_ceiling"])
        capped = min(asked, ceiling)

        driver = self.drivers[spec["driver"]]
        controls = list(driver.fncdp) + [f"NIST T26 {s}" for s in driver.nist_t26]

        return Finding(
            source=source,
            type=type,
            subject=subject,
            evidence=evidence,
            signal_strength=capped,
            driver_hint=driver.id,
            needs_followup=FollowUp(spec.get("followup", "none")),
            pillar=Pillar(spec.get("pillar", (source_default or Pillar.TECHNICAL).value)),
            controls=controls,
            evidence_refs=evidence_refs or [],
            note=note or ("" if capped == asked else f"strength capped from {asked.value} by policy"),
        )
