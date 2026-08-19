"""Core data model.

`Finding` is the code-level realisation of Table 6.1 of the thesis: the uniform
risk-finding schema shared by all three pillars. Keep the field names in the
table and in this class identical - the report generator prints them, so a
rename here is a rename in the appendix.

Design notes worth defending at the viva:
  * Raw and Finding are separate types. Raw is deterministic extraction from a
    tool response; Finding is interpretation. The boundary is what makes the
    pipeline auditable: raws are replayable from the evidence store, findings
    can be recomputed from raws without any network access.
  * SignalStrength is ordinal and comparable, so scoring can speak of a
    maximum strength per driver instead of ad-hoc numeric confidence.
  * There is deliberately no `Finding(answer="NO")`. A passive layer can raise
    a driver or stay silent; it can never certify absence.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utcnow() -> str:
    """ISO-8601 UTC timestamp, second precision. Used in evidence and findings."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class OrderedEnum(StrEnum):
    """String enum ordered by declaration order rather than alphabetically.

    StrEnum would otherwise inherit str's comparison, which would make
    `SignalStrength.INFO > SignalStrength.MODERATE` true ("i" > "m" is false,
    but "weak" > "strong" is true) - silently wrong in the scoring hub. Hence
    the explicit rank-based operators below.
    """

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank


class SignalStrength(OrderedEnum):
    """Ordinal confidence. Order matters: INFO < WEAK < MODERATE < STRONG."""

    INFO = "info"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


class Pillar(StrEnum):
    TECHNICAL = "technical"
    CORPORATE = "corporate"
    INCIDENT = "incident"


class Source(StrEnum):
    CRTSH = "crt.sh"
    DNS = "dns"
    SHODAN = "shodan"
    NVD = "nvd"
    KEV = "kev"
    EPSS = "epss"
    OPENSANCTIONS = "opensanctions"
    RANSOMWARE_LIVE = "ransomware.live"


class FollowUp(StrEnum):
    """Where the finding goes next.

    NEXT_TOOL keeps it inside the technical chain; HUMAN_REVIEW escalates to a
    function (Security, Legal, Procurement) and is the mechanism by which the
    layer shifts the burden of explanation onto the supplier.
    """

    NONE = "none"
    NEXT_TOOL = "next_tool"
    HUMAN_REVIEW = "human_review"


class Verdict(StrEnum):
    """Proposed driver answer. `NO` is intentionally absent - see module docstring."""

    SUGGEST_YES = "SUGGEST_YES"
    REVIEW = "REVIEW"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"


@dataclass
class Target:
    """The third party under assessment.

    `declared_*` fields exist so the layer can compare what the supplier says
    with what is observed: the dissonance, not the raw observation, is the
    contribution.
    """

    legal_name: str
    domains: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    country: str | None = None
    #: Registration identifiers we already hold for the counterparty
    #: (registrationNumber, taxNumber, vatCode, leiCode...). They are what
    #: turns a name similarity into an identification, so without them the
    #: corporate pillar can never reach `strong` - by design, not by omission.
    identifiers: dict[str, str] = field(default_factory=dict)
    declared_hosts: int | None = None
    declared_extra_eu: bool | None = None
    declared_breach_12m: bool | None = None
    notes: str = ""
    #: filled by __post_init__; the CLI prints these so a mistyped target file
    #: cannot pass for a supplier with no attack surface
    domain_warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.domain_warnings = self.normalise_domains()

    def normalise_domains(self) -> list[str]:
        """Reduce whatever was written in the target file to bare hostnames.

        A domain pasted from a browser (`https://www.uniroma1.it/en/page`)
        produced the crt.sh query `%.https://www.uniroma1.it/en/page`, which
        answers 200 with an empty result set: the run looked successful and
        found nothing. Normalising here, and reporting what was changed, turns
        a silent wrong answer into a visible correction.
        """
        warnings: list[str] = []
        cleaned: list[str] = []
        for original in self.domains:
            host = str(original).strip().lower()
            host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", host)   # scheme
            host = host.split("/")[0].split("?")[0]             # path, query
            host = host.split("@")[-1].split(":")[0]            # userinfo, port
            host = host.strip(".")
            if host.startswith("www."):
                host = host[4:]          # crt.sh's %.domain already covers www
            if not host or "." not in host:
                warnings.append(f"{original!r} is not a usable domain: dropped")
                continue
            if host != str(original).strip().lower():
                warnings.append(f"{original!r} -> {host!r}")
            if host not in cleaned:
                cleaned.append(host)
            elif host == original:
                warnings.append(f"{original!r} appears more than once: deduplicated")
        self.domains = cleaned
        return warnings

    @property
    def slug(self) -> str:
        return "".join(c if c.isalnum() else "-" for c in self.legal_name.lower()).strip("-")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Target:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass(slots=True)
class Raw:
    """Deterministic extraction from one tool response. No interpretation."""

    source: Source
    kind: str
    subject: str
    payload: dict[str, Any]
    retrieved_at: str = field(default_factory=utcnow)
    evidence_ref: str | None = None  # sha256 of the cached HTTP response

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        return d


@dataclass(slots=True)
class Finding:
    """Table 6.1. One interpreted signal, bound to at most one primary driver."""

    source: Source
    type: str
    subject: str
    evidence: dict[str, Any]
    signal_strength: SignalStrength
    driver_hint: str                      # driver id in config/drivers.yaml
    needs_followup: FollowUp
    pillar: Pillar
    controls: list[str] = field(default_factory=list)   # FNCDP / NIST refs
    observed_at: str = field(default_factory=utcnow)
    evidence_refs: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    note: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.signal_strength, str):
            self.signal_strength = SignalStrength(self.signal_strength)
        if not self.driver_hint:
            raise ValueError(
                f"finding {self.type!r} has no driver_hint: every risk finding must "
                "bear on a weighted driver (selection criterion 1)"
            )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["signal_strength"] = self.signal_strength.value
        d["needs_followup"] = self.needs_followup.value
        d["pillar"] = self.pillar.value
        return d

    @property
    def fingerprint(self) -> str:
        """Stable identity for de-duplication across runs."""
        key = f"{self.source.value}|{self.type}|{self.subject}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass(slots=True)
class DriverVerdict:
    """What the CTI layer proposes for one cell of the Phase 1 matrix."""

    driver_id: str
    driver_name: str
    weight: float | None
    verdict: Verdict
    max_strength: SignalStrength | None
    findings: list[Finding] = field(default_factory=list)
    rationale: str = ""
    corroborating_pillars: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "driver_id": self.driver_id,
            "driver_name": self.driver_name,
            "weight": self.weight,
            "verdict": self.verdict.value,
            "max_strength": self.max_strength.value if self.max_strength else None,
            "rationale": self.rationale,
            "corroborating_pillars": self.corroborating_pillars,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class RunStats:
    """Per-run counters. This is the raw material of the thesis statistics and
    of the screenshots, so every collector is expected to update it."""

    run_id: str
    target: str
    started_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    counters: dict[str, int] = field(default_factory=dict)
    timings_ms: dict[str, int] = field(default_factory=dict)
    http: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    #: stage name -> {"status", "raws", "findings", "errors"}. Populated by the
    #: runner. Without it a run in which a collector failed is indistinguishable
    #: from a run in which it found nothing - see `integrity`.
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)

    #: Statuses a stage can end in.
    OK = "ok"                    # produced data, no errors
    EMPTY = "empty"              # answered, genuinely nothing to report
    DEGRADED = "degraded"        # produced data, but some queries failed
    FAILED = "failed"            # produced nothing AND errored: NOT a clean result
    SKIPPED_UPSTREAM = "skipped_upstream_failed"   # got no input to work on
    NOT_IMPLEMENTED = "not_implemented"

    def record_stage(self, name: str, status: str, raws: int = 0, findings: int = 0,
                     errors: int = 0) -> None:
        self.stages[name] = {"status": status, "raws": raws,
                             "findings": findings, "errors": errors}

    @property
    def integrity(self) -> str:
        """`complete`, `degraded` or `invalid`.

        This is rule R1 applied to the run itself. A collector that failed
        produces zero findings, and zero findings look exactly like a clean
        supplier in the summary line. Marking the run is what stops an aborted
        crt.sh query from being read as evidence of a small attack surface.
        `invalid` means the first stage of the technical chain failed, so
        everything downstream had nothing to work on and no conclusion about
        that pillar may be drawn at all.
        """
        statuses = {n: v["status"] for n, v in self.stages.items()}
        if statuses.get("crtsh") == self.FAILED:
            return "invalid"
        if any(v == self.FAILED for v in statuses.values()):
            return "invalid"
        if any(v == self.DEGRADED for v in statuses.values()):
            return "degraded"
        #: A request that exhausted its retries is a hole in the collection even
        #: when the stage recovered through a fallback interface and recorded no
        #: error of its own. The stage statuses above cannot see it, because the
        #: HTTP client counts the failure and the collector only reports what it
        #: could not work around. Reading `http` here is what stops a run with
        #: an unreachable endpoint from being presented as a complete one.
        if self.http.get("failures") or self.http.get("transport_errors"):
            return "degraded"
        return "complete"

    @property
    def failed_stages(self) -> list[str]:
        return sorted(n for n, v in self.stages.items()
                      if v["status"] in (self.FAILED, self.DEGRADED))

    def bump(self, key: str, n: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + n

    def timing(self, key: str, ms: int) -> None:
        self.timings_ms[key] = self.timings_ms.get(key, 0) + ms

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "integrity": self.integrity,
            "stages": self.stages,
            "counters": dict(sorted(self.counters.items())),
            "timings_ms": dict(sorted(self.timings_ms.items())),
            "http": dict(sorted(self.http.items())),
            "errors": self.errors,
        }

    def dump(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
