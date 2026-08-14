"""The one interface every tool implements.

Two methods, deliberately separated:

    collect(target)  -> list[Raw]        touches the network (via PassiveClient)
    analyze(raws)    -> list[Finding]    pure function, no I/O

That split is what makes `--offline` work and what makes the interpretation
layer testable: `analyze` on a stored fixture must always yield the same
findings, so a reviewer can re-derive every statement in the report.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from ..config import Config
from ..models import Finding, Pillar, Raw, RunStats, Target


class Collector(Protocol):
    name: str
    pillar: Pillar

    def collect(self, target: Target) -> list[Raw]: ...

    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]: ...


class BaseCollector:
    """Shared plumbing: config, client, stats. Subclasses implement the two methods."""

    name: str = "base"
    pillar: Pillar = Pillar.TECHNICAL

    #: Handoff from the previous stage of the technical chain. The runner sets
    #: it before calling `run()`; stage 1 ignores it, stage 2 receives the
    #: hostnames from crt.sh, stage 3 the addresses from DNS. Keeping it a
    #: plain attribute rather than a `collect()` argument means every collector
    #: keeps the same two-method interface, chained or independent. It is a
    #: list of identifiers for stages 2 and 3 and a mapping for stage 4, which
    #: needs each CVE's observation context to write a usable finding.
    inputs: list | dict = []

    def __init__(self, client, config: Config, stats: RunStats | None = None) -> None:
        self.client = client
        self.config = config
        self.stats = stats
        self.inputs = []

    # convenience ---------------------------------------------------------
    def bump(self, key: str, n: int = 1) -> None:
        if self.stats is not None:
            self.stats.bump(f"{self.name}.{key}", n)

    def finding(self, **kwargs) -> Finding:
        """Build a Finding with the strength ceiling and driver taken from
        config/mapping.yaml, so a collector cannot over-claim confidence."""
        return self.config.make_finding(source_default=self.pillar, **kwargs)

    def run(self, target: Target) -> tuple[list[Raw], list[Finding]]:
        raws = self.collect(target)
        self.bump("raws", len(raws))
        findings = self.analyze(raws, target)
        self.bump("findings", len(findings))
        return raws, findings

    # to be overridden ----------------------------------------------------
    def collect(self, target: Target) -> list[Raw]:  # pragma: no cover
        raise NotImplementedError

    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError
