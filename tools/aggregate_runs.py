#!/usr/bin/env python3
"""Aggregate the run directories under `out/` into the tables of the evaluation
chapter.

Read-only by construction: it opens `stats.json`, `verdicts.json` and
`findings.json` and writes Markdown. It never touches the evidence store and
never re-derives a finding, so running it cannot change a result - which is the
property that lets the numbers in the thesis be recomputed from the same run
directories at any later date.

Six tables, each answering one question a reader will ask:

    1. inventory     did the collection succeed, and is the run readable at all?
    2. funnel        why is the technical pillar a chain and not a flat list?
    3. yield         which pillar produces signal, and at what strength?
    4. verdicts      does the layer discriminate, or does it fire on everything?
    5. projection    does the layer change the Phase 1 outcome?
    6. cost          is "zero budget, two minutes" true?

The honest claim these tables support is *discrimination*, not accuracy. There
is no ground truth for "this supplier has vulnerability-management deficiencies",
so nothing here should be presented as precision or recall. What can be shown is
that the positive controls fire, the negative controls stay quiet, and a failed
collection is never reported as a clean supplier.

Usage
-----
    python tools/aggregate_runs.py                       # all runs in out/
    python tools/aggregate_runs.py -o docs/evaluation.md
    python tools/aggregate_runs.py --roles config/controls.yaml --pseudonymise
    python tools/aggregate_runs.py --only 1 2 6          # just those tables

`--roles` takes a YAML mapping run directory name (or target legal name) to a
control role, so the tables can be grouped the way the chapter argues:

    acme-ran-s-p-a-DEMO: negative
    rosneft-01:          positive_corporate
    victim-01:           positive_incident
    nonexistent-01:      null_control

`--pseudonymise` replaces legal names with Supplier A, B, C... in the output and
prints the mapping to stderr only, so the mapping never lands in the thesis by
copy-paste accident.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import string
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

#: Counter -> column heading for the technical chain, in stage order.
#:
#: The counts are NOT monotonically decreasing, and the table must not be
#: presented as if they were. Two effects break it. `hosts_observed` and
#: `hosts_for_dns` count different populations: the first is the set of names
#: seen in certificates, the second the set actually handed to the resolver,
#: which expands wildcards and adds the apex domains. And one name resolves to
#: many addresses behind a CDN, so unique IPs routinely exceed resolved hosts.
#: What narrows along the chain is relevance, not cardinality.
FUNNEL = [
    ("crtsh.hosts_observed", "CT names"),
    ("crtsh.hosts_for_dns", "to resolver"),
    ("dns.hosts_resolved", "resolved"),
    ("dns.unique_ips", "unique IPs"),
    ("shodan.addresses_with_data", "in Shodan"),
    ("shodan.open_ports_observed", "open ports"),
    ("shodan.candidate_cves", "candidate CVEs"),
    ("vulns.kev_hits", "in KEV"),
    ("vulns.kev_ransomware_flagged", "KEV+ransomware"),
]

#: Counter -> column heading for the two independent pillars.
INDEPENDENT = [
    ("opensanctions.candidates", "OS candidates"),
    ("opensanctions.sanction_candidates", "sanction"),
    ("opensanctions.extra_eu_owners", "extra-EEA owners"),
    ("ransomware_live.listings_in_window", "DLS <12m"),
    ("ransomware_live.listings_stale", "DLS stale"),
]

STRENGTHS = ["strong", "moderate", "weak", "info"]
PILLARS = ["technical", "corporate", "incident"]

VERDICT_MARK = {"SUGGEST_YES": "**Y**", "REVIEW": "R", "NOT_OBSERVABLE": "-"}


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #
class Run:
    """One run directory, loaded lazily and tolerant of missing files.

    Older run directories may lack keys added later (the projection's
    `contradicted_drivers`, for instance). Missing data becomes an empty
    default rather than a crash: a partial run is still evidence, and refusing
    to tabulate it would be the aggregator making the same mistake the run
    integrity rule exists to prevent.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.unreadable: list[str] = []
        self.stats = self._load("stats.json", {})
        self.verdicts = self._load("verdicts.json", {})
        self.findings = self._load("findings.json", [])
        self.label = self.stats.get("target") or path.name

    def _load(self, name: str, default: Any) -> Any:
        """Missing or malformed files are recorded, never silently defaulted.

        An unreadable `findings.json` would otherwise reach the inventory as a
        run with zero findings, which is the same misreading the run integrity
        rule exists to prevent: nothing observed and nothing readable look
        identical once both are printed as 0.
        """
        p = self.path / name
        if not p.is_file():
            self.unreadable.append(f"{name} missing")
            print(f"[warn] {p}: file not found", file=sys.stderr)
            return default
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.unreadable.append(f"{name} unreadable")
            print(f"[warn] {p}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return default

    # -- accessors ---------------------------------------------------------
    @property
    def run_id(self) -> str:
        return self.stats.get("run_id", self.path.name)

    @property
    def integrity(self) -> str:
        return self.stats.get("integrity", "unknown")

    def counter(self, key: str) -> int | None:
        return self.stats.get("counters", {}).get(key)

    @property
    def projection(self) -> dict[str, Any]:
        return self.verdicts.get("projection", {}) or {}

    @property
    def wall_ms(self) -> int:
        """Sum of the per-pillar timings: the wall time of the collection."""
        timings = self.stats.get("timings_ms", {}) or {}
        return sum(v for k, v in timings.items() if k.startswith("pillar:"))

    @property
    def failed_stages(self) -> list[str]:
        stages = self.stats.get("stages", {}) or {}
        return sorted(n for n, v in stages.items()
                      if v.get("status") in ("failed", "degraded"))

    @property
    def findings_digest(self) -> str:
        """SHA-256 over the findings, with the volatile fields removed.

        `id` is a fresh uuid and `observed_at` is a timestamp, so both differ
        between a live run and its replay by design. Everything else must not.
        Comparing this digest between an online run and the same run replayed
        with `--offline` is the reproducibility claim, checkable rather than
        asserted.
        """
        if not self.findings:
            return "-"
        skel = [
            {k: v for k, v in f.items() if k not in ("id", "observed_at")}
            for f in self.findings
        ]
        skel.sort(key=lambda f: (f.get("type", ""), str(f.get("subject", ""))))
        blob = json.dumps(skel, sort_keys=True, ensure_ascii=False).encode()
        return hashlib.sha256(blob).hexdigest()[:12]


def discover(runs_dir: Path) -> list[Run]:
    dirs = [p for p in sorted(runs_dir.iterdir())
            if p.is_dir() and (p / "stats.json").is_file()]
    return [Run(p) for p in dirs]


def apply_roles(runs: list[Run], roles: dict[str, str]) -> None:
    for r in runs:
        r.role = roles.get(r.path.name) or roles.get(r.label) or roles.get(r.run_id) or ""


def pseudonymise(runs: list[Run]) -> dict[str, str]:
    """Stable Supplier A/B/C... mapping, printed to stderr only."""
    names = sorted({r.label for r in runs})
    mapping = {n: f"Supplier {string.ascii_uppercase[i]}" for i, n in enumerate(names)}
    for r in runs:
        r.label = mapping[r.label]
    return mapping


# --------------------------------------------------------------------------- #
# markdown helpers
# --------------------------------------------------------------------------- #
def table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_no data_\n"
    cells = [[("-" if c is None else str(c)) for c in row] for row in rows]
    width = [max(len(h), *(len(r[i]) for r in cells)) for i, h in enumerate(headers)]
    out = ["| " + " | ".join(h.ljust(width[i]) for i, h in enumerate(headers)) + " |",
           "|" + "|".join("-" * (w + 2) for w in width) + "|"]
    out += ["| " + " | ".join(c.ljust(width[i]) for i, c in enumerate(row)) + " |"
            for row in cells]
    return "\n".join(out) + "\n"


def pct(x: float | None) -> str:
    return "-" if x is None else f"{x * 100:.0f}%"


def role_col(runs: list[Run]) -> bool:
    return any(getattr(r, "role", "") for r in runs)


# --------------------------------------------------------------------------- #
# the six tables
# --------------------------------------------------------------------------- #
def t_inventory(runs: list[Run]) -> str:
    show_role = role_col(runs)
    headers = ["Target", "Run", *(["Control"] if show_role else []),
               "Integrity", "Failed/partial", "Findings", "Y", "R", "Digest"]
    rows = []
    for r in runs:
        counts = (r.verdicts.get("counts") or {})
        broken = "findings.json" in " ".join(r.unreadable)
        rows.append([
            r.label, r.run_id,
            *([getattr(r, "role", "") or "-"] if show_role else []),
            r.integrity,
            ", ".join(r.failed_stages) or "-",
            "n/a" if broken else len(r.findings),
            counts.get("suggest_yes"),
            counts.get("review"),
            r.findings_digest,
        ])
    unreadable = [f"`{r.path.name}`: {', '.join(r.unreadable)}"
                  for r in runs if r.unreadable]
    warning = ("\n> **Incomplete input.** " + "; ".join(unreadable) +
               ". Rows marked `n/a` could not be read and say nothing about the "
               "target.\n") if unreadable else ""
    return ("### 1. Run inventory and integrity\n\n"
            "`Digest` is a SHA-256 prefix over the findings with `id` and "
            "`observed_at` removed: it is identical for a run and its offline "
            "replay, and that identity is the reproducibility claim.\n\n"
            + table(headers, rows) + warning)


def t_funnel(runs: list[Run]) -> str:
    headers = ["Target", *[h for _, h in FUNNEL]]
    rows = [[r.label, *[r.counter(k) for k, _ in FUNNEL]] for r in runs]
    return ("### 2. Technical pillar: stage by stage\n\n"
            "Stage order, left to right. The counts do not decrease "
            "monotonically: one name resolves to several addresses behind a "
            "CDN, and the resolver receives the wildcard expansions and apex "
            "domains on top of the names observed in certificates. What "
            "narrows along the chain is relevance, since nothing downstream is "
            "meaningful without its upstream anchor.\n\n"
            + table(headers, rows)
            + "\n"
            + table(["Target", *[h for _, h in INDEPENDENT]],
                    [[r.label, *[r.counter(k) for k, _ in INDEPENDENT]] for r in runs]))


def t_yield(runs: list[Run]) -> str:
    headers = ["Target", "Pillar", *STRENGTHS, "Total"]
    rows: list[list[Any]] = []
    for r in runs:
        for pillar in PILLARS:
            fs = [f for f in r.findings if f.get("pillar") == pillar]
            if not fs:
                continue
            by = [len([f for f in fs if f.get("signal_strength") == s]) for s in STRENGTHS]
            rows.append([r.label, pillar, *by, len(fs)])
    return ("### 3. Yield by pillar and signal strength\n\n"
            "R2 caps strength per finding type, so `strong` in the technical "
            "column can only come from the end of the chain, and in the "
            "corporate column only from an identifier match.\n\n"
            + table(headers, rows))


def t_verdicts(runs: list[Run]) -> str:
    """Driver x target matrix. The discrimination table: the one that shows the
    layer is not simply answering YES everywhere."""
    order: list[tuple[str, float | None, str]] = []
    seen: set[str] = set()
    for r in runs:
        for v in r.verdicts.get("verdicts", []) or []:
            if v["driver_id"] not in seen:
                seen.add(v["driver_id"])
                order.append((v["driver_id"], v.get("weight"), v.get("driver_name", "")))

    headers = ["Driver", "Weight", *[r.label for r in runs]]
    rows: list[list[Any]] = []
    for driver_id, weight, _name in order:
        marks = []
        for r in runs:
            v = next((x for x in (r.verdicts.get("verdicts") or [])
                      if x["driver_id"] == driver_id), None)
            marks.append(VERDICT_MARK.get((v or {}).get("verdict", ""), "?"))
        if set(marks) == {"-"}:
            continue                      # never observable in any run: no information
        rows.append([driver_id, pct(weight), *marks])
    return ("### 4. Verdicts per driver (Y = SUGGEST_YES, R = REVIEW, - = NOT_OBSERVABLE)\n\n"
            "Drivers that are `NOT_OBSERVABLE` in every run are omitted: they "
            "are the non-observable drivers by design, and `grestin coverage` "
            "is the place that argument belongs.\n\n"
            + table(headers, rows))


def t_projection(runs: list[Run]) -> str:
    headers = ["Target", "Declared", "Level", "Projected", "Level", "Delta",
               "Crosses Phase 2", "Contradicted", "Unanswered"]
    rows = []
    for r in runs:
        p = r.projection
        if not p:
            continue
        rows.append([
            r.label,
            pct(p.get("declared_score")), p.get("declared_level", "-"),
            pct(p.get("projected_score")), p.get("projected_level", "-"),
            pct(p.get("delta")),
            "yes" if p.get("crosses_phase2_threshold") else "no",
            ", ".join(p.get("contradicted_drivers") or []) or "-",
            ", ".join(p.get("unanswered_drivers") or []) or "-",
        ])
    return ("### 5. Declared versus projected inherent risk\n\n"
            "`Contradicted` lists the drivers the compiler answered NO on and "
            "the layer found evidence against; `Unanswered` the ones left "
            "blank. Both move the projection by the same weight, but only the "
            "first is a question to put to the supplier.\n\n"
            + table(headers, rows))


def t_cost(runs: list[Run]) -> str:
    headers = ["Target", "HTTP requests", "Cache hits", "HTTP failures",
               "Recorded errors", "Collection (s)", "Slowest stage"]
    rows = []
    for r in runs:
        http = r.stats.get("http", {}) or {}
        timings = {k.removeprefix("pillar:"): v
                   for k, v in (r.stats.get("timings_ms") or {}).items()
                   if k.startswith("pillar:")}
        slowest = max(timings.items(), key=lambda kv: kv[1], default=("-", 0))
        rows.append([
            r.label,
            http.get("requests", 0),
            http.get("cache_hits", 0),
            http.get("failures", 0) + http.get("transport_errors", 0),
            len(r.stats.get("errors", []) or []),
            f"{r.wall_ms / 1000:.1f}",
            f"{slowest[0]} ({slowest[1] / 1000:.1f}s)" if slowest[1] else "-",
        ])
    return ("### 6. Cost per run\n\n"
            "Free tiers only, no active scanning, no paid data. The collection "
            "time is the sum of the per-pillar timings.\n\n"
            + table(headers, rows))


TABLES = {1: t_inventory, 2: t_funnel, 3: t_yield, 4: t_verdicts,
          5: t_projection, 6: t_cost}


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs-dir", default=str(ROOT / "out"),
                    help="directory holding the run directories (default: out/)")
    ap.add_argument("-o", "--output", help="write Markdown here instead of stdout")
    ap.add_argument("--roles", help="YAML mapping run dir / target -> control role")
    ap.add_argument("--pseudonymise", action="store_true",
                    help="replace legal names with Supplier A, B, C... (mapping to stderr)")
    ap.add_argument("--only", nargs="+", type=int, choices=sorted(TABLES),
                    help="emit only these tables")
    args = ap.parse_args(argv)

    runs_dir = Path(args.runs_dir)
    if not runs_dir.is_dir():
        print(f"[error] no such directory: {runs_dir}", file=sys.stderr)
        return 2
    runs = discover(runs_dir)
    if not runs:
        print(f"[error] no run directories with a stats.json under {runs_dir}",
              file=sys.stderr)
        return 2

    roles: dict[str, str] = {}
    if args.roles:
        import yaml  # already a dependency; imported only when --roles is used
        roles = yaml.safe_load(Path(args.roles).read_text(encoding="utf-8")) or {}
    apply_roles(runs, roles)

    if args.pseudonymise:
        mapping = pseudonymise(runs)
        print("[pseudonyms - not written to the output file]", file=sys.stderr)
        for real, alias in mapping.items():
            print(f"  {alias} = {real}", file=sys.stderr)

    # Group by control role when known, so the chapter's own structure survives
    # into the tables; otherwise keep discovery order.
    if role_col(runs):
        order = ["positive_technical", "positive_corporate", "positive_incident",
                 "negative", "null_control"]
        runs.sort(key=lambda r: (order.index(getattr(r, "role", ""))
                                if getattr(r, "role", "") in order else len(order),
                                r.label))

    wanted = args.only or sorted(TABLES)
    parts = ["## Evaluation tables",
             f"\n_{len(runs)} run(s) from `{runs_dir}`. "
             "Generated by `tools/aggregate_runs.py`; every number is "
             "recomputable from the run directories._\n"]
    parts += [TABLES[n](runs) for n in wanted]
    md = "\n".join(parts)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"written: {out}", file=sys.stderr)
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
