"""Incident pillar: ransomware data-leak-site listings via ransomware.live.

The third spoke, and the only one whose subject is an *event* rather than a
property. It answers the driver's own question directly: has this supplier
suffered a security incident, public or formally communicated, in the past
twelve months?

WHY THIS PILLAR REACHES `strong` WITHOUT CHAINING

The technical pillar needs four instruments to justify a driver, because each
of its observations is a proxy: an open port is not a breach. A leak-site
listing is not a proxy. When a ransomware group publishes a victim on its own
extortion site, the fact asserted is the incident itself - and the driver text
asks for exactly that, "public or formally communicated", within a window.
One observation, one driver, provided two conditions hold: the listing matches
the supplier by *domain*, and it falls inside the window.

THE THREE THINGS THIS SOURCE CANNOT DO, ALL OF WHICH MATTER

  1. A listing is a *claim by a criminal group*, not a verified fact. Groups
     exaggerate, republish old data, and occasionally list victims they never
     breached. The finding therefore says a public extortion claim exists and
     names the group, which is verifiable, rather than asserting a breach.
  2. Absence proves nothing, and here the gap is enormous: victims who pay are
     usually never published, and incidents without extortion never appear at
     all. This is the clearest illustration in the whole project of why the
     hub emits NOT_OBSERVABLE and never NO.
  3. Victim names on leak sites are free text, frequently a trading name or a
     misspelling. Matching on name alone risks attributing another company's
     breach to this supplier, which is why a name-only match is capped at
     `moderate` and escalates to a human.

CORROBORATION

`dls_listing` is declared in mapping.yaml as the corroboration partner of
`kev_ransomware_flag`. When the technical pillar finds a KEV entry used in
ransomware campaigns on an exposed service, and this pillar independently finds
the supplier on a leak site, two pillars that never exchanged data point at the
same risk. That convergence is the argument of section 6.4, and it is computed
by the hub, not asserted here.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from ...models import Finding, Pillar, Raw, SignalStrength, Source, Target
from ..base import BaseCollector

#: Free, keyless. Verify the path against the current API documentation before
#: a live run: this project pins v2, but the service has changed its routes
#: between major versions and a 404 here is a configuration problem, not a
#: finding of "no incidents".
SEARCH = "https://api.ransomware.live/v2/searchvictims/{query}"

#: Legal-form suffixes stripped before comparing names. Not exhaustive by
#: design: the stripped form is only ever used to *raise* a candidate for
#: human review, never to conclude.
LEGAL_SUFFIXES = (
    "s p a", "spa", "s r l", "srl", "s a s", "sas", "s n c", "snc", "s c a r l",
    "ltd", "limited", "llc", "inc", "incorporated", "corp", "corporation",
    "gmbh", "ag", "sa", "sarl", "bv", "nv", "plc", "oy", "ab", "as", "aps",
    "pte", "pty", "co", "company", "group", "holding", "holdings",
)

DATE_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d/%m/%Y")


def normalise_name(name: str) -> str:
    """Lowercase, depunctuate and drop the legal form, so that
    'Acme RAN S.p.A.' and 'Acme Ran SPA' compare equal."""
    text = re.sub(r"[^a-z0-9]+", " ", (name or "").lower()).strip()
    tokens = [t for t in text.split() if t]
    while tokens and " ".join(tokens[-1:]) in LEGAL_SUFFIXES:
        tokens.pop()
    # two-word suffixes such as "s p a" survive the single-token pass
    joined = " ".join(tokens)
    for suffix in sorted(LEGAL_SUFFIXES, key=len, reverse=True):
        if joined.endswith(" " + suffix):
            joined = joined[: -len(suffix) - 1].strip()
    return joined


def registrable(host: str) -> str:
    """Last two labels of a hostname. Crude on purpose: it is used to compare
    a leak-site URL with the supplier's domains, and over-matching here would
    only ever produce a candidate a human then adjudicates."""
    host = (host or "").strip().lower()
    host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0].strip(".")
    labels = [x for x in host.split(".") if x]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text[: len(fmt) + 8], fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


class RansomwareLiveCollector(BaseCollector):
    name = "ransomware_live"
    pillar = Pillar.INCIDENT

    def __init__(self, client, config, stats=None,
                 reference_date: datetime | None = None) -> None:
        super().__init__(client, config, stats)
        #: Fixed at construction so a replayed run classifies listings against
        #: the same window as the original: "within 12 months" must not drift
        #: with the clock, or the evidence stops being reproducible.
        self.reference_date = reference_date or datetime.now(UTC)

    # -- collect -----------------------------------------------------------
    def collect(self, target: Target) -> list[Raw]:
        queries: list[str] = []
        for domain in target.domains:
            queries.append(registrable(domain))
        queries.append(normalise_name(target.legal_name))
        queries += [normalise_name(a) for a in target.aliases]

        raws: list[Raw] = []
        for query in dict.fromkeys(q for q in queries if q):     # dedup, keep order
            try:
                body, ev = self.client.get_json(SEARCH.format(query=query))
            except Exception as exc:                 # noqa: BLE001 - recorded, not fatal
                self.bump("query_errors")
                if self.stats is not None:
                    self.stats.errors.append(
                        f"ransomware.live {query}: {type(exc).__name__}: {exc}")
                continue
            self.bump("queries")
            victims = body if isinstance(body, list) else (body or {}).get("victims", []) or []
            raws.append(Raw(source=Source.RANSOMWARE_LIVE, kind="victim_search",
                            subject=query,
                            payload={"query": query, "victims": victims},
                            evidence_ref=ev.sha256))
        return raws

    # -- analyze (pure) ----------------------------------------------------
    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]:
        window = int(self.config.threshold("dls_window_days"))
        domains = {registrable(d) for d in target.domains}
        names = {normalise_name(target.legal_name)} | {normalise_name(a) for a in target.aliases}
        names.discard("")

        seen: set[str] = set()
        findings: list[Finding] = []
        refs = [r.evidence_ref for r in raws if r.evidence_ref]

        for raw in raws:
            for victim in raw.payload.get("victims", []) or []:
                if not isinstance(victim, dict):
                    continue

                victim_name = str(victim.get("victim") or victim.get("post_title") or "")
                victim_domain = registrable(str(victim.get("domain")
                                                or victim.get("website") or ""))
                group = str(victim.get("group") or victim.get("group_name") or "unknown")
                published = parse_date(victim.get("published")
                                       or victim.get("discovered")
                                       or victim.get("attackdate"))

                domain_match = bool(victim_domain) and victim_domain in domains
                name_match = normalise_name(victim_name) in names
                if not (domain_match or name_match):
                    continue

                fingerprint = f"{group}|{victim_domain or victim_name}|{published}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                age_days = ((self.reference_date - published).days
                            if published else None)
                in_window = age_days is not None and age_days <= window

                evidence = {
                    "group": group,
                    "victim_name": victim_name,
                    "victim_domain": victim_domain or None,
                    "published": published.date().isoformat() if published else None,
                    "age_days": age_days,
                    "window_days": window,
                    "matched_on": "domain" if domain_match else "name",
                    "claim_url": victim.get("claim_url") or victim.get("post_url"),
                    "declared_breach_12m": target.declared_breach_12m,
                    "limitation": (
                        "a leak-site listing is a public extortion claim by a criminal "
                        "group, not a verified incident; and absence from leak sites is "
                        "not evidence that no incident occurred, since victims who pay "
                        "are generally never published"
                    ),
                }

                if domain_match and in_window:
                    self.bump("listings_in_window")
                    findings.append(self.config.make_finding(
                        type="dls_listing", source=Source.RANSOMWARE_LIVE,
                        subject=f"{victim_name or victim_domain} / {group}",
                        evidence=evidence, strength=SignalStrength.STRONG,
                        evidence_refs=refs,
                        note=("contradicts the supplier's declaration of no incident "
                              "in the past 12 months"
                              if target.declared_breach_12m is False else
                              "public extortion claim within the driver's 12-month window"),
                    ))
                elif domain_match:
                    self.bump("listings_stale")
                    findings.append(self.config.make_finding(
                        type="dls_listing_stale", source=Source.RANSOMWARE_LIVE,
                        subject=f"{victim_name or victim_domain} / {group}",
                        evidence=evidence, strength=SignalStrength.WEAK,
                        evidence_refs=refs,
                        note="outside the 12-month window of the driver: history, "
                             "relevant to the file but not to this answer",
                    ))
                else:
                    self.bump("listings_name_only")
                    findings.append(self.config.make_finding(
                        type="dls_listing_name_only", source=Source.RANSOMWARE_LIVE,
                        subject=f"{victim_name} / {group}",
                        evidence=evidence, strength=SignalStrength.MODERATE,
                        evidence_refs=refs,
                        note="victim name matches but no domain in the listing confirms "
                             "it: homonym risk, human confirmation required",
                    ))

        return findings
