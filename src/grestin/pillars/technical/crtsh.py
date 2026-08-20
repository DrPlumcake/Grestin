"""Stage 1 of the technical chain: certificate transparency via crt.sh.

What it observes: every hostname for which a publicly logged certificate has
been issued under the supplier's domains. This is the anchor of the pillar -
nothing downstream (DNS, Shodan, NVD/KEV) has a subject without it.

What it cannot observe, and the thesis should say so:
  * hosts that never had a publicly logged certificate (plain HTTP, internal
    PKI, or pre-CT issuance);
  * whether a hostname still exists: CT is append-only, so it is a history of
    issuance, not an inventory of live assets. Hence `subdomain_observed`
    is `info` and only DNS resolution promotes it.

Operational notes, learned the hard way and worth a line in Chapter 6:
  * crt.sh answers with HTTP 502/504 under load; the retry policy in
    PassiveClient handles it, and a run that fails here fails cleanly rather
    than silently producing an empty surface.
  * `?q=%.example.com` returns subdomains; `?q=example.com` returns only the
    apex. Both are issued, and the union is de-duplicated.
  * wildcard entries (`*.example.com`) are recorded but never passed
    downstream as resolvable hosts.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from urllib.parse import quote

from ...models import Finding, Pillar, Raw, SignalStrength, Source, Target
from ..base import BaseCollector

#: Two forms of the same query. crt.sh answers from a large PostgreSQL
#: instance and times out under load; `exclude=expired` makes the query
#: markedly more expensive server-side, so when the cheap-to-ask form fails we
#: retry without it and filter expired certificates ourselves. This turns a
#: substantial share of the 502s into successful runs, which matters because a
#: failed stage 1 invalidates the whole technical pillar.
CRTSH = "https://crt.sh/?q={q}&output=json&exclude=expired"
CRTSH_FALLBACK = "https://crt.sh/?q={q}&output=json"

#: Second interface onto the *same* Certificate Transparency logs, not a sixth
#: instrument. crt.sh is a single point of failure for the whole technical
#: pillar - when it times out, stage 1 produces nothing and stages 2 to 4 have
#: no subject. Cert Spotter reads the same public logs through a different
#: operator, so falling back to it changes the interface and not the evidence.
#: It is heavily rate limited without a key, hence last resort only.
#: Worth one sentence in Chapter 6: the reproducibility of an OSINT method
#: depends on the availability of the interface, not only of the data.
CERTSPOTTER = ("https://api.certspotter.com/v1/issuances"
               "?domain={domain}&include_subdomains=true"
               "&expand=dns_names&expand=issuer")


class CrtShCollector(BaseCollector):
    name = "crtsh"
    pillar = Pillar.TECHNICAL

    #: Certificates expired before this date are dropped in `analyze`, so the
    #: filtered and unfiltered queries yield the same inventory.
    horizon: str = ""

    def __init__(self, client, config, stats=None, horizon: str | None = None) -> None:
        super().__init__(client, config, stats)
        self.horizon = horizon or datetime.now(UTC).date().isoformat()

    @staticmethod
    def _from_certspotter(issuances: list[dict]) -> list[dict]:
        """Adapt Cert Spotter's shape to crt.sh's, so `analyze` is untouched."""
        entries = []
        for item in issuances or []:
            names = item.get("dns_names") or []
            issuer = (item.get("issuer") or {}).get("name", "")
            entries.append({
                "common_name": names[0] if names else "",
                "name_value": "\n".join(names),
                "issuer_name": issuer,
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
            })
        return entries

    # -- collect -----------------------------------------------------------
    def collect(self, target: Target) -> list[Raw]:
        raws: list[Raw] = []
        for domain in target.domains:
            #: Cert Spotter is queried with include_subdomains, so once it has
            #: answered for this domain it already covers the apex. A later
            #: failure of the apex query then costs no observation, and
            #: recording it as an error would mark the stage degraded over data
            #: the run actually holds.
            covered_by_certspotter = False
            for q in (f"%.{domain}", domain):
                encoded = quote(q, safe="")
                body = ev = None
                for attempt, template in enumerate((CRTSH, CRTSH_FALLBACK)):
                    try:
                        body, ev = self.client.get_json(template.format(q=encoded))
                        if attempt:
                            self.bump("fallback_queries")
                        break
                    except Exception as exc:           # noqa: BLE001 - recorded, not fatal
                        last = exc
                if ev is None and q.startswith("%."):
                    # crt.sh is down for this query: read the same logs through
                    # the other interface rather than losing the whole pillar.
                    try:
                        issuances, ev = self.client.get_json(
                            CERTSPOTTER.format(domain=domain))
                        body = self._from_certspotter(issuances)
                        self.bump("certspotter_fallback")
                        covered_by_certspotter = True
                        # A recovered query is not an error. crt.sh answers 502
                        # under load often enough that treating every successful
                        # fallback as a fault would leave every run degraded,
                        # and an integrity flag that is always raised carries no
                        # information. The counter records which interface was
                        # used; the run stays clean because no observation was
                        # lost.
                    except Exception as exc:           # noqa: BLE001
                        last = exc
                if ev is None:
                    self.bump("query_errors")
                    if covered_by_certspotter:
                        # The apex names are inside the Cert Spotter answer
                        # already obtained for this domain.
                        self.bump("queries_covered_by_fallback")
                        continue
                    if self.stats is not None:
                        self.stats.errors.append(
                            f"crtsh {q}: {type(last).__name__}: {last} "
                            "(filtered, unfiltered and Cert Spotter all failed)")
                    continue
                self.bump("queries")
                raws.append(Raw(
                    source=Source.CRTSH,
                    kind="certificate_entries",
                    subject=domain,
                    payload={"query": q, "entries": body if isinstance(body, list) else []},
                    evidence_ref=ev.sha256,
                ))
        return raws

    # -- analyze (pure) ----------------------------------------------------
    @staticmethod
    def _hostnames(entry: dict) -> set[str]:
        """A CT entry carries common_name plus a newline-separated SAN list."""
        names: set[str] = set()
        for field_name in ("common_name", "name_value"):
            raw = entry.get(field_name) or ""
            for line in str(raw).splitlines():
                h = line.strip().lower().rstrip(".")
                if h and " " not in h and h != "-":
                    names.add(h)
        return names

    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]:
        hosts: dict[str, dict] = {}
        wildcards: set[str] = set()
        refs: list[str] = []
        issuers: dict[str, int] = {}

        for raw in raws:
            if raw.evidence_ref:
                refs.append(raw.evidence_ref)
            for entry in raw.payload.get("entries", []):
                # the fallback query does not filter server-side
                if entry.get("not_after") and str(entry["not_after"]) < self.horizon:
                    self.bump("expired_entries_filtered")
                    continue
                issuer = str(entry.get("issuer_name", ""))[:120]
                issuers[issuer] = issuers.get(issuer, 0) + 1
                for host in self._hostnames(entry):
                    if not any(host == d or host.endswith("." + d) for d in target.domains):
                        continue                      # out-of-scope SAN, e.g. shared cert
                    if host.startswith("*."):
                        wildcards.add(host)
                        continue
                    rec = hosts.setdefault(host, {"certs": 0, "first_seen": None, "last_seen": None})
                    rec["certs"] += 1
                    for key, ent_key in (("first_seen", "not_before"), ("last_seen", "not_after")):
                        val = entry.get(ent_key)
                        if val and (rec[key] is None or
                                    (val < rec[key] if key == "first_seen" else val > rec[key])):
                            rec[key] = val

        self.bump("hosts_observed", len(hosts))
        self.bump("wildcards_observed", len(wildcards))

        findings: list[Finding] = []

        # 1. the inventory itself: one aggregate finding, not one per host
        #    (a hundred `info` findings would drown the report).
        if hosts:
            findings.append(self.config.make_finding(
                type="subdomain_observed",
                source=Source.CRTSH,
                subject=", ".join(target.domains),
                evidence={
                    "hosts_observed": len(hosts),
                    "wildcards_observed": sorted(wildcards),
                    "sample": sorted(hosts)[:15],
                    "top_issuers": sorted(issuers.items(), key=lambda kv: -kv[1])[:3],
                    "queries": [r.payload["query"] for r in raws],
                },
                strength=SignalStrength.INFO,
                evidence_refs=refs,
                note="asset inventory anchor; feeds DNS resolution (stage 2)",
            ))

        # 2. hostnames whose name alone discloses a management / non-prod surface
        flagged: dict[str, list[str]] = {}
        for host in sorted(hosts):
            cats = self.config.sensitive_categories(host)
            if cats:
                flagged[host] = cats
        if flagged:
            self.bump("sensitive_hosts", len(flagged))
            by_category: dict[str, list[str]] = {}
            for host, cats in flagged.items():
                for c in cats:
                    by_category.setdefault(c, []).append(host)
            findings.append(self.config.make_finding(
                type="sensitive_hostname_observed",
                source=Source.CRTSH,
                subject=", ".join(target.domains),
                evidence={
                    "count": len(flagged),
                    "by_category": {k: sorted(v) for k, v in sorted(by_category.items())},
                    "hosts": {h: hosts[h] | {"categories": c} for h, c in sorted(flagged.items())},
                },
                strength=SignalStrength.WEAK,
                evidence_refs=refs,
                note="naming evidence only; exposure is unconfirmed until DNS + Shodan",
            ))

        # 3. dissonance with the self-declaration, if the supplier declared an estate
        if target.declared_hosts:
            ratio = len(hosts) / max(target.declared_hosts, 1)
            if ratio >= float(self.config.threshold("crtsh_surface_anomaly_ratio")):
                findings.append(self.config.make_finding(
                    type="surface_scale_anomaly",
                    source=Source.CRTSH,
                    subject=", ".join(target.domains),
                    evidence={
                        "declared_hosts": target.declared_hosts,
                        "observed_hosts": len(hosts),
                        "ratio": round(ratio, 2),
                        "threshold": self.config.threshold("crtsh_surface_anomaly_ratio"),
                    },
                    strength=SignalStrength.WEAK,
                    evidence_refs=refs,
                    note="observed surface materially larger than declared",
                ))

        return findings

    # -- handoff to stage 2 ------------------------------------------------
    def resolvable_hosts(self, raws: Sequence[Raw], target: Target) -> list[str]:
        """Deduplicated, wildcard-free host list for dns.py. Sensitive hosts
        first, so a rate-limited run still covers what matters.

        The expiry horizon applied in `analyze` is applied here too. Certificate
        Transparency is append-only, so the unfiltered query returns the whole
        issuance history of a domain: without the filter this method handed the
        resolver names drawn from certificates that expired years ago, which is
        why the two counters could diverge by an order of magnitude and why the
        stage spent minutes resolving hosts that no longer exist. Both counts
        now describe the same population.
        """
        hosts: set[str] = set()
        for raw in raws:
            for entry in raw.payload.get("entries", []):
                if entry.get("not_after") and str(entry["not_after"]) < self.horizon:
                    continue
                for host in self._hostnames(entry):
                    if host.startswith("*.") or "*" in host:
                        continue
                    if any(host == d or host.endswith("." + d) for d in target.domains):
                        hosts.add(host)
        return sorted(hosts, key=lambda h: (not self.config.sensitive_categories(h), h))
