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
from urllib.parse import quote

from ...models import Finding, Pillar, Raw, SignalStrength, Source, Target
from ..base import BaseCollector

CRTSH = "https://crt.sh/?q={q}&output=json&exclude=expired"


class CrtShCollector(BaseCollector):
    name = "crtsh"
    pillar = Pillar.TECHNICAL

    # -- collect -----------------------------------------------------------
    def collect(self, target: Target) -> list[Raw]:
        raws: list[Raw] = []
        for domain in target.domains:
            for q in (f"%.{domain}", domain):
                url = CRTSH.format(q=quote(q, safe=""))
                try:
                    body, ev = self.client.get_json(url)
                except Exception as exc:               # noqa: BLE001 - recorded, not fatal
                    self.bump("query_errors")
                    if self.stats is not None:
                        self.stats.errors.append(f"crtsh {q}: {type(exc).__name__}: {exc}")
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
        first, so a rate-limited run still covers what matters."""
        hosts: set[str] = set()
        for raw in raws:
            for entry in raw.payload.get("entries", []):
                for host in self._hostnames(entry):
                    if host.startswith("*.") or "*" in host:
                        continue
                    if any(host == d or host.endswith("." + d) for d in target.domains):
                        hosts.add(host)
        return sorted(hosts, key=lambda h: (not self.config.sensitive_categories(h), h))
