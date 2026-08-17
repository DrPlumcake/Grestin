"""Stage 3 of the technical chain: Shodan host lookup.

Turns the *addresses* DNS resolved into *services*: which ports answer, what
software announces itself there, and which CVEs the banner is consistent with.
It is the stage that converts a name into a piece of attack surface.

PASSIVITY, RESTATED FOR THIS STAGE

Shodan holds two very different things behind one domain name, and the
distinction is the whole reason `http.assert_passive()` matches on URL
prefixes rather than on hosts:

    https://api.shodan.io/shodan/host/{ip}   READ of a scan Shodan already did
    https://api.shodan.io/shodan/scan        ORDER Shodan to scan that ip now

The first is a database query: the packets that reached the supplier were
Shodan's, weeks ago, as part of its indiscriminate indexing of the whole
address space. The second would make Shodan probe the supplier on our behalf,
which is active reconnaissance by proxy. The second is in `http.DENIED` and
raises before a socket opens.

TWO ENDPOINTS, DELIBERATELY

  * `internetdb.shodan.io/{ip}` is free, keyless and rate-friendly. It returns
    ports, CPEs, hostnames, tags and candidate CVEs. Every run uses it, so the
    pipeline is reproducible by a reviewer who has no Shodan account - which
    matters for a thesis.
  * `api.shodan.io/shodan/host/{ip}` needs a key and adds the geolocation and
    the product/version detail. Geolocation is the only passive input to the
    extra-EU driver, so without a key that driver simply stays unobservable
    and `stats.json` records it. Degraded, never silently wrong.

WHAT THIS STAGE MUST NOT CLAIM

A port answering is not a vulnerability, and a CPE match is not an exploit.
InternetDB's `vulns` list is inferred from banners: it says "software of this
version is associated with these CVEs", not "this host is exploitable". So the
CVE list is *handed to stage 4* rather than turned into findings here, and the
strongest thing this stage can say on its own is `moderate`, for a management
service that should not be reachable from the Internet at all.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx

from ...http import api_key
from ...models import Finding, Pillar, Raw, SignalStrength, Source, Target
from ..base import BaseCollector

INTERNETDB = "https://internetdb.shodan.io/{ip}"
HOST_LOOKUP = "https://api.shodan.io/shodan/host/{ip}?key={key}&minify=false"


class ShodanCollector(BaseCollector):
    name = "shodan"
    pillar = Pillar.TECHNICAL

    #: IP addresses handed over by the DNS stage; set by the runner
    inputs: list[str]

    def __init__(self, client, config, stats=None, max_addresses: int = 100) -> None:
        super().__init__(client, config, stats)
        self.max_addresses = max_addresses
        self.key = api_key("SHODAN_API_KEY")

    # -- collect -----------------------------------------------------------
    def _get(self, url: str) -> dict[str, Any] | None:
        """One lookup. A 404 means Shodan has nothing on that address, which is
        a result rather than a failure and must not abort the run."""
        try:
            body, ev = self.client.get_json(url)
            return {"body": body, "evidence_ref": ev.sha256}
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                self.bump("no_data")
                return None
            self.bump("http_errors")
            if self.stats is not None:
                self.stats.errors.append(f"shodan {exc.response.status_code}: {url[:60]}")
            return None
        except Exception as exc:                     # noqa: BLE001 - recorded, not fatal
            self.bump("errors")
            if self.stats is not None:
                self.stats.errors.append(f"shodan {type(exc).__name__}: {url[:60]}")
            return None

    def collect(self, target: Target) -> list[Raw]:
        addresses = self.inputs[: self.max_addresses]
        if len(self.inputs) > self.max_addresses:
            self.bump("addresses_skipped", len(self.inputs) - self.max_addresses)
        if not self.key:
            self.bump("geolocation_unavailable_no_api_key")

        raws: list[Raw] = []
        for i, ip in enumerate(addresses, start=1):
            self.progress(i, len(addresses), "addresses")
            free = self._get(INTERNETDB.format(ip=ip))
            paid = None
            if self.key:
                paid = self._get(HOST_LOOKUP.format(ip=ip, key=self.key))
            if free is None and paid is None:
                continue
            self.bump("addresses_with_data")
            raws.append(Raw(
                source=Source.SHODAN,
                kind="host_lookup",
                subject=ip,
                payload={
                    "internetdb": free["body"] if free else None,
                    "host": paid["body"] if paid else None,
                    "has_api_key": bool(self.key),
                },
                evidence_ref=(free or paid)["evidence_ref"],
            ))
        return raws

    # -- normalisation -----------------------------------------------------
    @staticmethod
    def _merge(payload: dict[str, Any]) -> dict[str, Any]:
        """One view of a host from the two possible sources.

        Kept as a separate pure function because it is the only place where the
        two response shapes differ, and because a reviewer should be able to
        see exactly which field came from which endpoint.
        """
        idb = payload.get("internetdb") or {}
        host = payload.get("host") or {}

        services: dict[int, dict[str, Any]] = {}
        for port in idb.get("ports", []) or []:
            services[int(port)] = {"port": int(port)}
        for entry in host.get("data", []) or []:
            port = int(entry.get("port", 0) or 0)
            if not port:
                continue
            services[port] = {
                "port": port,
                "transport": entry.get("transport"),
                "product": entry.get("product"),
                "version": entry.get("version"),
                "cpe": (entry.get("cpe23") or entry.get("cpe") or [None])[0]
                       if isinstance(entry.get("cpe23") or entry.get("cpe"), list)
                       else entry.get("cpe23") or entry.get("cpe"),
            }

        return {
            "ports": sorted(services),
            "services": [services[p] for p in sorted(services)],
            "cpes": sorted(idb.get("cpes", []) or []),
            "tags": sorted(idb.get("tags", []) or []),
            "shodan_hostnames": sorted(idb.get("hostnames", []) or []),
            "cves": sorted(set(idb.get("vulns", []) or []) | set(host.get("vulns", []) or [])),
            "country": host.get("country_code"),
            "org": host.get("org"),
            "isp": host.get("isp"),
        }

    # -- analyze (pure) ----------------------------------------------------
    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]:
        management_ports: dict[int, str] = {
            int(k): v for k, v in self.config.patterns["management_ports"].items()
        }
        eea = set(self.config.patterns["eea_countries"])
        adequacy = set(self.config.patterns["adequacy_countries"])

        findings: list[Finding] = []
        refs = [r.evidence_ref for r in raws if r.evidence_ref]
        by_ip: dict[str, dict[str, Any]] = {}
        exposed_management: dict[str, list[dict[str, Any]]] = {}
        outside: dict[str, list[dict[str, Any]]] = {}
        total_ports = 0

        for raw in raws:
            view = self._merge(raw.payload)
            by_ip[raw.subject] = view
            total_ports += len(view["ports"])

            hits = [s | {"service": management_ports[s["port"]]}
                    for s in view["services"] if s["port"] in management_ports]
            if hits:
                exposed_management[raw.subject] = hits

            country = view["country"]
            if country and country not in eea and country not in adequacy:
                outside.setdefault(country, []).append(
                    {"ip": raw.subject, "org": view["org"], "isp": view["isp"]})

        self.bump("addresses_analyzed", len(by_ip))
        self.bump("open_ports_observed", total_ports)
        self.bump("addresses_with_management_exposed", len(exposed_management))

        # 1. the surface itself: aggregate, weak by construction
        if total_ports:
            findings.append(self.config.make_finding(
                type="open_service_observed",
                source=Source.SHODAN,
                subject=", ".join(target.domains),
                evidence={
                    "addresses_analyzed": len(by_ip),
                    "open_ports_total": total_ports,
                    "by_address": {ip: v["ports"] for ip, v in sorted(by_ip.items())},
                    "software": sorted({
                        f"{s['product']} {s.get('version') or ''}".strip()
                        for v in by_ip.values() for s in v["services"] if s.get("product")
                    }),
                    "source": "shodan database lookup; no packet sent to the third party",
                },
                strength=SignalStrength.WEAK,
                evidence_refs=refs,
                note="reachable services recorded by Shodan; exploitability unassessed here",
            ))

        # 2. management planes reachable from the Internet.
        #
        # One finding for the whole estate, not one per address. On a large
        # supplier the per-address version produced fifty-odd findings that all
        # said the same thing and all bore on the same driver: the verdict was
        # identical, the report was unreadable, and the evidence that actually
        # mattered was buried. The addresses are kept in the evidence.
        if exposed_management:
            services_seen = sorted({h["service"] for hits in exposed_management.values()
                                    for h in hits})
            findings.append(self.config.make_finding(
                type="management_service_exposed",
                source=Source.SHODAN,
                subject=f"{len(exposed_management)} address(es), "
                        f"{', '.join(services_seen)}",
                evidence={
                    "addresses_affected": len(exposed_management),
                    "services": services_seen,
                    "detail": {
                        ip: {"services": hits,
                             "hostnames": by_ip[ip]["shodan_hostnames"][:5],
                             "org": by_ip[ip]["org"]}
                        for ip, hits in sorted(exposed_management.items())[:25]
                    },
                    "detail_truncated": max(0, len(exposed_management) - 25),
                },
                strength=SignalStrength.MODERATE,
                evidence_refs=refs,
                note="administration or database services should not be reachable from "
                     "the public Internet without a documented compensating control",
            ))

        # 3. hosting outside the EEA and outside an adequacy decision
        for country, hosts in sorted(outside.items()):
            findings.append(self.config.make_finding(
                type="hosting_outside_eea",
                source=Source.SHODAN,
                subject=f"{country} ({len(hosts)} address(es))",
                evidence={
                    "country": country,
                    "addresses": hosts,
                    "declared_extra_eu": target.declared_extra_eu,
                    "limitation": "infrastructure location only; says nothing about the "
                                  "legal basis of a transfer (SCC, adequacy, BCR)",
                },
                strength=SignalStrength.MODERATE,
                evidence_refs=refs,
                note=("contradicts the supplier's declaration"
                      if target.declared_extra_eu is False else
                      "consistent with the declaration; recorded for the file"),
            ))

        return findings

    # -- handoff to stage 4 ------------------------------------------------
    def candidate_cves(self, raws: Sequence[Raw]) -> dict[str, list[dict[str, Any]]]:
        """CVE -> where it was observed.

        Candidates, not findings: Shodan infers them from banners and versions,
        so stage 4 must still ask whether each one is in KEV and what EPSS says
        before anything reaches `strong`.
        """
        out: dict[str, list[dict[str, Any]]] = {}
        for raw in raws:
            view = self._merge(raw.payload)
            for cve in view["cves"]:
                out.setdefault(cve, []).append({
                    "address": raw.subject,
                    "ports": view["ports"],
                    "hostnames": view["shodan_hostnames"],
                })
        return dict(sorted(out.items()))
