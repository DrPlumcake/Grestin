"""Stage 4 of the technical chain: qualifying the candidate CVEs.

Stage 3 handed over a list of CVE identifiers that Shodan associated with the
banners it saw. This stage asks the three questions that decide whether any of
them is worth a driver:

    Is it being exploited right now?        CISA KEV catalogue
    How likely is exploitation soon?        FIRST EPSS
    How bad is it if exploited?             CVSS, from Shodan's CVE database

Only the first can justify `strong`. That is the whole design of the chain:
four instruments, and the driver moves only when the last one confirms that a
vulnerability *known to be exploited in the wild* sits on a service that was
*observed as reachable* on an address *attributed to the supplier*. Each of
those three clauses comes from a different stage, and none of them alone is
enough.

THE FALSE POSITIVE THAT HAS TO BE DECLARED

Shodan infers CVEs from version strings in banners. Linux distributions
routinely backport security fixes without changing the advertised version, so
a banner-based match systematically over-reports: a fully patched Debian box
still announces the version it shipped with. This stage therefore cannot say
"the supplier is vulnerable". What it says is: a service reachable from the
Internet advertises a version associated with a vulnerability that is being
actively exploited, and the supplier is asked to demonstrate otherwise. The
limitation travels inside the finding evidence, not only in the report text,
so that it survives being copied into another document.

That reversal is the point of the layer. It does not prove a weakness; it
moves the burden of explanation onto the party that actually has the facts.

API BUDGET

KEV is fetched once per run (a single JSON of the whole catalogue) and then
looked up locally: N CVEs cost one HTTP call, not N. EPSS is batched. Only the
CVSS lookup is per-CVE, and it is the one that degrades most gracefully if it
fails, so a rate-limited run still produces the KEV verdict.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ...models import Finding, Pillar, Raw, SignalStrength, Source, Target
from ..base import BaseCollector

KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
EPSS_BATCH = "https://api.first.org/data/v1/epss?cve={cves}"
CVEDB = "https://cvedb.shodan.io/cve/{cve}"

EPSS_BATCH_SIZE = 60          # comfortably under the endpoint's practical limit


class VulnsCollector(BaseCollector):
    name = "vulns"
    pillar = Pillar.TECHNICAL

    #: CVE -> observations, handed over by the Shodan stage. A mapping rather
    #: than a bare list because a finding is worthless without the address,
    #: port and hostname the CVE was seen on.
    inputs: dict[str, list[dict[str, Any]]] | list[str]

    def __init__(self, client, config, stats=None, max_cves: int = 300) -> None:
        super().__init__(client, config, stats)
        self.max_cves = max_cves

    # -- helpers -----------------------------------------------------------
    @property
    def observations(self) -> dict[str, list[dict[str, Any]]]:
        """Normalise the handoff: accept a mapping or a bare list of ids."""
        if isinstance(self.inputs, dict):
            return self.inputs
        return {cve: [] for cve in self.inputs}

    def _safe(self, url: str) -> Any | None:
        try:
            body, _ = self.client.get_json(url)
            return body
        except Exception as exc:                     # noqa: BLE001 - recorded, not fatal
            self.bump("lookup_errors")
            if self.stats is not None:
                self.stats.errors.append(f"vulns {type(exc).__name__}: {url[:70]}")
            return None

    # -- collect -----------------------------------------------------------
    def collect(self, target: Target) -> list[Raw]:
        cves = sorted(self.observations)[: self.max_cves]
        if not cves:
            return []
        if len(self.observations) > self.max_cves:
            self.bump("cves_skipped", len(self.observations) - self.max_cves)

        raws: list[Raw] = []

        # 1. KEV: one call for the whole catalogue, then local lookups
        catalogue = self._safe(KEV_FEED)
        kev_index: dict[str, dict[str, Any]] = {}
        if catalogue:
            for item in catalogue.get("vulnerabilities", []) or []:
                kev_index[item["cveID"]] = item
            self.bump("kev_catalogue_size", len(kev_index))
            raws.append(Raw(source=Source.KEV, kind="kev_catalogue", subject="cisa-kev",
                            payload={"catalogue_version": catalogue.get("catalogVersion"),
                                     "count": len(kev_index),
                                     "matches": {c: kev_index[c] for c in cves
                                                 if c in kev_index}}))

        # 2. EPSS: batched
        epss: dict[str, dict[str, Any]] = {}
        for i in range(0, len(cves), EPSS_BATCH_SIZE):
            batch = cves[i: i + EPSS_BATCH_SIZE]
            body = self._safe(EPSS_BATCH.format(cves=",".join(batch)))
            for item in (body or {}).get("data", []) or []:
                epss[item["cve"]] = item
            self.bump("epss_batches")
        if epss:
            raws.append(Raw(source=Source.EPSS, kind="epss_scores", subject="first-epss",
                            payload={"scores": epss}))

        # 3. CVSS and description, one call per CVE, best effort
        for i, cve in enumerate(cves, start=1):
            self.progress(i, len(cves), "CVEs")
            body = self._safe(CVEDB.format(cve=cve))
            self.bump("cvedb_lookups")
            raws.append(Raw(
                source=Source.NVD,
                kind="cve_detail",
                subject=cve,
                payload={
                    "detail": body or {},
                    "kev": kev_index.get(cve),
                    "epss": epss.get(cve),
                    "observed_on": self.observations.get(cve, []),
                },
            ))
        return raws

    # -- analyze (pure) ----------------------------------------------------
    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]:
        epss_high = float(self.config.threshold("epss_high"))
        cvss_high = float(self.config.threshold("cvss_high"))
        findings: list[Finding] = []

        for raw in raws:
            if raw.kind != "cve_detail":
                continue
            cve = raw.subject
            detail = raw.payload.get("detail") or {}
            kev = raw.payload.get("kev")
            epss = raw.payload.get("epss") or {}
            seen_on = raw.payload.get("observed_on") or []

            cvss = detail.get("cvss_v3") or detail.get("cvss") or None
            epss_score = float(epss.get("epss", 0) or 0)
            base = {
                "cve": cve,
                "cvss": cvss,
                "epss": epss_score,
                "epss_percentile": float(epss.get("percentile", 0) or 0),
                "summary": (detail.get("summary") or "")[:280],
                "observed_on": seen_on,
                "limitation": (
                    "CVE association is inferred from banner version strings; "
                    "backported distribution patches are not visible externally, so "
                    "this is a question for the supplier, not a confirmed weakness"
                ),
            }

            if kev:
                self.bump("kev_hits")
                findings.append(self.config.make_finding(
                    type="kev_on_exposed_service",
                    source=Source.KEV,
                    subject=f"{cve} on {self._where(seen_on)}",
                    evidence=base | {
                        "kev_date_added": kev.get("dateAdded"),
                        "kev_due_date": kev.get("dueDate"),
                        "kev_vendor_product": (
                            f"{kev.get('vendorProject', '')} {kev.get('product', '')}".strip()),
                        "kev_required_action": kev.get("requiredAction"),
                    },
                    strength=SignalStrength.STRONG,
                    note="in the CISA KEV catalogue: exploitation observed in the wild, "
                         "on a service recorded as reachable from the Internet",
                ))

                if str(kev.get("knownRansomwareCampaignUse", "")).lower() == "known":
                    self.bump("kev_ransomware_flagged")
                    findings.append(self.config.make_finding(
                        type="kev_ransomware_flag",
                        source=Source.KEV,
                        subject=cve,
                        evidence=base | {"known_ransomware_campaign_use": True},
                        strength=SignalStrength.MODERATE,
                        note="used in ransomware campaigns; corroborates any leak-site "
                             "listing found by the incident pillar",
                    ))
                continue        # KEV supersedes the weaker qualifications

            if epss_score >= epss_high:
                self.bump("epss_high")
                findings.append(self.config.make_finding(
                    type="high_epss_on_exposed_service",
                    source=Source.EPSS,
                    subject=f"{cve} on {self._where(seen_on)}",
                    evidence=base | {"threshold": epss_high},
                    strength=SignalStrength.MODERATE,
                    note="EPSS prioritises: it estimates the probability of exploitation "
                         "in the next 30 days, it does not evidence exploitation",
                ))
            elif cvss and float(cvss) >= cvss_high:
                self.bump("cvss_high")
                findings.append(self.config.make_finding(
                    type="cve_on_exposed_service",
                    source=Source.NVD,
                    subject=f"{cve} on {self._where(seen_on)}",
                    evidence=base | {"threshold": cvss_high},
                    strength=SignalStrength.MODERATE,
                    note="high severity, but neither actively exploited nor high EPSS",
                ))
            else:
                self.bump("cves_below_threshold")

        return findings

    @staticmethod
    def _where(seen_on: Sequence[dict[str, Any]]) -> str:
        """Human-readable location, so the subject of a finding is never a bare
        CVE id: the address and hostname are what makes it the supplier's."""
        if not seen_on:
            return "an address attributed to the third party"
        first = seen_on[0]
        host = (first.get("hostnames") or [None])[0]
        where = first.get("address", "?")
        if host:
            where = f"{host} ({where})"
        extra = f" and {len(seen_on) - 1} more" if len(seen_on) > 1 else ""
        return f"{where}{extra}"
