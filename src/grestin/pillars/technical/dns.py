"""Stage 2 of the technical chain: DNS resolution.

Turns the *names* crt.sh found into *addresses* Shodan can be asked about. It
is the narrowest stage of the pipeline and the one that decides how much of
the certificate surface is actually alive today.

WHY THIS STAGE NEEDS ITS OWN GUARD

DNS is not HTTP, so `http.assert_passive()` never sees these queries. That is
exactly why the passivity argument has to be made again here, and honestly:

  * A recursive query is answered from the resolver's cache when possible; on
    a miss the *resolver* - not this machine - contacts the authoritative
    nameserver for the zone. That nameserver is frequently operated by a DNS
    provider rather than by the supplier, and in every case it is a public
    service whose entire purpose is to answer questions from strangers.
  * No application-layer contact with the supplier's systems ever occurs: we
    never connect to the addresses we learn. That is Shodan's stored data in
    stage 3, not our socket.
  * The one thing that would cross the line is asking the authoritative server
    for the whole zone (AXFR/IXFR) or guessing names that were never observed.
    Both are refused: `ALLOWED_RRTYPES` is a three-element allowlist, and the
    host list comes exclusively from certificate transparency, so this stage
    never invents a name.

The `assert_passive_dns()` gate mirrors `http.assert_passive()`, and is
likewise covered by tests, so the claim in Chapter 6 is enforced on both
protocols rather than on one.

The resolver is pinned and recorded in the evidence, because "which resolver"
changes what you see (split-horizon, geo-DNS, regional filtering) and a run
that cannot be reproduced is not evidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from ...models import Finding, Pillar, Raw, SignalStrength, Source, Target
from ..base import BaseCollector

# Only these record types answer the question "does this name exist and where
# does it point". Anything else is either useless here or crosses into
# enumeration of the zone.
ALLOWED_RRTYPES = ("A", "AAAA", "CNAME")

DENIED_RRTYPES = {
    "AXFR": "full zone transfer: enumerates the supplier's entire namespace",
    "IXFR": "incremental zone transfer: same objection as AXFR",
    "ANY": "shotgun query, commonly refused and often used for amplification abuse",
}

# Public recursive resolvers. Pinned rather than inherited from the OS so that
# a run is reproducible and does not leak the query pattern to a corporate
# resolver that may log it against the analyst.
DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8")


class ZoneTransferBlocked(Exception):
    """Raised when a DNS query would go beyond passive resolution."""


def assert_passive_dns(rrtype: str, hostname: str) -> None:
    """Gate for the DNS stage, the analogue of http.assert_passive()."""
    rr = rrtype.upper()
    if rr in DENIED_RRTYPES:
        raise ZoneTransferBlocked(f"{rr} refused ({DENIED_RRTYPES[rr]}): {hostname}")
    if rr not in ALLOWED_RRTYPES:
        raise ZoneTransferBlocked(
            f"record type {rr} is not in the passive allowlist {ALLOWED_RRTYPES}"
        )
    if "*" in hostname:
        raise ZoneTransferBlocked(f"wildcard names are never resolved: {hostname}")


def evidence_uri(hostname: str, rrtype: str, resolver: str) -> str:
    """Stable key for the evidence store. Not an HTTP URL: DNS answers are
    stored alongside HTTP responses so that `--offline` replays the whole
    chain, not just the parts that happen to travel over TCP/443."""
    return f"dns://{resolver}/{rrtype}/{hostname}"


class DnsCollector(BaseCollector):
    name = "dns"
    pillar = Pillar.TECHNICAL

    #: hosts handed over by crt.sh; set by the runner before `run()`
    inputs: list[str]

    def __init__(self, client, config, stats=None, resolvers: Sequence[str] | None = None,
                 max_hosts: int = 250, timeout: float = 4.0) -> None:
        super().__init__(client, config, stats)
        self.resolvers = list(resolvers or DEFAULT_RESOLVERS)
        self.max_hosts = max_hosts
        self.timeout = timeout
        self.inputs = []
        self._resolver: dns.resolver.Resolver | None = None

    # -- resolver ----------------------------------------------------------
    @property
    def resolver(self) -> dns.resolver.Resolver:
        if self._resolver is None:
            r = dns.resolver.Resolver(configure=False)   # ignore the OS config on purpose
            r.nameservers = self.resolvers
            r.timeout = self.timeout
            r.lifetime = self.timeout * 2
            self._resolver = r
        return self._resolver

    def _query(self, hostname: str, rrtype: str) -> dict[str, Any]:
        """One record type for one name, with the answer normalised to a dict.

        Never raises for DNS-level outcomes: NXDOMAIN and "no answer" are
        results, not failures, and the difference between them matters
        downstream (a CNAME pointing at an NXDOMAIN target is a takeover
        precondition, whereas an empty answer is just a name with no address).
        """
        assert_passive_dns(rrtype, hostname)
        uri = evidence_uri(hostname, rrtype, self.resolvers[0])

        cached = self.client.evidence.lookup(uri)
        if cached is not None:
            self.bump("cache_hits")
            return cached["body"]

        if self.client.offline:
            self.bump("offline_misses")
            return {"status": "not_in_evidence", "values": []}

        payload: dict[str, Any]
        try:
            answer = self.resolver.resolve(hostname, rrtype, raise_on_no_answer=False)
            values = sorted(str(r).rstrip(".") for r in (answer.rrset or []))
            payload = {"status": "ok" if values else "no_answer", "values": values}
        except dns.resolver.NXDOMAIN:
            payload = {"status": "nxdomain", "values": []}
        except dns.resolver.NoNameservers:
            payload = {"status": "servfail", "values": []}
        except (dns.exception.Timeout, dns.exception.DNSException) as exc:
            payload = {"status": "error", "values": [], "error": type(exc).__name__}
            self.bump("errors")

        payload |= {"hostname": hostname, "rrtype": rrtype, "resolver": self.resolvers[0]}
        self.client.evidence.store(uri, 0, payload, {})
        self.bump("queries")
        return payload

    # -- collect -----------------------------------------------------------
    def collect(self, target: Target) -> list[Raw]:
        """Resolve the hosts handed over by stage 1, sensitive names first.

        `inputs` is already ordered by crt.sh so that a run truncated by
        `max_hosts` still covers the names that matter most.
        """
        hosts = [h for h in self.inputs if "*" not in h][: self.max_hosts]
        if len(self.inputs) > self.max_hosts:
            self.bump("hosts_skipped", len(self.inputs) - self.max_hosts)

        raws: list[Raw] = []
        for host in hosts:
            records = {rr: self._query(host, rr) for rr in ALLOWED_RRTYPES}

            # A CNAME is only a takeover precondition if its target is gone,
            # so resolve one further hop - and only one, to stay bounded.
            cname_target_status = None
            cnames = records["CNAME"]["values"]
            if cnames:
                cname_target_status = self._query(cnames[0], "A")["status"]

            raws.append(Raw(
                source=Source.DNS,
                kind="dns_records",
                subject=host,
                payload={
                    "records": records,
                    "cname_target_status": cname_target_status,
                    "resolver": self.resolvers[0],
                },
                evidence_ref=self.client.evidence.key(
                    evidence_uri(host, "A", self.resolvers[0])),
            ))
        return raws

    # -- analyze (pure) ----------------------------------------------------
    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]:
        resolved: dict[str, list[str]] = {}
        dead: list[str] = []
        dangling: list[dict[str, Any]] = []
        refs: list[str] = []

        for raw in raws:
            if raw.evidence_ref:
                refs.append(raw.evidence_ref)
            rec = raw.payload["records"]
            addresses = rec["A"]["values"] + rec["AAAA"]["values"]
            if addresses:
                resolved[raw.subject] = addresses
            elif rec["A"]["status"] == "nxdomain":
                dead.append(raw.subject)

            if rec["CNAME"]["values"] and raw.payload.get("cname_target_status") == "nxdomain":
                dangling.append({
                    "hostname": raw.subject,
                    "cname_target": rec["CNAME"]["values"][0],
                    "target_status": "nxdomain",
                })

        self.bump("hosts_resolved", len(resolved))
        self.bump("hosts_nxdomain", len(dead))
        self.bump("unique_ips", len({ip for ips in resolved.values() for ip in ips}))

        findings: list[Finding] = []

        if resolved:
            sensitive = {h: ips for h, ips in resolved.items()
                         if self.config.sensitive_categories(h)}
            findings.append(self.config.make_finding(
                type="hostname_resolves",
                source=Source.DNS,
                subject=", ".join(target.domains),
                evidence={
                    "hosts_queried": len(raws),
                    "hosts_resolving": len(resolved),
                    "hosts_nxdomain": len(dead),
                    "unique_addresses": sorted({ip for ips in resolved.values() for ip in ips}),
                    "sensitive_hosts_live": {h: ips for h, ips in sorted(sensitive.items())},
                    "resolver": raws[0].payload["resolver"] if raws else None,
                },
                strength=SignalStrength.INFO,
                evidence_refs=refs,
                note="live subset of the certificate surface; feeds the Shodan lookup (stage 3)",
            ))

        for item in dangling:
            findings.append(self.config.make_finding(
                type="dangling_cname",
                source=Source.DNS,
                subject=item["hostname"],
                evidence=item,
                strength=SignalStrength.MODERATE,
                evidence_refs=refs,
                note="alias points at a name that no longer exists: subdomain-takeover "
                     "precondition, observable without contacting the host",
            ))

        return findings

    # -- handoff to stage 3 ------------------------------------------------
    def addresses(self, raws: Sequence[Raw]) -> dict[str, list[str]]:
        """IP -> hostnames that resolve to it. Shodan is queried per address,
        so de-duplicating here is what keeps the API budget sane: a hundred
        names behind one load balancer cost one lookup, not a hundred."""
        out: dict[str, list[str]] = {}
        for raw in raws:
            rec = raw.payload["records"]
            for ip in rec["A"]["values"] + rec["AAAA"]["values"]:
                out.setdefault(ip, []).append(raw.subject)
        return {ip: sorted(hosts) for ip, hosts in sorted(out.items())}
