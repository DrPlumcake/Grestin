#!/usr/bin/env python3
"""Seed the evidence store from the test fixtures, so that

    grestin run --target config/targets_example.yaml --offline --run-id DEMO

works with the network unplugged. Two reasons this matters beyond convenience:
the presentation cannot fail because crt.sh is returning 502 at the wrong
moment, and a reviewer can reproduce every number in the report without any
API key.

Usage:  python tools/seed_demo_evidence.py [run_id]
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from grestin.http import EvidenceStore, redact  # noqa: E402
from grestin.pillars.corporate.opensanctions import MATCH  # noqa: E402
from grestin.pillars.technical.dns import evidence_uri  # noqa: E402
from grestin.pillars.technical.shodan import HOST_LOOKUP, INTERNETDB  # noqa: E402
from grestin.pillars.technical.vulns import CVEDB, EPSS_BATCH, KEV_FEED  # noqa: E402

DOMAIN = "acme-ran.example"
FIXTURE = ROOT / "tests" / "fixtures" / "crtsh_acme.json"
RESOLVER = "1.1.1.1"

# Fabricated DNS answers for the demo host set: what a small real estate looks
# like. `shop.` is deliberately a dangling CNAME so the chain produces a
# moderate signal and the driver moves to REVIEW - i.e. the demo shows stage 2
# doing something stage 1 could not.
DNS_FIXTURE = {
    "acme-ran.example":            {"A": ["203.0.113.10"]},
    "www.acme-ran.example":        {"A": ["203.0.113.10"]},
    "api.acme-ran.example":        {"A": ["203.0.113.11"]},
    "vpn.acme-ran.example":        {"A": ["203.0.113.7"]},
    "sso.acme-ran.example":        {"A": ["203.0.113.7"]},
    "jenkins.acme-ran.example":    {"A": ["203.0.113.23"]},
    "grafana.acme-ran.example":    {"A": ["203.0.113.23"]},
    "prometheus.acme-ran.example": {"A": ["203.0.113.23"]},
    "mail.acme-ran.example":       {"A": ["203.0.113.12"]},
    "uat-portal.acme-ran.example": {"CNAME": ["uat-acme.hosting-provider.example"]},
    "uat-acme.hosting-provider.example": {"NXDOMAIN": True},
}


# Shodan answers for the five addresses the DNS stage produces. Deliberately
# shaped so the demo shows what stage 3 adds and stage 2 could not:
#   .7   RDP exposed on a VPN/SSO address  -> management_service_exposed
#   .23  Elasticsearch on the devops host  -> management_service_exposed
#   .11  hosted in Singapore               -> hosting_outside_eea
# plus candidate CVEs, which stage 4 will have to qualify against KEV/EPSS.
SHODAN_INTERNETDB = {
    "203.0.113.10": {"ports": [80, 443], "cpes": ["cpe:/a:nginx:nginx:1.24.0"],
                     "hostnames": ["www.acme-ran.example"], "tags": [], "vulns": []},
    "203.0.113.11": {"ports": [443], "cpes": ["cpe:/a:apache:tomcat:9.0.65"],
                     "hostnames": ["api.acme-ran.example"], "tags": ["cloud"],
                     "vulns": ["CVE-2023-46589"]},
    "203.0.113.12": {"ports": [25, 587, 993], "cpes": [], "hostnames": ["mail.acme-ran.example"],
                     "tags": [], "vulns": []},
    "203.0.113.7":  {"ports": [443, 3389], "cpes": ["cpe:/a:paloaltonetworks:pan-os:10.2.4"],
                     "hostnames": ["vpn.acme-ran.example", "sso.acme-ran.example"],
                     "tags": ["vpn"], "vulns": ["CVE-2024-3400"]},
    "203.0.113.23": {"ports": [8080, 9200], "cpes": ["cpe:/a:jenkins:jenkins:2.401.1"],
                     "hostnames": ["jenkins.acme-ran.example", "grafana.acme-ran.example"],
                     "tags": ["devops"], "vulns": ["CVE-2024-23897"]},
}

SHODAN_HOST = {   # the keyed endpoint: geolocation and product/version detail
    "203.0.113.10": {"country_code": "IT", "org": "Acme RAN S.p.A.", "isp": "Example Telecom",
                     "data": [{"port": 443, "transport": "tcp", "product": "nginx",
                               "version": "1.24.0"}], "vulns": []},
    "203.0.113.11": {"country_code": "SG", "org": "Cloud Provider APAC", "isp": "Cloud Provider",
                     "data": [{"port": 443, "transport": "tcp", "product": "Apache Tomcat",
                               "version": "9.0.65"}], "vulns": ["CVE-2023-46589"]},
    "203.0.113.12": {"country_code": "IT", "org": "Acme RAN S.p.A.", "isp": "Example Telecom",
                     "data": [{"port": 25, "transport": "tcp", "product": "Postfix"}],
                     "vulns": []},
    "203.0.113.7":  {"country_code": "IT", "org": "Acme RAN S.p.A.", "isp": "Example Telecom",
                     "data": [{"port": 3389, "transport": "tcp",
                               "product": "Microsoft Terminal Services"},
                              {"port": 443, "transport": "tcp", "product": "PAN-OS",
                               "version": "10.2.4"}], "vulns": ["CVE-2024-3400"]},
    "203.0.113.23": {"country_code": "IT", "org": "Acme RAN S.p.A.", "isp": "Example Telecom",
                     "data": [{"port": 8080, "transport": "tcp", "product": "Jenkins",
                               "version": "2.401.1"},
                              {"port": 9200, "transport": "tcp", "product": "Elasticsearch"}],
                     "vulns": ["CVE-2024-23897"]},
}


# Stage 4 fixtures. The CVE identifiers are real, but the catalogue entries,
# EPSS scores and CVSS values below are ILLUSTRATIVE: a live run fetches the
# current CISA catalogue and the current EPSS model, both of which change
# daily. Never quote these numbers in the thesis - quote a real run.
#
# The mix is deliberate: one KEV entry with ransomware use (drives the driver
# to SUGGEST_YES and sets up the cross-pillar corroboration), one KEV entry
# without it, and one CVE that is neither, to show the layer staying quiet.
KEV_FIXTURE = {
    "catalogVersion": "2026.08.13-DEMO",
    "vulnerabilities": [
        {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS",
         "vulnerabilityName": "Command injection in GlobalProtect",
         "dateAdded": "2024-04-12", "dueDate": "2024-04-19",
         "requiredAction": "Apply mitigations per vendor instructions.",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2024-23897", "vendorProject": "Jenkins", "product": "Jenkins",
         "vulnerabilityName": "Arbitrary file read via the CLI",
         "dateAdded": "2024-08-19", "dueDate": "2024-09-09",
         "requiredAction": "Apply mitigations per vendor instructions.",
         "knownRansomwareCampaignUse": "Unknown"},
    ],
}

EPSS_FIXTURE = {
    "CVE-2024-3400":  {"epss": "0.94", "percentile": "0.99"},
    "CVE-2024-23897": {"epss": "0.71", "percentile": "0.97"},
    "CVE-2023-46589": {"epss": "0.02", "percentile": "0.61"},
}

CVEDB_FIXTURE = {
    "CVE-2024-3400":  {"cvss_v3": 10.0, "summary": "Command injection in the GlobalProtect "
                                                   "feature of PAN-OS."},
    "CVE-2024-23897": {"cvss_v3": 9.8, "summary": "Arbitrary file read through the Jenkins CLI."},
    "CVE-2023-46589": {"cvss_v3": 7.5, "summary": "Improper handling of trailer headers in "
                                                  "Apache Tomcat."},
}


# Corporate pillar fixture. Two candidates: one sanctioned entity whose name
# merely resembles the counterparty (no shared identifier -> fuzzy, moderate,
# never strong), and the actual counterparty with a controlling shareholder in
# a non-EEA jurisdiction. Entities and ids are invented.
OPENSANCTIONS_FIXTURE = {
    "responses": {
        "q1": {
            "results": [
                {
                    "id": "NK-acmeRanHoldings",
                    "caption": "Acme RAN Holdings Ltd",
                    "schema": "Company",
                    "score": 0.87,
                    "match": False,
                    "datasets": ["eu_fsf", "us_ofac_sdn"],
                    "properties": {
                        "name": ["Acme RAN Holdings Ltd"],
                        "country": ["ru"],
                        "topics": ["sanction"],
                        "registrationNumber": ["9988776"],
                    },
                },
                {
                    "id": "NK-acmeRanSpa",
                    "caption": "Acme RAN S.p.A.",
                    "schema": "Company",
                    "score": 0.96,
                    "match": True,
                    "datasets": ["it_registry"],
                    "properties": {
                        "name": ["Acme RAN S.p.A."],
                        "country": ["it"],
                        "topics": [],
                        "registrationNumber": ["RM-1234567"],
                        "ownershipAsset": [{
                            "id": "own-1",
                            "schema": "Ownership",
                            "properties": {
                                "percentage": ["62"],
                                "owner": [{
                                    "id": "NK-zetaInvest",
                                    "caption": "Zeta Invest Group",
                                    "schema": "Company",
                                    "properties": {"country": ["cn"], "topics": []},
                                }],
                            },
                        }],
                    },
                },
            ]
        }
    }
}


def main() -> int:
    run_id = sys.argv[1] if len(sys.argv) > 1 else "DEMO"
    store = EvidenceStore(ROOT / "evidence", run_id=run_id)
    entries = json.loads(FIXTURE.read_text(encoding="utf-8"))

    for q, body in ((f"%.{DOMAIN}", entries), (DOMAIN, [e for e in entries if e["id"] in (1, 3)])):
        url = f"https://crt.sh/?q={quote(q, safe='')}&output=json&exclude=expired"
        rec = store.store(redact(url), 200, body, {"content-type": "application/json"})
        print(f"seeded {rec.sha256[:12]}  {url}")

    for host, spec in DNS_FIXTURE.items():
        for rrtype in ("A", "AAAA", "CNAME"):
            values = spec.get(rrtype, [])
            if spec.get("NXDOMAIN"):
                status = "nxdomain"
            elif values:
                status = "ok"
            else:
                status = "no_answer"
            store.store(evidence_uri(host, rrtype, RESOLVER), 0,
                        {"status": status, "values": values, "hostname": host,
                         "rrtype": rrtype, "resolver": RESOLVER}, {})
    print(f"seeded {len(DNS_FIXTURE) * 3} DNS answers via {RESOLVER}")

    for ip, body in SHODAN_INTERNETDB.items():
        store.store(redact(INTERNETDB.format(ip=ip)), 200, body | {"ip": ip}, {})
    # The keyed lookup is stored under the REDACTED url, exactly as the client
    # would key it, so the replay works without a key being present anywhere.
    for ip, body in SHODAN_HOST.items():
        url = HOST_LOOKUP.format(ip=ip, key="anything")
        store.store(redact(url), 200, body | {"ip_str": ip}, {})
    print(f"seeded {len(SHODAN_INTERNETDB)} internetdb + {len(SHODAN_HOST)} host lookups")

    store.store(redact(KEV_FEED), 200, KEV_FIXTURE, {})
    cves = sorted(CVEDB_FIXTURE)
    store.store(redact(EPSS_BATCH.format(cves=",".join(cves))), 200,
                {"status": "OK", "data": [{"cve": c, **EPSS_FIXTURE[c]} for c in cves]}, {})
    for cve, body in CVEDB_FIXTURE.items():
        store.store(redact(CVEDB.format(cve=cve)), 200, body | {"cve_id": cve}, {})
    match_payload = {"queries": {"q1": {
        "schema": "Company",
        "properties": {
            "name": ["Acme RAN S.p.A.", "Acme RAN SpA", "Acme RAN"],
            "country": ["IT"],
            "registrationNumber": ["RM-1234567"],
            "vatCode": ["IT01234567890"],
        },
    }}}
    body_digest = hashlib.sha256(
        json.dumps(match_payload, sort_keys=True).encode()).hexdigest()[:16]
    store.store(f"{MATCH.format(scope='default')}#body={body_digest}", 200,
                OPENSANCTIONS_FIXTURE, {})
    print("seeded 1 OpenSanctions match response")

    print(f"seeded KEV catalogue ({len(KEV_FIXTURE['vulnerabilities'])} entries), "
          f"1 EPSS batch, {len(CVEDB_FIXTURE)} CVE details")

    print(f"\nevidence/{run_id}/index.jsonl written. Now run:\n"
          f"  grestin run --target config/targets_example.yaml "
          f"--declared config/declared_example.yaml --offline --run-id {run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
