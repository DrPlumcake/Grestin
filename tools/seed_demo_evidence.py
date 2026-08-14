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

import json
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from grestin.http import EvidenceStore  # noqa: E402
from grestin.pillars.technical.dns import evidence_uri  # noqa: E402
from grestin.pillars.technical.shodan import HOST_LOOKUP, INTERNETDB  # noqa: E402

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


def main() -> int:
    run_id = sys.argv[1] if len(sys.argv) > 1 else "DEMO"
    store = EvidenceStore(ROOT / "evidence", run_id=run_id)
    entries = json.loads(FIXTURE.read_text(encoding="utf-8"))

    for q, body in ((f"%.{DOMAIN}", entries), (DOMAIN, [e for e in entries if e["id"] in (1, 3)])):
        url = f"https://crt.sh/?q={quote(q, safe='')}&output=json&exclude=expired"
        rec = store.store(url, 200, body, {"content-type": "application/json"})
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
        store.store(INTERNETDB.format(ip=ip), 200, body | {"ip": ip}, {})
    # The keyed lookup is stored under the REDACTED url, exactly as the client
    # would key it, so the replay works without a key being present anywhere.
    for ip, body in SHODAN_HOST.items():
        url = HOST_LOOKUP.format(ip=ip, key="REDACTED")
        store.store(url, 200, body | {"ip_str": ip}, {})
    print(f"seeded {len(SHODAN_INTERNETDB)} internetdb + {len(SHODAN_HOST)} host lookups")

    print(f"\nevidence/{run_id}/index.jsonl written. Now run:\n"
          f"  grestin run --target config/targets_example.yaml "
          f"--declared config/declared_example.yaml --offline --run-id {run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
