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

    print(f"\nevidence/{run_id}/index.jsonl written. Now run:\n"
          f"  grestin run --target config/targets_example.yaml "
          f"--declared config/declared_example.yaml --offline --run-id {run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
