"""Command line entry point and runner.

    grestin run      --target config/targets/acme.yaml [--offline] [--prefill TOOL.xlsx]
    grestin guard    --url https://api.shodan.io/shodan/scan   # demo the policy
    grestin coverage                                            # driver coverage table

The runner executes the technical pillar as a chain (crt.sh -> DNS -> Shodan ->
NVD/KEV/EPSS) and the corporate and incident pillars independently, exactly as
Chapter 6 describes. Only crt.sh is wired in this commit; the remaining stages
are registered as `None` so the run still completes and stats.json records what
is missing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import yaml
from dotenv import load_dotenv

from .config import Config
from .http import ActiveScanBlocked, EvidenceStore, PassiveClient, assert_passive
from .hub import report as report_mod
from .hub.prefill import prefill, read_declared_answers
from .hub.scoring import projected_score, score
from .models import RunStats, Target, utcnow
from .pillars.technical.crtsh import CrtShCollector
from .pillars.technical.dns import DnsCollector
from .pillars.technical.shodan import ShodanCollector
from .pillars.technical.vulns import VulnsCollector

TECHNICAL_CHAIN = [("crtsh", CrtShCollector), ("dns", DnsCollector),
                   ("shodan", ShodanCollector), ("vulns", VulnsCollector)]
INDEPENDENT = [("opensanctions", None), ("ransomware_live", None)]


def load_target(path: str | Path) -> Target:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Target.from_dict(data)


def run(args: argparse.Namespace) -> int:
    config = Config.load(args.config_dir)
    target = load_target(args.target)
    run_id = args.run_id or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stats = RunStats(run_id=run_id, target=target.legal_name)
    out_dir = Path(args.out) / f"{target.slug}-{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    evidence = EvidenceStore(args.evidence, run_id=run_id)
    findings, raws_all = [], []

    with PassiveClient(evidence=evidence, offline=args.offline, stats=stats) as client:
        # --- technical pillar: sequential, each stage narrows the next -----
        handoff: list[str] = []
        for name, cls in TECHNICAL_CHAIN:
            if cls is None:
                stats.bump(f"{name}.not_implemented")
                print(f"  [skip] {name}: not implemented yet", file=sys.stderr)
                continue
            t0 = time.monotonic()
            collector = cls(client, config, stats)
            collector.inputs = handoff          # output of the previous stage
            raws, fs = collector.run(target)
            stats.timing(f"pillar:{name}", int((time.monotonic() - t0) * 1000))
            raws_all += raws
            findings += fs
            if name == "crtsh":
                handoff = collector.resolvable_hosts(raws, target)
                stats.bump("crtsh.hosts_for_dns", len(handoff))
                (out_dir / "handoff_hosts.json").write_text(
                    json.dumps(handoff, indent=2), encoding="utf-8")
            elif name == "dns":
                addresses = collector.addresses(raws)
                handoff = list(addresses)       # stage 3 is queried per address
                stats.bump("dns.addresses_for_shodan", len(handoff))
                (out_dir / "handoff_addresses.json").write_text(
                    json.dumps(addresses, indent=2), encoding="utf-8")
            elif name == "shodan":
                cves = collector.candidate_cves(raws)
                handoff = cves                  # mapping: stage 4 needs the context
                stats.bump("shodan.candidate_cves", len(handoff))
                (out_dir / "handoff_cves.json").write_text(
                    json.dumps(cves, indent=2), encoding="utf-8")
            print(f"  [ok]   {name}: {len(raws)} raw, {len(fs)} findings", file=sys.stderr)

        # --- corporate and incident pillars: independent -------------------
        for name, cls in INDEPENDENT:
            if cls is None:
                stats.bump(f"{name}.not_implemented")
                print(f"  [skip] {name}: not implemented yet", file=sys.stderr)

    # --- hub --------------------------------------------------------------
    summary = score(findings, config)
    declared: dict[str, str] = {}
    if args.declared:
        declared = yaml.safe_load(Path(args.declared).read_text(encoding="utf-8")) or {}
    elif args.prefill:
        # read what the compiler has already answered straight from the workbook
        declared = read_declared_answers(args.prefill, config)
        print(f"  [ok]   declared answers read from the tool: {len(declared)}", file=sys.stderr)
    projection = projected_score(summary, config, declared)

    (out_dir / "findings.json").write_text(
        json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "raws.json").write_text(
        json.dumps([r.to_dict() for r in raws_all], indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "verdicts.json").write_text(
        json.dumps(summary.to_dict() | {"projection": projection}, indent=2, ensure_ascii=False),
        encoding="utf-8")

    md = report_mod.render(target, summary, config, run_id, utcnow(), projection)
    report_mod.write(out_dir / "risk_assessment_report.md", md)

    if args.prefill:
        result = prefill(args.prefill, out_dir / f"{target.slug}_driver_matrix.xlsx",
                         summary, config, target.legal_name, run_id, projection,
                         write_answers=args.write_answers)
        stats.bump("prefill.suggestions", len(result["suggestions_written"]))
        stats.bump("prefill.cells_written", len(result["cells_written"]))
        print(f"  [ok]   prefill ({result['mode']}): "
              f"{len(result['suggestions_written'])} suggestion(s), "
              f"{len(result['cells_written'])} answer(s) -> {result['output']}", file=sys.stderr)
        if result["excel_only_formulas"]:
            print(f"  [warn] {result['recalculation']}", file=sys.stderr)

    stats.finished_at = utcnow()
    stats.dump(str(out_dir / "stats.json"))

    print(f"\nTarget: {target.legal_name}")
    print(f"Findings: {len(findings)} | SUGGEST_YES: {len(summary.suggest_yes)} | "
          f"REVIEW: {len(summary.review)}")
    print(f"Addressable weight: {summary.addressable_weight:.0%} | "
          f"proposed: {summary.suggested_weight:.0%}")
    print(f"Declared {projection['declared_score']:.0%} ({projection['declared_level']}) -> "
          f"projected {projection['projected_score']:.0%} ({projection['projected_level']})")
    print(f"Output: {out_dir}")
    return 0


def guard(args: argparse.Namespace) -> int:
    """Show the passive policy refusing or accepting a URL. Good slide material."""
    try:
        assert_passive(args.url)
    except ActiveScanBlocked as exc:
        print(f"BLOCKED  {args.url}\n         {exc}")
        return 1
    print(f"ALLOWED  {args.url}")
    return 0


def coverage(args: argparse.Namespace) -> int:
    config = Config.load(args.config_dir)
    print(f"{'driver':<52}{'weight':>8}  {'CTI':>4}  sources")
    print("-" * 96)
    for d in config.drivers.values():
        w = f"{d.weight:.2f}" if d.weight is not None else f"<={d.max_weight:.2f}*"
        print(f"{d.name[:50]:<52}{w:>8}  {'yes' if d.cti_observable else ' no':>4}  "
              f"{', '.join(d.cti_sources) or '-'}")
    print("-" * 96)
    print(f"{'ADDRESSABLE BY THE CTI LAYER':<52}{config.addressable_weight:>8.2f}")
    print("* variable weight (data classification C1-C4)")
    return 0


def main(argv: list[str] | None = None) -> int:
    # API keys live in .env (git-ignored), never in the repo or in a YAML file.
    load_dotenv()
    p = argparse.ArgumentParser(prog="grestin", description=__doc__)
    p.add_argument("--config-dir", default=str(Path(__file__).resolve().parents[2] / "config"))
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the pillars against one target")
    r.add_argument("--target", required=True)
    r.add_argument("--declared", help="YAML of the answers already given in the tool")
    r.add_argument("--offline", action="store_true", help="replay from the evidence store only")
    r.add_argument("--run-id", help="reuse a previous run id (with --offline)")
    r.add_argument("--evidence", default="evidence")
    r.add_argument("--out", default="out")
    r.add_argument("--prefill", default=os.environ.get("TPRM_TOOL_XLSX"),
                   help="path to Third Parties Risk Evaluation Tool v2.0.xlsx "
                        "(defaults to TPRM_TOOL_XLSX, which .env can set)")
    r.add_argument("--write-answers", action="store_true",
                   help="also write YES into the answer column (default: suggestions only)")
    r.set_defaults(func=run)

    g = sub.add_parser("guard", help="test the passive policy against a URL")
    g.add_argument("--url", required=True)
    g.set_defaults(func=guard)

    c = sub.add_parser("coverage", help="print the driver coverage table")
    c.set_defaults(func=coverage)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
