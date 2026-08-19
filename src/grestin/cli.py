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
from .hub.prefill import prefill, read_declared_answers, working_copy
from .hub.scoring import projected_score, score
from .models import RunStats, Target, utcnow
from .pillars.corporate.opensanctions import OpenSanctionsCollector
from .pillars.incident.ransomware_live import RansomwareLiveCollector
from .pillars.technical.crtsh import CrtShCollector
from .pillars.technical.dns import DnsCollector
from .pillars.technical.shodan import ShodanCollector
from .pillars.technical.vulns import VulnsCollector

TECHNICAL_CHAIN = [("crtsh", CrtShCollector), ("dns", DnsCollector),
                   ("shodan", ShodanCollector), ("vulns", VulnsCollector)]
INDEPENDENT = [("opensanctions", OpenSanctionsCollector),
               ("ransomware_live", RansomwareLiveCollector)]


def load_target(path: str | Path) -> Target:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    target = Target.from_dict(data)
    for warning in target.domain_warnings:
        print(f"  [warn] target file: {warning}", file=sys.stderr)
    if not target.domains:
        print("  [warn] no usable domain in the target file: the technical pillar "
              "cannot run", file=sys.stderr)
    return target


#: CLI limit -> collector attribute. Applied after construction so every
#: collector keeps the same three-argument signature.
LIMITS = ("max_hosts", "max_addresses", "max_cves")


def _selected(chain, wanted: set[str] | None):
    return [(n, c) for n, c in chain if wanted is None or n in wanted]


def _status(raws: int, errors: int) -> str:
    """A stage that produced nothing *and* errored has not observed a clean
    supplier: it has failed. Conflating the two is the failure mode this
    function exists to prevent."""
    if raws == 0 and errors:
        return RunStats.FAILED
    if errors:
        return RunStats.DEGRADED
    return RunStats.OK if raws else RunStats.EMPTY


def _tag(status: str) -> str:
    return {RunStats.OK: "ok  ", RunStats.EMPTY: "none",
            RunStats.DEGRADED: "warn", RunStats.FAILED: "FAIL"}.get(status, "skip")


def _why(stage: dict) -> str:
    if stage["status"] == RunStats.FAILED:
        return f"  <-- {stage['errors']} error(s), NO data: not a clean result"
    if stage["status"] == RunStats.DEGRADED:
        return f"  <-- {stage['errors']} error(s), partial data"
    return ""


def run(args: argparse.Namespace) -> int:
    config = Config.load(args.config_dir)
    target = load_target(args.target)
    run_id = args.run_id or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stats = RunStats(run_id=run_id, target=target.legal_name)
    out_dir = Path(args.out) / f"{target.slug}-{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    evidence = EvidenceStore(args.evidence, run_id=run_id)
    findings, raws_all = [], []

    with PassiveClient(evidence=evidence, offline=args.offline, stats=stats,
                       max_retries=args.retries) as client:
        # --- technical pillar: sequential, each stage narrows the next -----
        stages = set(args.stages.split(",")) if args.stages else None
        if stages:
            known = {n for n, _ in TECHNICAL_CHAIN + INDEPENDENT}
            unknown = stages - known
            if unknown:
                print(f"unknown stage(s): {', '.join(sorted(unknown))}; "
                      f"available: {', '.join(sorted(known))}", file=sys.stderr)
                return 2

        handoff: list[str] = []
        for name, cls in _selected(TECHNICAL_CHAIN, stages):
            if cls is None:
                stats.bump(f"{name}.not_implemented")
                stats.record_stage(name, RunStats.NOT_IMPLEMENTED)
                print(f"  [skip] {name}: not implemented yet", file=sys.stderr)
                continue
            if name != "crtsh" and not handoff:
                # No input from upstream. Reporting this as "empty" would be a
                # lie: the stage never got the chance to observe anything.
                upstream_failed = any(
                    v["status"] == RunStats.FAILED for v in stats.stages.values())
                stats.record_stage(name, RunStats.SKIPPED_UPSTREAM if upstream_failed
                                   else RunStats.EMPTY)
                print(f"  [skip] {name}: no input from the previous stage",
                      file=sys.stderr)
                continue
            errors_before = len(stats.errors)
            failures_before = stats.http.get("failures", 0)
            t0 = time.monotonic()
            collector = cls(client, config, stats)
            collector.inputs = handoff          # output of the previous stage
            for limit in LIMITS:                # honour the CLI budget caps
                value = getattr(args, limit, None)
                if value and hasattr(collector, limit):
                    setattr(collector, limit, value)
            raws, fs = collector.run(target)
            stats.timing(f"pillar:{name}", int((time.monotonic() - t0) * 1000))
            raws_all += raws
            findings += fs
            stats.record_stage(name, _status(len(raws), len(stats.errors) - errors_before),
                               len(raws), len(fs), len(stats.errors) - errors_before)
            if raws and not fs and failures_before != stats.http.get("failures", 0):
                # Answered, produced nothing, and lost at least one request on
                # the way. The stage cannot distinguish an endpoint that
                # returned an empty body from one it never reached, so say so
                # instead of letting the summary read as a clean supplier.
                print(f"  [warn] {name}: no observations, and {stats.http.get('failures', 0) - failures_before}"
                      " request(s) failed", file=sys.stderr)
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
            print(f"  [{_tag(stats.stages[name]['status'])}] {name}: "
                  f"{len(raws)} raw, {len(fs)} findings"
                  f"{_why(stats.stages[name])}", file=sys.stderr)

        # --- corporate and incident pillars: independent -------------------
        for name, cls in _selected(INDEPENDENT, stages):
            if cls is None:
                stats.bump(f"{name}.not_implemented")
                stats.record_stage(name, RunStats.NOT_IMPLEMENTED)
                print(f"  [skip] {name}: not implemented yet", file=sys.stderr)
                continue
            t0 = time.monotonic()
            errors_before = len(stats.errors)
            collector = cls(client, config, stats)
            raws, fs = collector.run(target)         # no handoff: independent by design
            stats.timing(f"pillar:{name}", int((time.monotonic() - t0) * 1000))
            raws_all += raws
            findings += fs
            stats.record_stage(name, _status(len(raws), len(stats.errors) - errors_before),
                               len(raws), len(fs), len(stats.errors) - errors_before)
            print(f"  [{_tag(stats.stages[name]['status'])}] {name}: "
                  f"{len(raws)} raw, {len(fs)} findings"
                  f"{_why(stats.stages[name])}", file=sys.stderr)

    # --- hub --------------------------------------------------------------
    summary = score(findings, config)

    # One master template, one persistent working copy per third party.
    template = args.tool or args.prefill
    workbook: Path | None = None
    if template:
        workbook = working_copy(template, args.tool_dir, target.slug, config,
                                fresh=args.fresh_tool,
                                keep_template_answers=args.keep_template_answers)
        print(f"  [ok]   workbook for this third party: {workbook}", file=sys.stderr)

    declared: dict[str, str] = {}
    if args.declared:
        declared = yaml.safe_load(Path(args.declared).read_text(encoding="utf-8")) or {}
    elif workbook:
        # what the compiler has already answered, read from *their* copy
        declared = read_declared_answers(workbook, config)
        print(f"  [ok]   declared answers read from the workbook: {len(declared)}",
              file=sys.stderr)
    projection = projected_score(summary, config, declared)

    (out_dir / "findings.json").write_text(
        json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "raws.json").write_text(
        json.dumps([r.to_dict() for r in raws_all], indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "verdicts.json").write_text(
        json.dumps(summary.to_dict() | {"projection": projection}, indent=2, ensure_ascii=False),
        encoding="utf-8")

    md = report_mod.render(target, summary, config, run_id, utcnow(), projection, stats)
    report_mod.write(out_dir / "risk_assessment_report.md", md)

    if workbook:
        # the compiler's copy is updated in place, so the suggestions are where
        # they will actually be read; the run directory keeps a snapshot
        prefill(workbook, workbook, summary, config, target.legal_name, run_id,
                projection, write_answers=args.write_answers)
        result = prefill(workbook, out_dir / f"{target.slug}_driver_matrix.xlsx",
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

    banner = {"complete": "", "degraded": "  [PARTIAL RUN]",
              "invalid": "  [INCOMPLETE RUN - DO NOT READ AS A CLEAN RESULT]"}
    print(f"\nTarget: {target.legal_name}{banner[stats.integrity]}")
    if stats.integrity != "complete":
        print(f"Integrity: {stats.integrity} - failed or partial stage(s): "
              f"{', '.join(stats.failed_stages)}")
        print("The absence of findings below reflects a failed collection, not the "
              "third party. Re-run before drawing any conclusion.")
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
    r.add_argument("--retries", type=int, default=3,
                   help="HTTP retries per request; raise to 5 or 6 when crt.sh is "
                        "returning 502 (default 3)")
    r.add_argument("--run-id", help="reuse a previous run id (with --offline)")
    r.add_argument("--evidence", default="evidence")
    r.add_argument("--out", default="out")
    r.add_argument("--tool", default=os.environ.get("TPRM_TOOL_XLSX"),
                   help="master Third Parties Risk Evaluation Tool .xlsx used as a "
                        "template (defaults to TPRM_TOOL_XLSX, which .env can set)")
    r.add_argument("--tool-dir", default=os.environ.get("TPRM_TOOL_DIR", "tool/work"),
                   help="where the per-third-party working copies live "
                        "(default tool/work)")
    r.add_argument("--fresh-tool", action="store_true",
                   help="recreate this third party's working copy from the template, "
                        "discarding any answers already given in it")
    r.add_argument("--keep-template-answers", action="store_true",
                   help="do not clear the answer column when creating a working copy")
    r.add_argument("--prefill", help=argparse.SUPPRESS)   # former name of --tool
    r.add_argument("--stages", help="comma-separated subset to run, e.g. "
                                    "'crtsh' to size a surface before spending API quota, "
                                    "or 'crtsh,dns,shodan'")
    r.add_argument("--max-hosts", type=int,
                   help="cap on hostnames resolved by the DNS stage (default 250)")
    r.add_argument("--max-addresses", type=int,
                   help="cap on addresses looked up in Shodan (default 100)")
    r.add_argument("--max-cves", type=int,
                   help="cap on CVEs qualified by the vulnerability stage (default 300)")
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
