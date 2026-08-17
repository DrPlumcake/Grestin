# Grestin

A passive Cyber Threat Intelligence layer that feeds the **Phase 1 driver matrix**
of the 5G TPRM process. Three pillars (technical, corporate, incident) converge on
one hub: the weighted driver questionnaire of the *Third Parties Risk Evaluation
Tool v2.0*.

## Quickstart (Windows / PowerShell)

```powershell
# once: allow local scripts for your user only
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

.\tasks.ps1 install                 # venv + editable install + .env
.\.venv\Scripts\Activate.ps1

# 0. make the Excel tool usable in LibreOffice (once, on the master file)
.\tasks.ps1 fixtool -Tool "C:\path\to\Third Parties Risk Evaluation Tool v2.0.xlsx"

# 1. the passivity policy, enforced by code
.\tasks.ps1 guard
pytest tests\test_passive_guard.py -v

# 2. driver coverage: what the layer can and cannot reach
.\tasks.ps1 coverage

# 3. a full run, replayed from stored evidence (no network, no API keys)
.\tasks.ps1 demo

# 4. the same run, adding the CTI suggestion columns to this supplier's workbook
grestin run --target config\targets_example.yaml --offline --run-id DEMO --tool tool\tprm_tool_lo.xlsx

# 5. live run against a real target
grestin run --target config\targets\supplier.yaml --run-id supplier-01 --max-hosts 60
```

### One template, one workbook per third party

`--tool` points at the **master template**. On the first run for a supplier the
CLI creates `tool/work/<slug>.xlsx`, clearing the answer column so the supplier
does not inherit whatever was last typed into the template, and from then on it
reuses that copy: suggestions are written into it, and the answers the compiler
gives there are read back on the next run as the *declared* baseline. Nothing
to copy by hand.

```powershell
grestin run --target config\targets\italtel.yaml --tool tool\tprm_tool_lo.xlsx
# -> tool\work\italtel-s-p-a.xlsx   (created, answers cleared, suggestions written)
# ... the compiler answers column G in that file ...
grestin run --target config\targets\italtel.yaml --tool tool\tprm_tool_lo.xlsx
# -> declared answers read back; the report shows declared vs projected
```

`--fresh-tool` recreates the working copy from the template.
`--keep-template-answers` keeps the template's answers on creation.
`--tool-dir` moves the directory (or set `TPRM_TOOL_DIR`).

### Useful flags on a real run

| Flag | Why |
|---|---|
| `--stages crtsh` | size the surface before spending API quota |
| `--max-hosts` / `--max-addresses` / `--max-cves` | budget caps (250 / 100 / 300) |
| `--retries 6` | crt.sh returns 502 under load |
| `--offline --run-id X` | replay a previous run from the evidence store |
| `--write-answers` | also fill column G, for the demo; not for deployment |

On macOS or Linux the same commands are `grestin run ...` directly; `tasks.ps1`
is only a convenience wrapper around the CLI.

Outputs land in `out\<slug>-<run_id>\`: `findings.json`, `raws.json`,
`verdicts.json`, `risk_assessment_report.md`, `stats.json`,
`handoff_hosts.json`, and the annotated workbook. Raw HTTP responses live in
`evidence\<run_id>\` with an append-only `index.jsonl`.

## API keys

Keys go in `.env` at the repository root (git-ignored); `cli.main()` loads it
with `python-dotenv`, and `http.api_key("VAR")` reads it. Never put a key in a
YAML file or on the command line.

```
SHODAN_API_KEY=xxxxxxxx
OPENSANCTIONS_API_KEY=xxxxxxxx
```

**crt.sh has no API key and needs none** - it is a public certificate
transparency search with no authentication. The Shodan key raises the host
lookup from the free `internetdb` subset to the full record (geolocation, which
the extra-EU driver needs); without it the run still completes and records in
`stats.json` which stages were degraded.

## LibreOffice

The master workbook computes its score with `_xlfn._xlws.FILTER`, an Excel
dynamic-array function. LibreOffice Calc has no dynamic arrays, so it shows
`#VALUE!` in `Driver Configuration!G2` and `G3` and the tool displays no score
at all. Run `tools/make_libreoffice_safe.py` once: it rewrites those three
formulas as `SUMPRODUCT`/`IF` equivalents that evaluate identically in both
suites (verified: same 0.16 / NOT CRITICAL as Excel's cached value). Work from
the converted file from then on.

## Dependencies

The code imports five packages: `httpx`, `pyyaml`, `jinja2`, `openpyxl`,
`python-dotenv`. Four from the original list were dropped, each for a reason
that is easy to reverse:

| Package | Why it is not there | To bring it back |
|---|---|---|
| `pydantic` | `models.py` uses stdlib dataclasses. `Finding` needs ordinal comparison on `signal_strength` and a custom `__post_init__`, both of which are plainer without a validation framework, and the schema is already pinned by tests. | Swap the dataclasses for `BaseModel`; `to_dict()` becomes `model_dump()`. Half a day, no behavioural gain. |
| `tenacity` | `PassiveClient` retries by hand because it needs to honour `Retry-After`, distinguish 429 from 502, and re-run `assert_passive()` on every redirect. A decorator would hide the guard. | Wrap only the socket call, leaving the guard outside the decorator. |
| `rich` | The CLI prints plain text so that terminal output pastes cleanly into the thesis and into screenshots. | Useful for the live demo: a `rich.table` for `grestin coverage` would look good on a projector. |
| `python-dotenv` | **Kept and wired**: `cli.main()` calls `load_dotenv()`, and `http.api_key()` reads from the environment. | - |

## Handing the project to someone (or something) else

`docs/HANDOFF.md` is a dense onboarding brief: architecture, invariants, state
of play, known traps and working conventions. Point a new collaborator - or a
new assistant session - at that file first.

## Layout

```
config/       drivers.yaml (13 drivers, weights, cells) | mapping.yaml | patterns.yaml
tasks.ps1     PowerShell task runner (install / test / demo / run / fixtool)
src/grestin/
  models.py   Finding (Table 6.1), Raw, Target, DriverVerdict, RunStats
  config.py   loader + the only Finding factory (enforces strength ceilings)
  http.py     PassiveClient: allowlist/denylist guard, cache, evidence store, replay
  pillars/
    base.py                 collect(target)->[Raw] ; analyze(raws)->[Finding]
    technical/crtsh.py      stage 1 (done) -> dns -> shodan -> vulns
    corporate/              opensanctions
    incident/               ransomware_live
  hub/
    scoring.py  findings -> DriverVerdict (rules R1-R3)
    prefill.py  writes verdicts into a copy of the tool + CTI Evidence sheet
    report.py   Risk Assessment Report (Markdown)
  cli.py      run | guard | coverage
tools/        seed_demo_evidence.py | make_libreoffice_safe.py
```

## Four invariants worth defending

1. **Passivity is enforced, not promised.** Every request passes
   `assert_passive()`: https + GET only, an explicit denylist of active
   endpoints (each with its documented reason), then a prefix allowlist. New
   tool = conscious edit. `tests/test_passive_guard.py` is the proof.
2. **The layer never answers NO.** Verdicts are `SUGGEST_YES`, `REVIEW`,
   `NOT_OBSERVABLE`. Absence of passive evidence is not evidence of
   compliance, and the compiler of the tool keeps ownership of every cell.
3. **Strength is capped per finding type** in `mapping.yaml`, so `strong` is
   reachable only at the end of the technical chain (KEV on an exposed
   service), on an exact sanctions identifier match, or on a leak-site listing
   inside the 12-month window. No collector can promote its own output.
4. **`collect` and `analyze` are separated.** `analyze` is pure, so every
   finding is re-derivable from stored evidence with the network unplugged -
   which is both the reproducibility argument and the demo insurance policy.

## Reading and writing the workbook

- Input cells are **`'Supply Risk Drivers'!G5:G17` only**. Column C of
  *Driver Configuration* is derived (`C7` spills `='Supply Risk Drivers'!G7:G17`).
- `'Driver Configuration'!G2` is an array formula using `_xlfn._xlws.FILTER`.
  It survives an openpyxl round-trip, but **never recalculate the output with
  LibreOffice** - it cannot evaluate a spilling array written by openpyxl and
  will bake in `#NAME?`. Excel recalculates correctly on open; for a number
  without Excel, read the `CTI Evidence` sheet, which is formula-free.
- Every G cell carries a data validation list, so a written value must belong
  to the driver's `answer_domain` in `drivers.yaml`.

## Endpoint cheatsheet for the remaining stages

All of these are already in the allowlist; none of them touches the supplier.

| Stage | Endpoint | Notes |
|---|---|---|
| dns | (no HTTP) system resolver, A/AAAA/CNAME | passive-safe; no AXFR, no brute force. Document the resolver used. |
| shodan | `https://internetdb.shodan.io/{ip}` | free, no key; ports, CPEs, hostnames, vulns |
| shodan | `https://api.shodan.io/shodan/host/{ip}?key=$SHODAN_API_KEY` | richer; geolocation for the extra-EU driver |
| cve meta | `https://cvedb.shodan.io/cve/{cve}` | KEV flag, EPSS, CVSS in one call |
| nvd | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}` | 5 req/30s without a key; ask for one |
| kev | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | fetch once per run, cache, then look up locally |
| epss | `https://api.first.org/data/v1/epss?cve={cve1},{cve2}` | batch up to ~100 CVEs per call |
| opensanctions | `https://api.opensanctions.org/match/default` | needs a key; **POST** - see below |
| ransomware.live | `https://api.ransomware.live/v2/searchvictims/{query}` | no key; check the current path before wiring |

> **OpenSanctions and the GET-only rule.** The match endpoint is a POST. Do not
> loosen `assert_passive`: add a narrowly scoped `post_json()` that calls
> `assert_passive(url, "POST")` after adding an explicit
> `POST_ALLOWED = ("https://api.opensanctions.org/match/",)` tuple, and say so
> in the thesis. A POST that submits *our own* query payload to a sanctions
> database is still passive with respect to the supplier; the point of the
> guard is the target, not the verb. Keeping the exception explicit and tested
> is what makes it defensible.

## Statistics produced per run (`stats.json`)

Hosts observed in CT, hosts handed to DNS, how many resolve, hosts with open
ports, CVEs, KEV hits, findings per pillar, verdicts by class, HTTP calls,
cache hits, per-stage timings, errors. This is the material for the evaluation
chapter and for the screenshots.
