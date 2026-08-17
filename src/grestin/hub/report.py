"""Risk Assessment Report generator (Markdown; HTML/PDF via pandoc if wanted).

The report is the artefact the Security function already owes to the process
(see the TPRM procedure, section 5), so the layer produces it in the shape that
process expects: what was observed, how strong the signal is, which driver it
bears on, which control it operationalises, and what is being asked of whom.

Deliberately blunt about limits: a section at the end lists the drivers the
layer cannot see, so the reader is never left thinking silence means safety.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment

from ..config import Config
from ..models import Target, Verdict
from .scoring import ScoreSummary

TEMPLATE = """# Risk Assessment Report - CTI layer (Phase 1 support)

**Third party:** {{ target.legal_name }}{{ ' (' ~ target.country ~ ')' if target.country else '' }}

**Domains in scope:** {{ target.domains | join(', ') }}
**Run id:** `{{ run_id }}`  **Generated:** {{ generated_at }}
**Method:** passive OSINT only - no active scanning was performed against the third party.
{% if stats %}
**Run integrity:** {{ stats.integrity | upper }}
{% if stats.integrity != 'complete' %}
> **This run is incomplete.** Stage(s) {{ stats.failed_stages | join(', ') }} failed or
> returned partial data. Findings are missing because collection did not complete, not
> because the third party has nothing to find. No conclusion may be drawn about the
> affected pillar until the run is repeated.
>
> | Stage | Status | Raws | Findings | Errors |
> |---|---|---|---|---|
{% for name, st in stats.stages.items() %}
> | {{ name }} | {{ st.status }} | {{ st.raws }} | {{ st.findings }} | {{ st.errors }} |
{% endfor %}
{% endif %}
{% endif %}

## 1. Executive summary

The passive layer can independently inform **{{ '%.0f' % (summary.addressable_weight * 100) }}%**
of the inherent-risk weight of the Phase 1 matrix ({{ summary.verdicts | length }} drivers,
of which {{ observable_count }} are CTI-observable). In this run it proposes
**YES on {{ summary.suggest_yes | length }}** driver(s)
({{ '%.0f' % (summary.suggested_weight * 100) }}% of weight) and flags
**{{ summary.review | length }}** for human adjudication
({{ '%.0f' % (summary.review_weight * 100) }}%).
{% if projection %}
| | Score | Level |
|---|---|---|
| Declared answers only | {{ '%.0f' % (projection.declared_score * 100) }}% | {{ projection.declared_level }} |
| Projection with CTI signals accepted | {{ '%.0f' % (projection.projected_score * 100) }}% | {{ projection.projected_level }} |
| Delta introduced by the CTI layer | {{ '%+.0f' % (projection.delta * 100) }}% | |
{% if projection.crosses_phase2_threshold %}
> **The projection crosses the Phase 2 threshold.** On the declared answers alone this
> supplier would not have received the in-depth cyber assessment.
{% endif %}
{% endif %}
{% if summary.corroborations %}
### Cross-pillar corroboration
{% for c in summary.corroborations %}
- **{{ c.driver }}**: {{ c.pillars | join(' + ') }} - {{ c.finding_types | join(', ') }}
{% endfor %}
{% endif %}

## 2. Proposed driver answers

| Driver | Weight | Verdict | Max strength | Basis |
|---|---|---|---|---|
{% for v in summary.verdicts if v.findings -%}
| {{ v.driver_name }} | {{ '%.2f' % v.weight if v.weight else 'variable' }} | {{ v.verdict.value }} | {{ v.max_strength.value if v.max_strength else '-' }} | {{ v.rationale }} |
{% endfor %}

Verdict semantics: **SUGGEST_YES** = the layer has evidence sufficient to put the
question to the supplier as a finding; **REVIEW** = a signal exists but requires
human adjudication; **NOT_OBSERVABLE** = nothing was seen. NOT_OBSERVABLE is
never to be read as NO.

## 3. Findings

{% for v in summary.verdicts if v.findings %}
### {{ v.driver_name }} ({{ v.verdict.value }})

{% for f in v.findings %}
**{{ loop.index }}. `{{ f.type }}`** - source: {{ f.source.value }} | strength: **{{ f.signal_strength.value }}** | follow-up: {{ f.needs_followup.value }}
- Subject: `{{ f.subject }}`
- Controls: {{ f.controls | join(', ') }}
- Observed: {{ f.observed_at }}{{ ' | evidence: `' ~ f.evidence_refs[0][:16] ~ '...`' if f.evidence_refs else '' }}
{% if f.note %}
- Note: {{ f.note }}
{% endif %}
```json
{{ f.evidence | tojson(indent=2) }}
```
{% endfor %}
{% endfor %}

## 4. What this layer cannot see

The following weighted drivers are not observable by passive OSINT and remain
entirely with the declaring functions and with Phase 2:

| Driver | Weight | Why not observable |
|---|---|---|
{% for v in summary.verdicts if not v.findings -%}
{% if v.driver_id in non_observable -%}
| {{ v.driver_name }} | {{ '%.2f' % v.weight if v.weight else 'variable' }} | {{ non_observable[v.driver_id] }} |
{% endif -%}
{% endfor %}

## 5. Requests arising from this run

{% for v in summary.verdicts if v.verdict.value in ('SUGGEST_YES', 'REVIEW') %}
{% for f in v.findings if f.needs_followup.value == 'human_review' -%}
- **{{ v.driver_name }}** / `{{ f.type }}` on `{{ f.subject }}`: request a written
  explanation from the supplier and, where the driver is a legal one, referral to
  {% if v.driver_id in ('golden_power', 'ownership_due_diligence') %}Legal{% else %}Security{% endif %}.
{% endfor -%}
{% endfor %}

## 6. Provenance

Every assertion above is backed by a stored response in
`evidence/{{ run_id }}/`, indexed in `index.jsonl` (URL, HTTP status, retrieval
timestamp, sha256 of the body). The run is reproducible offline with
`grestin run --offline --run-id {{ run_id }}`.
"""


def render(target: Target, summary: ScoreSummary, config: Config, run_id: str,
           generated_at: str, projection: dict[str, Any] | None = None,
           stats: Any | None = None) -> str:
    env = Environment(trim_blocks=True, lstrip_blocks=True)
    non_observable = {
        d.id: (d.cti_note.strip().split("\n")[0] if d.cti_note else "not observable")
        for d in config.drivers.values() if not d.cti_observable
    }
    return env.from_string(TEMPLATE).render(
        target=target,
        summary=summary,
        config=config,
        run_id=run_id,
        generated_at=generated_at,
        projection=projection,
        stats=stats,
        observable_count=len([d for d in config.drivers.values() if d.cti_observable]),
        non_observable=non_observable,
        Verdict=Verdict,
    )


def write(path: str | Path, content: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p
