"""Corporate pillar: sanctions, PEP and ownership screening via OpenSanctions.

Independent of the technical chain by design. It starts from the legal name,
not from a domain, so it observes something the technical pillar structurally
cannot: who ultimately controls the counterparty. Two drivers:

    ownership_due_diligence  0.10   sanctions / PEP / adverse media / opaque control
    golden_power             0.05   secondary, weak - the FOCI element only

WHY THIS PILLAR IS THE MOST DANGEROUS ONE

A name is not an identity. "Acme Ltd" matches dozens of unrelated entities, and
a false positive here is not an inconvenience: it is an accusation against a
company, with contractual and reputational consequences, produced by software.
So the rules are stricter than anywhere else in the project:

  * `strong` requires an identifier match (registration number, tax number,
    LEI, IMO...), never a name similarity, however high the score. The API's
    own `match: true` flag is necessary but not sufficient.
  * everything else is `moderate` at most, and *every* finding of this pillar
    carries `human_review` - the mapping enforces it - because the adjudication
    belongs to Legal, not to an analyst and certainly not to a script.
  * the finding never states that the supplier is sanctioned. It states that a
    screening returned a candidate requiring adjudication, and it records the
    score, the dataset and the entity id so the reviewer can go and look.

OWNERSHIP TRAVERSAL

From a matched company the collector walks the ownership graph up to
`max_depth` hops, looking for controlling entities registered outside the EEA.
It is bounded on purpose: the graph is wide, the API is rate limited, and past
two hops the analytical value collapses while the false-attribution risk grows.
An incomplete chain is reported as incomplete rather than as an absence.

CREDENTIALS

OpenSanctions authenticates with an `Authorization` header, not a query
parameter, so the key never appears in a URL and therefore never in the
evidence index. The `/match/` endpoint is a POST - the one exception in
`http.POST_ALLOWED`, and the reasoning is documented there.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ...http import api_key
from ...models import Finding, Pillar, Raw, SignalStrength, Source, Target
from ..base import BaseCollector

MATCH = "https://api.opensanctions.org/match/{scope}"
ENTITY = "https://api.opensanctions.org/entities/{entity_id}"

#: OpenSanctions topic codes -> what they mean for our drivers.
TOPIC_SANCTION = ("sanction", "sanction.linked", "export.control", "debarment")
TOPIC_PEP = ("role.pep", "role.rca")
TOPIC_ADVERSE = ("crime", "crime.fin", "crime.war", "crime.theft", "poi",
                 "reg.warn", "reg.action", "wanted",
                 # `export.risk` marks entities flagged for business in
                 # sanctioned jurisdictions without themselves being listed.
                 # Encountered on a real run against a major EU vendor, where
                 # it was the only topic returned: without it the pillar
                 # produced no finding at all on a genuinely relevant listing.
                 "export.risk", "sanction.counter")

#: Identifier properties that make a match an identity rather than a name.
IDENTIFIER_PROPS = ("registrationNumber", "taxNumber", "leiCode", "vatCode",
                    "innCode", "ogrnCode", "swiftBic")


class OpenSanctionsCollector(BaseCollector):
    name = "opensanctions"
    pillar = Pillar.CORPORATE

    def __init__(self, client, config, stats=None, scope: str = "default",
                 max_depth: int = 2, max_results: int = 5) -> None:
        super().__init__(client, config, stats)
        self.scope = scope
        self.max_depth = max_depth
        self.max_results = max_results
        self.key = api_key("OPENSANCTIONS_API_KEY")

    # -- helpers -----------------------------------------------------------
    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"ApiKey {self.key}"} if self.key else {}

    @staticmethod
    def _props(entity: dict[str, Any]) -> dict[str, list[Any]]:
        return entity.get("properties", {}) or {}

    @classmethod
    def _countries(cls, entity: dict[str, Any]) -> list[str]:
        props = cls._props(entity)
        values = (props.get("country", []) or []) + (props.get("jurisdiction", []) or [])
        return sorted({str(v).upper()[:2] for v in values if v})

    @classmethod
    def _topics(cls, entity: dict[str, Any]) -> list[str]:
        return [str(t) for t in cls._props(entity).get("topics", []) or []]

    @classmethod
    def _has_identifier_match(cls, entity: dict[str, Any], target: Target) -> bool:
        """True only if the candidate shares a registration identifier with what
        we know about the counterparty. Deliberately conservative: with no
        identifier on our side, this is always False and `strong` is
        unreachable, which is the correct outcome for a name-only screening."""
        known = {str(v).replace(" ", "").upper()
                 for v in (target.identifiers or {}).values() if v}
        if not known:
            return False
        props = cls._props(entity)
        for prop in IDENTIFIER_PROPS:
            for value in props.get(prop, []) or []:
                if str(value).replace(" ", "").upper() in known:
                    return True
        return False

    def _lookup_entity(self, entity_id: str) -> dict[str, Any] | None:
        try:
            body, _ = self.client.get_json(ENTITY.format(entity_id=entity_id),
                                           api_key_header=(
                                               ("Authorization", f"ApiKey {self.key}")
                                               if self.key else None))
            return body
        except Exception as exc:                     # noqa: BLE001 - recorded, not fatal
            self.bump("entity_lookup_errors")
            if self.stats is not None:
                self.stats.errors.append(
                    f"opensanctions entity {entity_id}: {type(exc).__name__}: {exc}")
            return None

    # -- collect -----------------------------------------------------------
    def collect(self, target: Target) -> list[Raw]:
        if not self.key and not self.client.offline:
            self.bump("skipped_no_api_key")
            if self.stats is not None:
                self.stats.errors.append(
                    "opensanctions: no OPENSANCTIONS_API_KEY, corporate pillar skipped")
            return []

        query: dict[str, Any] = {
            "schema": "Company",
            "properties": {"name": [target.legal_name] + list(target.aliases)},
        }
        if target.country:
            query["properties"]["country"] = [target.country]
        for prop, value in (target.identifiers or {}).items():
            query["properties"].setdefault(prop, []).append(value)

        payload = {"queries": {"q1": query}}
        try:
            body, ev = self.client.post_json(MATCH.format(scope=self.scope), payload,
                                             headers=self._headers)
        except Exception as exc:                     # noqa: BLE001
            self.bump("match_errors")
            if self.stats is not None:
                self.stats.errors.append(f"opensanctions match: {type(exc).__name__}: {exc}")
            return []

        results = (((body or {}).get("responses", {}) or {})
                   .get("q1", {}) or {}).get("results", []) or []
        results = results[: self.max_results]
        self.bump("candidates", len(results))

        raws = [Raw(source=Source.OPENSANCTIONS, kind="match_results",
                    subject=target.legal_name,
                    payload={"query": query, "results": results},
                    evidence_ref=ev.sha256)]

        # bounded walk up the ownership graph from each candidate company
        for result in results:
            chain = self._walk_ownership(result)
            if chain:
                raws.append(Raw(source=Source.OPENSANCTIONS, kind="ownership_chain",
                                subject=result.get("caption", result.get("id", "?")),
                                payload={"root_id": result.get("id"), "chain": chain}))
        return raws

    def _walk_ownership(self, entity: dict[str, Any]) -> list[dict[str, Any]]:
        """Follow `ownershipAsset` links upwards, at most `max_depth` hops."""
        chain: list[dict[str, Any]] = []
        seen: set[str] = set()
        frontier = [(entity, 0)]

        while frontier:
            current, depth = frontier.pop(0)
            if depth >= self.max_depth:
                continue
            for link in self._props(current).get("ownershipAsset", []) or []:
                owner = (link.get("properties", {}) or {}).get("owner", [{}])
                owner = owner[0] if owner else {}
                if isinstance(owner, str):
                    owner = self._lookup_entity(owner) or {}
                owner_id = owner.get("id")
                if not owner_id or owner_id in seen:
                    continue
                seen.add(owner_id)
                self.bump("ownership_hops")
                chain.append({
                    "depth": depth + 1,
                    "owner_id": owner_id,
                    "owner": owner.get("caption"),
                    "countries": self._countries(owner),
                    "topics": self._topics(owner),
                    "percentage": (link.get("properties", {}) or {}).get("percentage", []),
                })
                frontier.append((owner, depth + 1))
        return chain

    # -- analyze (pure) ----------------------------------------------------
    def analyze(self, raws: Sequence[Raw], target: Target) -> list[Finding]:
        eea = set(self.config.patterns["eea_countries"])
        adequacy = set(self.config.patterns["adequacy_countries"])
        floor = float(self.config.threshold("fuzzy_name_score"))
        findings: list[Finding] = []

        for raw in raws:
            if raw.kind != "match_results":
                continue
            for result in raw.payload["results"]:
                score = float(result.get("score", 0) or 0)
                if score < floor:
                    self.bump("candidates_below_threshold")
                    continue

                topics = self._topics(result)
                base = {
                    "entity_id": result.get("id"),
                    "caption": result.get("caption"),
                    "schema": result.get("schema"),
                    "score": round(score, 3),
                    "api_match_flag": bool(result.get("match")),
                    "datasets": result.get("datasets", []),
                    "countries": self._countries(result),
                    "topics": topics,
                    "queried_name": target.legal_name,
                    "limitation": (
                        "a screening candidate, not an identification: name similarity "
                        "does not establish that this entity is the counterparty. "
                        "Adjudication belongs to Legal."
                    ),
                }

                if any(t in topics for t in TOPIC_SANCTION):
                    identified = (result.get("match") is True
                                  and self._has_identifier_match(result, target))
                    self.bump("sanction_candidates")
                    findings.append(self.config.make_finding(
                        type="sanctions_match_exact" if identified else "sanctions_match_fuzzy",
                        source=Source.OPENSANCTIONS,
                        subject=f"{result.get('caption')} ({result.get('id')})",
                        evidence=base | {"identifier_match": identified},
                        strength=(SignalStrength.STRONG if identified
                                  else SignalStrength.MODERATE),
                        note=("identifier match: the candidate shares a registration "
                              "identifier with the counterparty"
                              if identified else
                              "name similarity only: no shared registration identifier, "
                              "so the candidate cannot be treated as identified"),
                    ))
                elif any(t in topics for t in TOPIC_PEP):
                    self.bump("pep_candidates")
                    findings.append(self.config.make_finding(
                        type="pep_match", source=Source.OPENSANCTIONS,
                        subject=f"{result.get('caption')} ({result.get('id')})",
                        evidence=base, strength=SignalStrength.MODERATE,
                        note="politically exposed person or related entity in the "
                             "ownership or management of the candidate",
                    ))
                elif any(t in topics for t in TOPIC_ADVERSE):
                    self.bump("adverse_candidates")
                    findings.append(self.config.make_finding(
                        type="adverse_media_match", source=Source.OPENSANCTIONS,
                        subject=f"{result.get('caption')} ({result.get('id')})",
                        evidence=base, strength=SignalStrength.WEAK,
                        note="adverse listing (criminal, regulatory or interest); "
                             "context for the file, not a conclusion",
                    ))

        # ownership: one finding per non-EEA controlling entity found
        for raw in raws:
            if raw.kind != "ownership_chain":
                continue
            for hop in raw.payload["chain"]:
                outside = [c for c in hop["countries"] if c not in eea and c not in adequacy]
                if not outside:
                    continue
                self.bump("extra_eu_owners")
                evidence = {
                    "controlled_entity": raw.subject,
                    "owner": hop["owner"],
                    "owner_id": hop["owner_id"],
                    "jurisdictions": outside,
                    "depth": hop["depth"],
                    "percentage": hop["percentage"],
                    "traversal_depth_limit": self.max_depth,
                    "limitation": (
                        "the ownership graph is walked to a bounded depth; an "
                        "incomplete chain is not evidence that no further control exists"
                    ),
                }
                findings.append(self.config.make_finding(
                    type="extra_eu_ownership_chain", source=Source.OPENSANCTIONS,
                    subject=f"{hop['owner']} -> {raw.subject}",
                    evidence=evidence, strength=SignalStrength.MODERATE,
                    note="control exercised from outside the EEA and outside an "
                         "adequacy decision",
                ))
                findings.append(self.config.make_finding(
                    type="golden_power_indicator", source=Source.OPENSANCTIONS,
                    subject=f"{hop['owner']} ({', '.join(outside)})",
                    evidence=evidence | {
                        "legal_ref": "D.L. 21/2012",
                        "note": "the CTI layer flags the foreign-control element only; "
                                "whether the supply falls within the Golden Power "
                                "perimeter is a legal determination",
                    },
                    strength=SignalStrength.WEAK,
                    note="refer to Legal for the D.L. 21/2012 scope assessment",
                ))

        return findings
