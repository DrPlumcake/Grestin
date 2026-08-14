"""Passive HTTP client.

The methodological claim of the thesis is that the layer never touches the
supplier's infrastructure. This module is what makes that claim *enforced by
the code* rather than entrusted to the author's memory, which is the difference
between an assertion and a verifiable property.

Three mechanisms, in this order:

  1. An explicit DENYLIST of endpoints that would be active reconnaissance,
     each carrying the reason it is excluded. Checked first, so a future
     refactor that widens the allowlist cannot silently re-admit them.
  2. An ALLOWLIST of URL prefixes. Anything not prefixed by one of them raises
     ActiveScanBlocked. New tool -> conscious edit here.
  3. Structural constraints: https only, GET only, no credentials in the URL,
     no automatic redirect following (a 3xx Location is re-checked against the
     guard before it is followed).

Everything that goes over the wire is also written to the evidence store
(sha256-addressed), which gives the report a chain of custody and makes
`--offline` replay possible: findings can be recomputed from disk with the
network unplugged, which is how the demo is derisked.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .models import utcnow

# --------------------------------------------------------------------------
# 1. Endpoints that are active reconnaissance. Never callable.
#    The value is the reason, printed in the exception and quoted in Ch. 6.
# --------------------------------------------------------------------------
DENIED: dict[str, str] = {
    "https://api.shodan.io/shodan/scan": (
        "on-demand scan: would actively probe the supplier's hosts"
    ),
    "https://api.ssllabs.com/": (
        "SSL Labs connects directly to the supplier's TLS endpoint"
    ),
    "https://observatory-api.mdn.mozilla.net/": (
        "Mozilla Observatory fetches the supplier's site on our behalf"
    ),
    "https://api.hackertarget.com/": "runs live port scans and DNS brute force",
    "https://urlscan.io/liveshot/": "renders the supplier's page on request",
}

# --------------------------------------------------------------------------
# 2. The passive allowlist. Prefix match, one entry per tool of Chapter 6.
# --------------------------------------------------------------------------
ALLOWED: tuple[str, ...] = (
    # technical pillar
    "https://crt.sh/",                                  # certificate transparency
    "https://internetdb.shodan.io/",                    # free host lookup
    "https://cvedb.shodan.io/",                          # CVE metadata
    "https://api.shodan.io/shodan/host/",                # host LOOKUP, not scan
    "https://services.nvd.nist.gov/rest/json/cves/",     # NVD
    "https://services.nvd.nist.gov/rest/json/cvehistory/",
    "https://api.first.org/data/v1/epss",                # EPSS
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",  # KEV
    # corporate pillar
    "https://api.opensanctions.org/",
    # incident pillar
    "https://api.ransomware.live/",
)


#: Query parameters that carry a credential. They are stripped before a URL is
#: used as an evidence key, so no API key ever reaches evidence/index.jsonl,
#: the finding records, or the appendix of the thesis. Two consequences worth
#: stating in Chapter 6: the stored artefact is publishable as-is, and rotating
#: a key does not invalidate the cache, because the cache key never contained it.
SECRET_PARAMS = ("key", "api_key", "apikey", "token", "access_token")


def redact(url: str) -> str:
    """Return `url` with any credential query parameter replaced by REDACTED."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    query = [(k, "REDACTED" if k.lower() in SECRET_PARAMS else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query), parts.fragment))


class ActiveScanBlocked(Exception):
    """Raised when an endpoint violates the passive-reconnaissance policy."""


class CacheMiss(Exception):
    """Raised in offline mode when a request is not in the evidence store."""


def assert_passive(url: str, method: str = "GET") -> None:
    """Gatekeeper. Raises ActiveScanBlocked unless the request is passive.

    Kept as a module-level function (not a method) so the test suite can
    exercise the policy without instantiating a client:

        with pytest.raises(ActiveScanBlocked):
            assert_passive("https://api.shodan.io/shodan/scan?ips=1.2.3.4")
    """
    if method.upper() != "GET":
        raise ActiveScanBlocked(f"only GET is passive; {method} refused for {url}")

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ActiveScanBlocked(f"non-https endpoint refused: {url}")
    if parts.username or parts.password:
        raise ActiveScanBlocked("credentials in URL refused")
    if ".." in parts.path:
        raise ActiveScanBlocked(f"path traversal refused: {url}")

    normalised = f"https://{parts.netloc.lower()}{parts.path}"
    for denied, reason in DENIED.items():
        if normalised.startswith(denied):
            raise ActiveScanBlocked(f"explicitly excluded ({reason}): {url}")

    if not normalised.startswith(ALLOWED):
        raise ActiveScanBlocked(
            f"endpoint not permitted by the passive policy: {url}\n"
            f"Add it to ALLOWED in http.py only after checking it does not touch the target."
        )


@dataclass(slots=True)
class EvidenceRecord:
    """One stored response. `sha256` is what a Finding references."""

    sha256: str
    url: str
    status: int
    retrieved_at: str
    path: str
    from_cache: bool = False


class EvidenceStore:
    """sha256-addressed store of raw responses + append-only index.

    The index (`index.jsonl`) is the appendix of the thesis: for every
    assertion in the Risk Assessment Report there is a line saying which URL
    was queried, when, and where the bytes are.
    """

    def __init__(self, root: str | Path = "evidence", run_id: str | None = None) -> None:
        self.root = Path(root)
        self.run_id = run_id or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.dir = self.root / self.run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / "index.jsonl"

    @staticmethod
    def key(url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()

    def blob_path(self, url: str) -> Path:
        return self.dir / f"{self.key(url)}.json"

    def lookup(self, url: str) -> dict[str, Any] | None:
        """Look for this URL in the current run, then in any previous run."""
        candidates = [self.blob_path(url)]
        candidates += sorted(self.root.glob(f"*/{self.key(url)}.json"), reverse=True)
        for p in candidates:
            if p.exists():
                with p.open(encoding="utf-8") as fh:
                    return json.load(fh)
        return None

    def store(self, url: str, status: int, body: Any, headers: dict[str, str]) -> EvidenceRecord:
        record = {
            "url": url,
            "status": status,
            "retrieved_at": utcnow(),
            "headers": {k.lower(): v for k, v in headers.items() if k.lower() in
                        ("content-type", "date", "last-modified", "x-ratelimit-remaining")},
            "body": body,
        }
        path = self.blob_path(url)
        path.write_text(json.dumps(record, ensure_ascii=False, indent=1), encoding="utf-8")
        with self.index_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "sha256": self.key(url),
                "url": url,
                "status": status,
                "retrieved_at": record["retrieved_at"],
            }, ensure_ascii=False) + "\n")
        return EvidenceRecord(self.key(url), url, status, record["retrieved_at"], str(path))


class PassiveClient:
    """The only way this project is allowed to reach the network.

    Parameters
    ----------
    offline : replay only. Any URL absent from the store raises CacheMiss, so
        a demo can be rehearsed and a run can be reproduced byte-for-byte.
    min_interval : per-host politeness delay in seconds (crt.sh in particular
        deserves it; it is a free public service).
    """

    DEFAULT_INTERVALS = {
        "crt.sh": 2.0,                 # free public service, deserves the courtesy
        "api.shodan.io": 1.1,          # documented 1 request/second limit
        "internetdb.shodan.io": 0.5,
        "api.opensanctions.org": 1.0,
    }

    def __init__(
        self,
        evidence: EvidenceStore | None = None,
        offline: bool = False,
        timeout: float = 30.0,
        max_retries: int = 3,
        min_interval: float = 0.5,
        user_agent: str = "grestin/0.1 (academic research; passive OSINT only)",
        stats: Any | None = None,
    ) -> None:
        self.evidence = evidence or EvidenceStore()
        self.offline = offline
        self.timeout = timeout
        self.max_retries = max_retries
        self.min_interval = min_interval
        self.stats = stats
        self._last_call: dict[str, float] = {}
        self._client = None if offline else httpx.Client(
            timeout=timeout,
            follow_redirects=False,          # redirects are re-checked by hand
            headers={"User-Agent": user_agent, "Accept": "application/json"},
        )

    # -- internals ---------------------------------------------------------
    def _throttle(self, host: str) -> None:
        interval = self.DEFAULT_INTERVALS.get(host, self.min_interval)
        last = self._last_call.get(host)
        if last is not None:
            wait = interval - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
        self._last_call[host] = time.monotonic()

    def _count(self, key: str) -> None:
        if self.stats is not None:
            self.stats.http[key] = self.stats.http.get(key, 0) + 1

    # -- public API --------------------------------------------------------
    def get_json(
        self,
        url: str,
        *,
        api_key_header: tuple[str, str] | None = None,
        use_cache: bool = True,
        expect_json: bool = True,
    ) -> tuple[Any, EvidenceRecord]:
        """Passive GET returning ``(body, evidence_record)``.

        Raises ActiveScanBlocked before any socket is opened, CacheMiss in
        offline mode, and httpx.HTTPStatusError after exhausting retries.
        """
        assert_passive(url, "GET")
        key_url = redact(url)          # what the evidence store sees

        if use_cache:
            cached = self.evidence.lookup(key_url)
            if cached is not None:
                self._count("cache_hits")
                return cached["body"], EvidenceRecord(
                    EvidenceStore.key(key_url), key_url, cached["status"],
                    cached["retrieved_at"], str(self.evidence.blob_path(key_url)),
                    from_cache=True,
                )

        if self.offline:
            raise CacheMiss(f"offline mode and no stored evidence for {key_url}")

        host = urlsplit(url).netloc.lower()
        last_exc: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            self._throttle(host)
            t0 = time.monotonic()
            try:
                headers = {}
                if api_key_header:
                    headers[api_key_header[0]] = api_key_header[1]
                resp = self._client.get(url, headers=headers)
                self._count("requests")
                if self.stats is not None:
                    self.stats.timing(f"http:{host}", int((time.monotonic() - t0) * 1000))

                # redirects: never followed blindly
                if resp.is_redirect:
                    location = str(resp.headers.get("location", ""))
                    target = str(httpx.URL(url).join(location))
                    assert_passive(target, "GET")   # may raise: that is the point
                    self._count("redirects")
                    url = target
                    key_url = redact(url)
                    continue

                if resp.status_code in (429, 500, 502, 503, 504):
                    self._count(f"status_{resp.status_code}")
                    retry_after = float(resp.headers.get("retry-after", 0) or 0)
                    time.sleep(max(retry_after, 2.0 ** attempt))
                    last_exc = httpx.HTTPStatusError(
                        f"{resp.status_code} from {host}", request=resp.request, response=resp
                    )
                    continue

                resp.raise_for_status()
                body = resp.json() if expect_json else resp.text
                record = self.evidence.store(key_url, resp.status_code, body,
                                             dict(resp.headers))
                return body, record

            except (httpx.TransportError, json.JSONDecodeError, ValueError) as exc:
                self._count("transport_errors")
                last_exc = exc
                time.sleep(2.0 ** attempt)

        assert last_exc is not None
        self._count("failures")
        raise last_exc

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> PassiveClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def api_key(env_var: str) -> str | None:
    """Read an API key from the environment. Never hard-code one in the repo."""
    return os.environ.get(env_var) or None
