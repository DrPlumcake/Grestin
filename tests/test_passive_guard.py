"""The passivity of the method, as an executable assertion.

This file is the evidence for the sentence in Chapter 6 that says the passive
constraint is enforced by the code. Run it in front of the committee if asked.
"""

import pytest

from grestin.http import ALLOWED, DENIED, ActiveScanBlocked, assert_passive


@pytest.mark.parametrize("url", [
    "https://crt.sh/?q=%25.example.com&output=json",
    "https://internetdb.shodan.io/1.2.3.4",
    "https://api.shodan.io/shodan/host/1.2.3.4?key=REDACTED",
    "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3400",
    "https://api.first.org/data/v1/epss?cve=CVE-2024-3400",
    "https://api.opensanctions.org/match/default",
    "https://api.ransomware.live/v2/victims/example.com",
])
def test_passive_endpoints_allowed(url):
    assert_passive(url)          # must not raise


def test_shodan_scan_is_blocked():
    """The canonical case: same host as an allowed endpoint, different path."""
    with pytest.raises(ActiveScanBlocked) as exc:
        assert_passive("https://api.shodan.io/shodan/scan?ips=1.2.3.4")
    assert "actively probe" in str(exc.value)


@pytest.mark.parametrize("url", [
    "https://api.ssllabs.com/api/v3/analyze?host=example.com",
    "https://observatory-api.mdn.mozilla.net/api/v2/scan?host=example.com",
    "https://api.hackertarget.com/nmap/?q=example.com",
])
def test_named_active_services_are_blocked(url):
    with pytest.raises(ActiveScanBlocked):
        assert_passive(url)


def test_unknown_endpoint_is_blocked_by_default():
    """Fail-closed: a new tool must be added to ALLOWED consciously."""
    with pytest.raises(ActiveScanBlocked):
        assert_passive("https://api.some-new-scanner.io/probe?host=example.com")


def test_non_get_is_blocked():
    with pytest.raises(ActiveScanBlocked):
        assert_passive("https://crt.sh/", method="POST")


def test_the_single_post_exception_is_permitted():
    """OpenSanctions matches on a POST because the query is a structured
    entity. The exception is one prefix wide, and it is tested."""
    assert_passive("https://api.opensanctions.org/match/default", method="POST")


def test_the_post_exception_does_not_widen_to_the_whole_host():
    with pytest.raises(ActiveScanBlocked) as exc:
        assert_passive("https://api.opensanctions.org/entities/NK-x", method="POST")
    assert "POST is only permitted" in str(exc.value)


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD"])
def test_no_other_verb_is_ever_allowed(method):
    with pytest.raises(ActiveScanBlocked):
        assert_passive("https://api.opensanctions.org/match/default", method=method)


def test_denylist_still_wins_over_the_post_exception():
    with pytest.raises(ActiveScanBlocked) as exc:
        assert_passive("https://api.shodan.io/shodan/scan", method="POST")
    assert "actively probe" in str(exc.value)


def test_plain_http_is_blocked():
    with pytest.raises(ActiveScanBlocked):
        assert_passive("http://crt.sh/?q=example.com")


def test_path_traversal_cannot_escape_an_allowed_prefix():
    with pytest.raises(ActiveScanBlocked):
        assert_passive("https://api.shodan.io/shodan/host/../scan?ips=1.2.3.4")


def test_credentials_in_url_blocked():
    with pytest.raises(ActiveScanBlocked):
        assert_passive("https://user:pw@crt.sh/?q=example.com")


def test_case_insensitive_host_still_matched():
    assert_passive("https://CRT.SH/?q=example.com")


def test_every_denied_entry_has_a_documented_reason():
    """The denylist is also thesis text: no silent exclusions."""
    for endpoint, reason in DENIED.items():
        assert endpoint.startswith("https://")
        assert len(reason) > 20, endpoint


def test_allowlist_has_one_entry_per_declared_tool():
    joined = " ".join(ALLOWED)
    for marker in ("crt.sh", "shodan", "nvd.nist.gov", "first.org",
                   "cisa.gov", "opensanctions", "ransomware.live"):
        assert marker in joined, f"{marker} missing from the passive allowlist"
