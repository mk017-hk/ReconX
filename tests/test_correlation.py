"""
Tests for reconx.utils.correlation — asset correlation layer.
"""

import pytest
from reconx.utils.correlation import correlate, _classify_host_role, CorrelationResult
from reconx.core.severity import Finding, Severity


# ─────────────────────────────────────────────────────────────
# Host role classification
# ─────────────────────────────────────────────────────────────

class TestClassifyHostRole:
    def test_api(self):
        assert _classify_host_role("api.example.com") == "api"

    def test_graphql(self):
        assert _classify_host_role("graphql.example.com") == "api"

    def test_admin(self):
        assert _classify_host_role("admin.example.com") == "admin"

    def test_portal(self):
        assert _classify_host_role("portal.example.com") == "admin"

    def test_staging(self):
        assert _classify_host_role("staging.example.com") == "staging"

    def test_uat(self):
        assert _classify_host_role("uat.example.com") == "staging"

    def test_dev(self):
        assert _classify_host_role("dev.example.com") == "dev"

    def test_cdn(self):
        assert _classify_host_role("cdn.example.com") == "cdn"

    def test_static(self):
        assert _classify_host_role("static.example.com") == "cdn"

    def test_mail(self):
        assert _classify_host_role("mail.example.com") == "mail"

    def test_vpn(self):
        assert _classify_host_role("vpn.example.com") == "vpn"

    def test_www_is_prod(self):
        assert _classify_host_role("www.example.com") == "prod"

    def test_app_is_prod(self):
        assert _classify_host_role("app.example.com") == "prod"

    def test_unknown(self):
        assert _classify_host_role("unrecognised.example.com") == "unknown"

    def test_case_insensitive(self):
        assert _classify_host_role("ADMIN.example.com") == "admin"


# ─────────────────────────────────────────────────────────────
# correlate() — basic result structure
# ─────────────────────────────────────────────────────────────

def _make_subdomain(name: str, ips: list[str] = None):
    """Return a minimal Subdomain-like object."""
    class Sub:
        pass
    s = Sub()
    s.name = name
    s.ips = ips or []
    return s


def test_correlate_returns_result_type():
    result = correlate({"target": "example.com"})
    assert isinstance(result, CorrelationResult)


def test_correlate_target_added_to_hostnames():
    result = correlate({"target": "example.com"})
    assert "example.com" in result.all_hostnames


def test_correlate_classifies_target_role():
    result = correlate({"target": "example.com"})
    assert "example.com" in result.host_roles


def test_correlate_empty_collected_no_crash():
    result = correlate({})
    assert result.all_hostnames == []
    assert result.correlated_findings == []


# ─────────────────────────────────────────────────────────────
# SSL SAN cross-reference
# ─────────────────────────────────────────────────────────────

def _ssl_data_with_san(san: list[str]):
    class Cert:
        pass
    c = Cert()
    c.san = san

    class SSL:
        pass
    s = SSL()
    s.cert = c
    return s


def test_ssl_confirmed_subdomain():
    ssl = _ssl_data_with_san(["example.com", "api.example.com"])

    class Sub:
        name = "api.example.com"
        ips = ["1.2.3.4"]

    class SubResult:
        subdomains = [Sub()]

    result = correlate({
        "target": "example.com",
        "ssl": ssl,
        "subdomains": SubResult(),
    })
    assert "api.example.com" in result.ssl_confirmed_subdomains
    assert "api.example.com" not in result.subdomains_not_in_san


def test_subdomain_not_in_san():
    # SAN only covers api.example.com — shadow.example.com is NOT in it
    ssl = _ssl_data_with_san(["api.example.com"])

    class Sub:
        name = "shadow.example.com"
        ips = ["5.6.7.8"]

    class SubResult:
        subdomains = [Sub()]

    result = correlate({
        "target": "example.com",
        "ssl": ssl,
        "subdomains": SubResult(),
    })
    assert "shadow.example.com" in result.subdomains_not_in_san


def test_wildcard_san_confirms_subdomain():
    ssl = _ssl_data_with_san(["*.example.com"])

    class Sub:
        name = "anything.example.com"
        ips = ["1.2.3.4"]

    class SubResult:
        subdomains = [Sub()]

    result = correlate({
        "target": "example.com",
        "ssl": ssl,
        "subdomains": SubResult(),
    })
    assert "anything.example.com" in result.ssl_confirmed_subdomains


# ─────────────────────────────────────────────────────────────
# Correlated finding generation
# ─────────────────────────────────────────────────────────────

def test_admin_host_generates_finding():
    # Use admin host as the scan target so it meets the "internet-reachable" condition
    result = correlate({"target": "admin.example.com"})
    titles = [f.title for f in result.correlated_findings]
    assert any("admin" in t.lower() for t in titles)


def test_shadow_subdomain_generates_finding():
    # SAN only covers "api.example.com" — shadow.example.com is not listed
    ssl = _ssl_data_with_san(["api.example.com"])

    class Sub:
        name = "shadow.example.com"
        ips = ["9.9.9.9"]

    class SubResult:
        subdomains = [Sub()]

    result = correlate({
        "target": "example.com",
        "ssl": ssl,
        "subdomains": SubResult(),
    })
    titles = [f.title for f in result.correlated_findings]
    assert any("san" in t.lower() or "ssl" in t.lower() or "subdomains" in t.lower() for t in titles)


def test_staging_alongside_prod_generates_finding():
    class Sub1:
        name = "staging.example.com"
        ips = ["1.1.1.1"]

    class Sub2:
        name = "www.example.com"
        ips = ["2.2.2.2"]

    class SubResult:
        subdomains = [Sub1(), Sub2()]

    result = correlate({
        "target": "example.com",
        "subdomains": SubResult(),
    })
    titles = [f.title for f in result.correlated_findings]
    assert any("staging" in t.lower() or "dev" in t.lower() for t in titles)


# ─────────────────────────────────────────────────────────────
# Finding deduplication
# ─────────────────────────────────────────────────────────────

def test_deduplication_keeps_highest_confidence():
    f1 = Finding(severity=Severity.HIGH, title="Test vuln", module="dns", confidence=60)
    f2 = Finding(severity=Severity.HIGH, title="Test vuln", module="dns", confidence=85)
    result = correlate({"target": "x.com", "_findings": [f1, f2]})
    deduped = result.deduplicated_findings
    # Should keep the higher-confidence one
    assert len(deduped) == 1
    assert deduped[0].confidence == 85


def test_deduplication_different_titles_kept():
    f1 = Finding(severity=Severity.HIGH, title="Finding A", module="http")
    f2 = Finding(severity=Severity.MEDIUM, title="Finding B", module="http")
    result = correlate({"target": "x.com", "_findings": [f1, f2]})
    assert len(result.deduplicated_findings) == 2
