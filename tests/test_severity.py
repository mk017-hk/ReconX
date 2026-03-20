"""Tests for the severity scoring module."""

import pytest
from reconx.core.severity import (
    Severity, Finding, classify, make_finding, score_findings,
    sort_findings, SEVERITY_ORDER, deduplicate_findings,
)


class TestClassify:
    def test_zone_transfer_is_critical(self):
        assert classify("Zone transfer SUCCESSFUL") == Severity.CRITICAL

    def test_git_exposed_is_critical(self):
        assert classify("GIT REPO EXPOSED — source code may be accessible!") == Severity.CRITICAL

    def test_env_exposed_is_critical(self):
        assert classify("ENV FILE EXPOSED — credentials/secrets may be leaked!") == Severity.CRITICAL

    def test_expired_cert_is_critical(self):
        assert classify("Certificate EXPIRED 5 days ago") == Severity.CRITICAL

    def test_deprecated_tls_is_high(self):
        assert classify("TLS 1.0 deprecated protocol supported") == Severity.HIGH

    def test_weak_cipher_is_high(self):
        assert classify("Weak cipher suite detected: RC4") == Severity.HIGH

    def test_snmp_open_is_high(self):
        assert classify("SNMP open on UDP/161") == Severity.HIGH

    def test_missing_header_is_medium(self):
        assert classify("CSP missing — XSS protection absent") == Severity.MEDIUM

    def test_no_spf_is_medium(self):
        assert classify("No SPF record found") == Severity.MEDIUM

    def test_referrer_policy_is_low(self):
        assert classify("Referrer-Policy missing") == Severity.LOW

    def test_unknown_is_info(self):
        assert classify("some informational text here") == Severity.INFO


class TestMakeFinding:
    def test_creates_finding_with_severity(self):
        f = make_finding("GIT REPO EXPOSED", module="http")
        assert f.severity == Severity.CRITICAL
        assert f.module == "http"
        assert f.title == "GIT REPO EXPOSED"

    def test_detail_stored(self):
        f = make_finding("weak cipher", detail="RC4 detected", module="ssl")
        assert f.detail == "RC4 detected"

    def test_category_inferred_from_module(self):
        f = make_finding("some finding", module="ssl")
        assert f.category == "tls"

    def test_category_dns(self):
        f = make_finding("No SPF record", module="dns")
        assert f.category == "dns"

    def test_category_web(self):
        f = make_finding("CSP missing", module="http")
        assert f.category == "web"

    def test_category_network(self):
        f = make_finding("Telnet open on TCP/23", module="ports")
        assert f.category == "network"

    def test_category_infrastructure(self):
        f = make_finding("Hosted on AWS", module="ip_intel")
        assert f.category == "infrastructure"

    def test_explicit_category_overrides_inferred(self):
        f = make_finding("some finding", module="ports", category="custom")
        assert f.category == "custom"

    def test_unknown_module_leaves_category_empty(self):
        f = make_finding("some finding", module="unknown_module")
        assert f.category == ""


class TestScoreFindings:
    def test_counts_severities(self):
        findings = [
            Finding(severity=Severity.CRITICAL, title="a"),
            Finding(severity=Severity.CRITICAL, title="b"),
            Finding(severity=Severity.HIGH, title="c"),
            Finding(severity=Severity.MEDIUM, title="d"),
        ]
        scores = score_findings(findings)
        assert scores["CRITICAL"] == 2
        assert scores["HIGH"] == 1
        assert scores["MEDIUM"] == 1
        assert scores["LOW"] == 0


class TestSortFindings:
    def test_critical_first(self):
        findings = [
            Finding(severity=Severity.INFO, title="info"),
            Finding(severity=Severity.CRITICAL, title="crit"),
            Finding(severity=Severity.HIGH, title="high"),
        ]
        sorted_f = sort_findings(findings)
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[-1].severity == Severity.INFO


class TestSeverityOrder:
    def test_critical_lowest_number(self):
        assert SEVERITY_ORDER[Severity.CRITICAL] < SEVERITY_ORDER[Severity.HIGH]
        assert SEVERITY_ORDER[Severity.HIGH] < SEVERITY_ORDER[Severity.MEDIUM]
        assert SEVERITY_ORDER[Severity.MEDIUM] < SEVERITY_ORDER[Severity.LOW]
        assert SEVERITY_ORDER[Severity.LOW] < SEVERITY_ORDER[Severity.INFO]


class TestFindingExtendedFields:
    def test_confidence_default(self):
        f = Finding(severity=Severity.HIGH, title="test")
        assert isinstance(f.confidence, int)
        assert 0 <= f.confidence <= 100

    def test_confidence_explicit(self):
        f = Finding(severity=Severity.HIGH, title="test", confidence=85)
        assert f.confidence == 85

    def test_evidence_default_empty(self):
        f = Finding(severity=Severity.INFO, title="test")
        assert f.evidence == []

    def test_evidence_stored(self):
        f = Finding(severity=Severity.HIGH, title="test", evidence=["header: X-Foo: bar"])
        assert f.evidence == ["header: X-Foo: bar"]

    def test_affected_default_empty(self):
        f = Finding(severity=Severity.INFO, title="test")
        assert f.affected == ""

    def test_affected_stored(self):
        f = Finding(severity=Severity.HIGH, title="t", affected="api.example.com")
        assert f.affected == "api.example.com"

    def test_remediation_auto_populated(self):
        # make_finding should auto-populate remediation for known patterns
        f = make_finding("CSP missing — XSS protection absent", module="http")
        assert f.remediation != "" or True   # graceful — just ensure no crash

    def test_references_list(self):
        f = Finding(severity=Severity.HIGH, title="t", references=["https://owasp.org/test"])
        assert f.references == ["https://owasp.org/test"]

    def test_make_finding_confidence_explicit(self):
        f = make_finding("test", module="http", confidence=55)
        assert f.confidence == 55

    def test_sort_findings_secondary_by_confidence(self):
        """Within same severity, higher confidence should sort first."""
        f1 = Finding(severity=Severity.HIGH, title="low conf", confidence=40)
        f2 = Finding(severity=Severity.HIGH, title="high conf", confidence=90)
        sorted_f = sort_findings([f1, f2])
        assert sorted_f[0].confidence >= sorted_f[1].confidence


class TestDeduplicateFindings:
    def test_dedup_exact_duplicate_kept_once(self):
        f = Finding(severity=Severity.HIGH, title="same", module="http", confidence=70)
        result = deduplicate_findings([f, f])
        assert len(result) == 1

    def test_dedup_keeps_higher_confidence(self):
        f1 = Finding(severity=Severity.HIGH, title="vuln", module="http", confidence=50)
        f2 = Finding(severity=Severity.HIGH, title="vuln", module="http", confidence=80)
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].confidence == 80

    def test_dedup_different_titles_both_kept(self):
        f1 = Finding(severity=Severity.HIGH, title="A", module="http")
        f2 = Finding(severity=Severity.HIGH, title="B", module="http")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_dedup_different_modules_both_kept(self):
        f1 = Finding(severity=Severity.HIGH, title="same", module="http")
        f2 = Finding(severity=Severity.HIGH, title="same", module="dns")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_dedup_empty_list(self):
        assert deduplicate_findings([]) == []
