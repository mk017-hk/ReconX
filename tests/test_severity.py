"""Tests for the severity scoring module."""

import pytest
from reconx.core.severity import (
    Severity, Finding, classify, make_finding, score_findings,
    sort_findings, SEVERITY_ORDER,
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
