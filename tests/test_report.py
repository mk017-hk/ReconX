"""Tests for JSON and HTML report generation."""

import json
from pathlib import Path

import pytest

from reconx.utils.report import save_json, generate_html
from reconx.core.severity import Finding, Severity


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _minimal_collected() -> dict:
    return {
        "target": "example.com",
    }


def _collected_with_findings() -> dict:
    """Collected dict with module-level data that triggers findings in both JSON and HTML reports."""
    return {
        "target": "example.com",
        # Pre-aggregated findings for JSON report / display
        "_findings": [
            Finding(severity=Severity.CRITICAL, title="GIT REPO EXPOSED — source code may be accessible!", module="http", category="web"),
            Finding(severity=Severity.HIGH, title="TLS 1.0 deprecated protocol supported", module="ssl", category="tls"),
            Finding(severity=Severity.MEDIUM, title="CSP missing — XSS protection absent", module="http", category="web"),
        ],
        # HTTP module data used by generate_html()
        "http": [
            {
                "url": "https://example.com:443",
                "status_code": 200,
                "title": "Example Domain",
                "server": "Apache/2.4.58",
                "technologies": [],
                "security_headers": [],
                "missing_security_headers": ["CSP missing — XSS protection absent"],
                "interesting_paths": [
                    {"path": "/.git/HEAD", "status_code": 200,
                     "content_length": 23,
                     "note": "GIT REPO EXPOSED — source code may be accessible!"},
                ],
                "redirect_chain": [],
                "cookies": [],
                "raw_headers": {},
                "error": None,
            }
        ],
    }


# ─────────────────────────────────────────────────────────────
# JSON report
# ─────────────────────────────────────────────────────────────

class TestSaveJson:
    def test_creates_file(self, tmp_path):
        out = str(tmp_path / "report.json")
        result = save_json(_minimal_collected(), out)
        assert Path(result).exists()

    def test_valid_json(self, tmp_path):
        out = str(tmp_path / "report.json")
        save_json(_minimal_collected(), out)
        data = json.loads(Path(out).read_text())
        assert isinstance(data, dict)

    def test_contains_target(self, tmp_path):
        out = str(tmp_path / "report.json")
        save_json(_minimal_collected(), out)
        data = json.loads(Path(out).read_text())
        assert data.get("target") == "example.com"

    def test_has_generated_at(self, tmp_path):
        out = str(tmp_path / "report.json")
        save_json(_minimal_collected(), out)
        data = json.loads(Path(out).read_text())
        assert "generated_at" in data
        ts = data["generated_at"]
        # Timestamp must be UTC-aware (ends with Z or +00:00)
        assert ts.endswith("Z") or "+00:00" in ts, f"Bad timestamp: {ts}"

    def test_findings_serialised_as_strings(self, tmp_path):
        """Enum values in Finding must serialise to plain strings, not Enum reprs."""
        out = str(tmp_path / "report.json")
        save_json(_collected_with_findings(), out)
        data = json.loads(Path(out).read_text())
        findings = data.get("_findings", [])
        assert isinstance(findings, list)
        for f in findings:
            if isinstance(f, dict):
                sev = f.get("severity")
                assert isinstance(sev, str), f"severity must be a string, got {type(sev)}"
                assert "<" not in sev, f"Enum repr leaked into JSON: {sev}"

    def test_returns_path(self, tmp_path):
        out = str(tmp_path / "report.json")
        result = save_json(_minimal_collected(), out)
        assert result == out


# ─────────────────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────────────────

class TestGenerateHtml:
    def test_creates_file(self, tmp_path):
        out = str(tmp_path / "report.html")
        result = generate_html(_minimal_collected(), out)
        assert Path(result).exists()

    def test_valid_html_structure(self, tmp_path):
        out = str(tmp_path / "report.html")
        generate_html(_minimal_collected(), out)
        content = Path(out).read_text()
        assert "<!DOCTYPE html>" in content or "<html" in content

    def test_target_in_html(self, tmp_path):
        out = str(tmp_path / "report.html")
        generate_html(_minimal_collected(), out)
        assert "example.com" in Path(out).read_text()

    def test_findings_rendered_in_html(self, tmp_path):
        """Critical findings must appear in the HTML output."""
        out = str(tmp_path / "report.html")
        generate_html(_collected_with_findings(), out)
        content = Path(out).read_text()
        assert "GIT REPO EXPOSED" in content
        assert "CRITICAL" in content

    def test_no_enum_repr_in_html(self, tmp_path):
        """Enum repr strings like <Severity.HIGH: 'HIGH'> must not appear."""
        out = str(tmp_path / "report.html")
        generate_html(_collected_with_findings(), out)
        content = Path(out).read_text()
        assert "<Severity." not in content, "Enum repr leaked into HTML report"

    def test_returns_path(self, tmp_path):
        out = str(tmp_path / "report.html")
        result = generate_html(_minimal_collected(), out)
        assert result == out
