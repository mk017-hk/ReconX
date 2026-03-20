"""
Tests for the layered fingerprinting engine in reconx.core.http_probe.
"""

import pytest
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────────────────────
# Helper: import private functions we want to unit-test
# ─────────────────────────────────────────────────────────────

from reconx.core.http_probe import (
    _fingerprint_technologies,
    _analyse_cors,
    _find_cloud_bucket_refs,
    _check_directory_listing,
    Technology,
    CloudBucketRef,
)


# ─────────────────────────────────────────────────────────────
# _fingerprint_technologies
# ─────────────────────────────────────────────────────────────

class TestFingerprintTechnologies:
    """_fingerprint_technologies(headers: dict, body: str, cookie_header: str)"""

    def test_apache_from_server_header(self):
        headers = {"Server": "Apache/2.4.51 (Ubuntu)"}
        techs = _fingerprint_technologies(headers, "", "")
        names = [t.name for t in techs]
        assert "Apache" in names

    def test_nginx_from_server_header(self):
        headers = {"Server": "nginx/1.25.3"}
        techs = _fingerprint_technologies(headers, "", "")
        names = [t.name for t in techs]
        assert "Nginx" in names

    def test_php_from_x_powered_by(self):
        headers = {"X-Powered-By": "PHP/8.1.0"}
        techs = _fingerprint_technologies(headers, "", "")
        names = [t.name for t in techs]
        assert "PHP" in names

    def test_wordpress_from_body(self):
        body = '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
        techs = _fingerprint_technologies({}, body, "")
        names = [t.name for t in techs]
        assert "WordPress" in names

    def test_django_from_csrftoken_cookie(self):
        techs = _fingerprint_technologies({}, "", "csrftoken=abc123; sessionid=xyz")
        names = [t.name for t in techs]
        assert "Django" in names

    def test_no_false_positive_empty_inputs(self):
        techs = _fingerprint_technologies({}, "", "")
        assert isinstance(techs, list)

    def test_technology_has_confidence_field(self):
        headers = {"Server": "Apache/2.4.51"}
        techs = _fingerprint_technologies(headers, "", "")
        for t in techs:
            assert isinstance(t, Technology)
            assert t.confidence >= 0

    def test_version_extracted(self):
        headers = {"Server": "Apache/2.4.51"}
        techs = _fingerprint_technologies(headers, "", "")
        apache = next((t for t in techs if t.name == "Apache"), None)
        assert apache is not None
        assert "2.4" in (apache.version or "")

    def test_dedup_same_category_name(self):
        """Same technology should not appear twice."""
        headers = {"Server": "nginx/1.25"}
        body = "nginx" * 5
        techs = _fingerprint_technologies(headers, body, "")
        nginx_count = sum(1 for t in techs if t.name == "Nginx")
        assert nginx_count <= 1

    def test_jquery_from_body(self):
        # Pattern matches "jquery.min.js" or "jQuery v3.6.0"
        body = '<script>/* jQuery v3.6.0 | (c) JS Foundation */</script>'
        techs = _fingerprint_technologies({}, body, "")
        names = [t.name for t in techs]
        assert "jQuery" in names


# ─────────────────────────────────────────────────────────────
# _analyse_cors
# ─────────────────────────────────────────────────────────────

class TestAnalyseCors:
    def test_no_cors_headers(self):
        issues = _analyse_cors({"Content-Type": "text/html"})
        assert issues == []

    def test_wildcard_origin(self):
        headers = {"Access-Control-Allow-Origin": "*"}
        issues = _analyse_cors(headers)
        assert any("wildcard" in i.lower() or "*" in i for i in issues)

    def test_wildcard_with_credentials_flagged(self):
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        issues = _analyse_cors(headers)
        assert len(issues) >= 1
        combined = " ".join(issues).lower()
        assert "credential" in combined or "wildcard" in combined

    def test_null_origin(self):
        headers = {"Access-Control-Allow-Origin": "null"}
        issues = _analyse_cors(headers)
        assert any("null" in i.lower() for i in issues)

    def test_specific_origin_no_issue(self):
        headers = {"Access-Control-Allow-Origin": "https://trusted.example.com"}
        issues = _analyse_cors(headers)
        assert issues == []


# ─────────────────────────────────────────────────────────────
# _find_cloud_bucket_refs
# ─────────────────────────────────────────────────────────────

class TestFindCloudBucketRefs:
    def test_s3_bucket_detected(self):
        body = 'See our assets at https://my-bucket.s3.amazonaws.com/logo.png'
        refs = _find_cloud_bucket_refs(body)
        providers = [r.provider for r in refs]
        assert any("s3" in p.lower() or "aws" in p.lower() for p in providers)

    def test_azure_blob_detected(self):
        body = "Files stored at https://myaccount.blob.core.windows.net/container/file.txt"
        refs = _find_cloud_bucket_refs(body)
        providers = [r.provider for r in refs]
        assert any("azure" in p.lower() for p in providers)

    def test_gcs_detected(self):
        body = "Download from https://storage.googleapis.com/my-bucket/data.csv"
        refs = _find_cloud_bucket_refs(body)
        providers = [r.provider for r in refs]
        assert any("gcp" in p.lower() or "google" in p.lower() or "storage" in p.lower() for p in providers)

    def test_no_bucket_refs(self):
        body = "<html><body>Hello world</body></html>"
        refs = _find_cloud_bucket_refs(body)
        assert refs == []

    def test_returns_cloud_bucket_ref_objects(self):
        body = "https://bucket.s3.amazonaws.com/file.jpg"
        refs = _find_cloud_bucket_refs(body)
        for r in refs:
            assert isinstance(r, CloudBucketRef)
            assert r.provider
            assert r.bucket_url


# ─────────────────────────────────────────────────────────────
# _check_directory_listing
# ─────────────────────────────────────────────────────────────

class TestCheckDirectoryListing:
    def test_apache_index(self):
        body = "<html><head><title>Index of /uploads</title></head></html>"
        assert _check_directory_listing(body) is True

    def test_nginx_autoindex(self):
        body = "<h1>Index of /static/</h1>"
        assert _check_directory_listing(body) is True

    def test_no_listing(self):
        body = "<html><body>Welcome to our site</body></html>"
        assert _check_directory_listing(body) is False

    def test_empty_body(self):
        assert _check_directory_listing("") is False
