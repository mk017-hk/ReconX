"""Tests for the CLI interface."""

import pytest
from click.testing import CliRunner
from reconx.cli import cli
from reconx import __version__


@pytest.fixture
def runner():
    return CliRunner()


class TestCLIBasics:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ReconX" in result.output

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--ports" in result.output
        assert "--targets-file" in result.output
        assert "--profile" in result.output
        assert "--udp" in result.output
        assert "--delay" in result.output
        assert "--resume" in result.output

    def test_portscan_help(self, runner):
        result = runner.invoke(cli, ["portscan", "--help"])
        assert result.exit_code == 0
        assert "--delay" in result.output

    def test_udpscan_help(self, runner):
        result = runner.invoke(cli, ["udpscan", "--help"])
        assert result.exit_code == 0

    def test_crawl_help(self, runner):
        result = runner.invoke(cli, ["crawl", "--help"])
        assert result.exit_code == 0
        assert "--depth" in result.output

    def test_ipintel_help(self, runner):
        result = runner.invoke(cli, ["ipintel", "--help"])
        assert result.exit_code == 0

    def test_dnsenum_help(self, runner):
        result = runner.invoke(cli, ["dnsenum", "--help"])
        assert result.exit_code == 0

    def test_subdomains_help(self, runner):
        result = runner.invoke(cli, ["subdomains", "--help"])
        assert result.exit_code == 0

    def test_subdomenum_help_backward_compat(self, runner):
        """subdomenum is a deprecated alias — must still be invocable."""
        result = runner.invoke(cli, ["subdomenum", "--help"])
        assert result.exit_code == 0

    def test_sslcheck_help(self, runner):
        result = runner.invoke(cli, ["sslcheck", "--help"])
        assert result.exit_code == 0

    def test_whoislookup_help(self, runner):
        result = runner.invoke(cli, ["whoislookup", "--help"])
        assert result.exit_code == 0

    def test_httpprobe_help(self, runner):
        result = runner.invoke(cli, ["httpprobe", "--help"])
        assert result.exit_code == 0

    def test_init_config_help(self, runner):
        result = runner.invoke(cli, ["init-config", "--help"])
        assert result.exit_code == 0

    def test_install_completion_help(self, runner):
        result = runner.invoke(cli, ["install-completion", "--help"])
        assert result.exit_code == 0

    def test_scan_missing_targets_file(self, runner):
        result = runner.invoke(cli, ["scan", "example.com", "--targets-file", "/nonexistent/file.txt"])
        assert result.exit_code != 0 or "not found" in result.output

    def test_init_config_creates_file(self, runner, tmp_path):
        out = str(tmp_path / "test_config.yml")
        result = runner.invoke(cli, ["init-config", "--output", out])
        assert result.exit_code == 0
        import os
        assert os.path.exists(out)
        content = open(out).read()
        assert "ports" in content
        assert "concurrency" in content


class TestProfileOption:
    def test_profile_option_in_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--profile" in result.output
        assert "quick" in result.output or "full" in result.output or "web" in result.output

    def test_insecure_flag_in_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert "--insecure" in result.output

    def test_scan_standard_profile_insecure_sets_verify_ssl_false(self, runner, monkeypatch):
        """--insecure should set verify_ssl=False on the profile before running."""
        captured = {}

        async def fake_run_scan(**kwargs):
            captured.update(kwargs)

        monkeypatch.setattr("reconx.cli._run_scan", fake_run_scan)
        result = runner.invoke(cli, [
            "scan", "example.com",
            "--no-dns", "--no-http", "--no-ssl", "--no-whois",
            "--insecure",
        ])
        assert captured.get("verify_ssl") is False

    def test_scan_default_verify_ssl_true(self, runner, monkeypatch):
        """Without --insecure, verify_ssl must be True."""
        captured = {}

        async def fake_run_scan(**kwargs):
            captured.update(kwargs)

        monkeypatch.setattr("reconx.cli._run_scan", fake_run_scan)
        result = runner.invoke(cli, [
            "scan", "example.com",
            "--no-dns", "--no-http", "--no-ssl", "--no-whois",
        ])
        assert captured.get("verify_ssl") is True
