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

    def test_portscan_help(self, runner):
        result = runner.invoke(cli, ["portscan", "--help"])
        assert result.exit_code == 0

    def test_dnsenum_help(self, runner):
        result = runner.invoke(cli, ["dnsenum", "--help"])
        assert result.exit_code == 0

    def test_subdomenum_help(self, runner):
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

    def test_install_completion_help(self, runner):
        result = runner.invoke(cli, ["install-completion", "--help"])
        assert result.exit_code == 0

    def test_scan_missing_targets_file(self, runner):
        result = runner.invoke(cli, ["scan", "example.com", "--targets-file", "/nonexistent/file.txt"])
        assert result.exit_code != 0 or "not found" in result.output


class TestParsePortRange:
    """Smoke-test port range parsing through the CLI help."""

    def test_scan_ports_option_visible(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert "top100" in result.output
        assert "--ports" in result.output
