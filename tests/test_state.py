"""Tests for save/resume state."""

import json
import tempfile
from pathlib import Path

import pytest
from reconx.utils.state import ScanState, state_file_for


class TestScanState:
    def test_fresh_state(self, tmp_path):
        sf = str(tmp_path / "test.state.json")
        state = ScanState.load(sf)
        assert state.targets == []
        assert state.completed == {}

    def test_is_done_false_initially(self, tmp_path):
        sf = str(tmp_path / "test.state.json")
        state = ScanState.load(sf)
        assert not state.is_done("example.com")

    def test_save_and_reload(self, tmp_path):
        sf = str(tmp_path / "test.state.json")
        state = ScanState.load(sf)
        state.save_result("example.com", {"target": "example.com", "port_scan": None})
        state.flush()

        # Reload
        state2 = ScanState.load(sf)
        assert state2.is_done("example.com")
        assert "example.com" in state2.completed
        assert state2.results.get("example.com") is not None

    def test_remaining_targets(self, tmp_path):
        sf = str(tmp_path / "test.state.json")
        state = ScanState.load(sf)
        targets = ["a.com", "b.com", "c.com"]
        state.save_result("a.com", {})
        state.flush()

        remaining = state.remaining_targets(targets)
        assert "a.com" not in remaining
        assert "b.com" in remaining
        assert "c.com" in remaining

    def test_progress_string(self, tmp_path):
        sf = str(tmp_path / "test.state.json")
        state = ScanState.load(sf)
        state.targets = ["a.com", "b.com"]
        state.save_result("a.com", {})
        assert state.progress == "1/2"

    def test_state_file_path(self):
        path = state_file_for("my_report", "reports")
        assert "my_report" in path
        assert path.endswith(".state.json")

    def test_flush_creates_file(self, tmp_path):
        sf = str(tmp_path / "state.json")
        state = ScanState.load(sf)
        state.targets = ["x.com"]
        state.flush()
        assert Path(sf).exists()
        raw = json.loads(Path(sf).read_text())
        assert raw["targets"] == ["x.com"]

    def test_get_result_returns_none_for_unknown(self, tmp_path):
        sf = str(tmp_path / "test.state.json")
        state = ScanState.load(sf)
        assert state.get_result("nonexistent.com") is None
