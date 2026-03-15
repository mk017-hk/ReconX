"""
Resume and save-state support for ReconX scans.

State files are stored as JSON alongside the report output.
A state file tracks:
  - scan parameters
  - which targets have been completed
  - partial results (so completed modules aren't re-run)

Usage:
  state = ScanState.load("reports/batch_state.json")
  if state.is_done(target):
      collected = state.get_result(target)
  else:
      # ... run scan ...
      state.save_result(target, collected)
      state.flush()
"""

from __future__ import annotations

import datetime
from datetime import timezone
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


@dataclass
class ScanState:
    state_file: str
    targets: list[str] = field(default_factory=list)
    completed: dict[str, str] = field(default_factory=dict)   # target → ISO timestamp
    results: dict[str, Any] = field(default_factory=dict)     # target → serialised result dict
    scan_args: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    # ── Persistence ────────────────────────────────────────

    @classmethod
    def load(cls, state_file: str) -> "ScanState":
        """Load existing state or create a fresh one."""
        path = Path(state_file)
        if path.exists():
            try:
                raw = json.loads(path.read_text())
                return cls(
                    state_file=state_file,
                    targets=raw.get("targets", []),
                    completed=raw.get("completed", {}),
                    results=raw.get("results", {}),
                    scan_args=raw.get("scan_args", {}),
                    created_at=raw.get("created_at", ""),
                    updated_at=raw.get("updated_at", ""),
                )
            except (json.JSONDecodeError, KeyError):
                pass
        return cls(
            state_file=state_file,
            created_at=datetime.datetime.now(timezone.utc).isoformat() + "Z",
        )

    def flush(self) -> None:
        """Write the state to disk."""
        self.updated_at = datetime.datetime.now(timezone.utc).isoformat() + "Z"
        path = Path(self.state_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "targets": self.targets,
            "completed": self.completed,
            "results": self.results,
            "scan_args": self.scan_args,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        path.write_text(json.dumps(payload, indent=2, default=str))

    # ── Target tracking ────────────────────────────────────

    def is_done(self, target: str) -> bool:
        return target in self.completed

    def get_result(self, target: str) -> Optional[dict]:
        return self.results.get(target)

    def save_result(self, target: str, collected: dict) -> None:
        """Store a completed scan result and mark target done."""
        self.completed[target] = datetime.datetime.now(timezone.utc).isoformat() + "Z"
        # Serialise to JSON-safe dict (handles dataclasses)
        self.results[target] = _make_serialisable(collected)
        if target not in self.targets:
            self.targets.append(target)

    def remaining_targets(self, targets: list[str]) -> list[str]:
        """Return targets not yet completed."""
        return [t for t in targets if not self.is_done(t)]

    @property
    def progress(self) -> str:
        total = len(self.targets)
        done = len(self.completed)
        return f"{done}/{total}" if total else "0/0"


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _make_serialisable(obj: Any) -> Any:
    """Recursively convert dataclasses / objects to JSON-safe types."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _make_serialisable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_make_serialisable(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _make_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, (int, float, str, bool)) or obj is None:
        return obj
    return str(obj)


def state_file_for(report_name: str, output_dir: str) -> str:
    """Derive the state file path from the report name."""
    return str(Path(output_dir) / f"{report_name}.state.json")
