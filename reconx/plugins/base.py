"""
Plugin base contract for ReconX.

Design principles:
  - Protocol-based: no mandatory base class inheritance.
  - Standard I/O model: every plugin receives (target, config, context) and
    returns a PluginResult.
  - Metadata-first: name, version, category, description are required so
    the registry can surface them in --help and reports.
  - Timeout-aware: plugins must honour the timeout value in config.
  - Config-aware: plugins receive the full ScanProfile to read API keys,
    rate-limit settings, and any plugin-specific keys.
  - Context-aware: the context dict contains results from prior modules so
    plugins can build on existing scan data (e.g., read open port list).

Writing a plugin
----------------
1. Create a new Python file under reconx/plugins/ (or any importable package).
2. Define a class that satisfies the ReconPlugin protocol below.
3. Instantiate the class and call registry.register(instance) to enrol it.

Minimal example::

    from reconx.plugins.base import PluginResult, registry
    from reconx.core.severity import make_finding, Severity

    class HeaderAuditPlugin:
        name        = "header-audit"
        version     = "1.0.0"
        category    = "web"
        description = "Checks for custom security response headers."
        author      = "you"

        async def run(self, target, config, context):
            http_results = context.get("http", [])
            findings = []
            for r in http_results:
                if "X-Custom-Token" in (r.get("raw_headers") or {}):
                    findings.append(make_finding(
                        "Sensitive header 'X-Custom-Token' exposed",
                        module=self.name,
                        category=self.category,
                    ))
            return PluginResult(plugin_name=self.name, findings=findings)

    registry.register(HeaderAuditPlugin())
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from reconx.core.severity import Finding

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Plugin output
# ─────────────────────────────────────────────────────────────

@dataclass
class PluginResult:
    """Standardised output returned by every plugin."""
    plugin_name: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)      # arbitrary extra output
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Plugin protocol
# ─────────────────────────────────────────────────────────────

@runtime_checkable
class ReconPlugin(Protocol):
    """
    Contract that every ReconX plugin must satisfy.

    Attributes are checked at registration time; the run() method is called
    during a scan after all built-in modules have completed.
    """

    name: str           # Unique machine-readable identifier (kebab-case)
    version: str        # SemVer string
    category: str       # "web" | "network" | "dns" | "tls" | "passive" | …
    description: str    # One-sentence human description shown in --help
    author: str         # Author name or email

    async def run(
        self,
        target: str,
        config: Any,            # reconx.config.ScanProfile
        context: dict[str, Any],  # collected results from built-in modules
    ) -> PluginResult:
        """
        Execute the plugin against *target*.

        Args:
            target:  The scan target (domain or IP).
            config:  Active ScanProfile — use for timeouts, API keys, etc.
            context: Dict of results from prior built-in modules.  Keys match
                     the ``collected`` dict in cli._run_scan():
                       port_scan, dns, ssl, http, subdomains, crawl,
                       ip_intel, passive, udp, whois, _findings
        Returns:
            PluginResult with any findings and/or extra data.
        """
        ...


# ─────────────────────────────────────────────────────────────
# Plugin registry
# ─────────────────────────────────────────────────────────────

class PluginRegistry:
    """Central registry for ReconX plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, ReconPlugin] = {}

    def register(self, plugin: ReconPlugin) -> None:
        """
        Enrol a plugin instance.

        Raises:
            TypeError:  If the plugin does not satisfy the ReconPlugin protocol.
            ValueError: If a plugin with the same name is already registered.
        """
        if not isinstance(plugin, ReconPlugin):
            missing = [
                attr for attr in ("name", "version", "category", "description", "author")
                if not hasattr(plugin, attr)
            ]
            raise TypeError(
                f"Plugin does not implement ReconPlugin protocol. "
                f"Missing attributes: {missing}"
            )
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' is already registered.")
        self._plugins[plugin.name] = plugin
        log.debug("Plugin registered: %s v%s", plugin.name, plugin.version)

    def unregister(self, name: str) -> None:
        """Remove a plugin by name."""
        self._plugins.pop(name, None)

    def get(self, name: str) -> ReconPlugin | None:
        """Return a plugin by name, or None."""
        return self._plugins.get(name)

    @property
    def all(self) -> list[ReconPlugin]:
        """Return all registered plugins."""
        return list(self._plugins.values())

    async def run_all(
        self,
        target: str,
        config: Any,
        context: dict[str, Any],
        timeout: float = 60.0,
    ) -> list[PluginResult]:
        """
        Run all registered plugins concurrently.

        Each plugin is wrapped in a timeout so a slow/hung plugin does not
        block the overall scan.

        Args:
            target:  Scan target.
            config:  Active ScanProfile.
            context: Module results from the built-in scan pipeline.
            timeout: Per-plugin timeout in seconds.

        Returns:
            List of PluginResult, one per plugin that completed (or errored).
        """
        if not self._plugins:
            return []

        async def _run_one(plugin: ReconPlugin) -> PluginResult:
            try:
                return await asyncio.wait_for(
                    plugin.run(target, config, context),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                log.warning("Plugin '%s' timed out after %.0fs", plugin.name, timeout)
                return PluginResult(
                    plugin_name=plugin.name,
                    errors=[f"Plugin timed out after {timeout:.0f}s"],
                )
            except Exception as exc:
                log.error("Plugin '%s' raised an error: %s", plugin.name, exc)
                return PluginResult(
                    plugin_name=plugin.name,
                    errors=[f"Plugin error: {exc}"],
                )

        return list(await asyncio.gather(*[_run_one(p) for p in self._plugins.values()]))


# ─────────────────────────────────────────────────────────────
# Module-level singleton registry
# ─────────────────────────────────────────────────────────────

registry = PluginRegistry()
