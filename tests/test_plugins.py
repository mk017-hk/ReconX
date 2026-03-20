"""
Tests for reconx.plugins — plugin protocol, registry, and run_all().
"""

import asyncio
import pytest
from reconx.plugins.base import PluginResult, PluginRegistry, ReconPlugin


# ─────────────────────────────────────────────────────────────
# Minimal compliant plugin
# ─────────────────────────────────────────────────────────────

class _GoodPlugin:
    name        = "test-plugin"
    version     = "1.0.0"
    category    = "test"
    description = "A minimal test plugin."
    author      = "tester"

    async def run(self, target, config, context):
        return PluginResult(plugin_name=self.name, data={"ran": True})


# ─────────────────────────────────────────────────────────────
# Protocol conformance
# ─────────────────────────────────────────────────────────────

class TestReconPluginProtocol:
    def test_good_plugin_is_instance(self):
        assert isinstance(_GoodPlugin(), ReconPlugin)

    def test_missing_name_fails(self):
        class Bad:
            version = "1.0"; category = "x"; description = "x"; author = "x"
            async def run(self, t, c, ctx): ...
        assert not isinstance(Bad(), ReconPlugin)

    def test_missing_run_fails(self):
        class Bad:
            name = "x"; version = "1.0"; category = "x"; description = "x"; author = "x"
        assert not isinstance(Bad(), ReconPlugin)


# ─────────────────────────────────────────────────────────────
# PluginRegistry
# ─────────────────────────────────────────────────────────────

class TestPluginRegistry:
    def _fresh_registry(self) -> PluginRegistry:
        return PluginRegistry()

    def test_register_valid_plugin(self):
        reg = self._fresh_registry()
        reg.register(_GoodPlugin())
        assert len(reg.all) == 1

    def test_register_returns_by_name(self):
        reg = self._fresh_registry()
        plugin = _GoodPlugin()
        reg.register(plugin)
        assert reg.get("test-plugin") is plugin

    def test_get_unknown_returns_none(self):
        reg = self._fresh_registry()
        assert reg.get("does-not-exist") is None

    def test_register_duplicate_raises(self):
        reg = self._fresh_registry()
        reg.register(_GoodPlugin())
        with pytest.raises(ValueError, match="already registered"):
            reg.register(_GoodPlugin())

    def test_register_invalid_raises_type_error(self):
        reg = self._fresh_registry()
        class NotAPlugin:
            pass
        with pytest.raises(TypeError):
            reg.register(NotAPlugin())

    def test_unregister(self):
        reg = self._fresh_registry()
        reg.register(_GoodPlugin())
        reg.unregister("test-plugin")
        assert reg.get("test-plugin") is None

    def test_unregister_unknown_no_error(self):
        reg = self._fresh_registry()
        reg.unregister("nonexistent")  # should not raise

    def test_all_returns_list(self):
        reg = self._fresh_registry()
        reg.register(_GoodPlugin())
        result = reg.all
        assert isinstance(result, list)
        assert len(result) == 1


# ─────────────────────────────────────────────────────────────
# run_all()
# ─────────────────────────────────────────────────────────────

class TestRunAll:
    async def test_run_all_empty_registry(self):
        reg = PluginRegistry()
        results = await reg.run_all("example.com", {}, {})
        assert results == []

    async def test_run_all_returns_plugin_results(self):
        reg = PluginRegistry()
        reg.register(_GoodPlugin())
        results = await reg.run_all("example.com", {}, {})
        assert len(results) == 1
        assert isinstance(results[0], PluginResult)
        assert results[0].plugin_name == "test-plugin"
        assert results[0].data.get("ran") is True

    async def test_run_all_timeout_produces_error_result(self):
        class SlowPlugin:
            name        = "slow"
            version     = "1.0"
            category    = "test"
            description = "slow"
            author      = "x"

            async def run(self, target, config, context):
                await asyncio.sleep(60)
                return PluginResult(plugin_name=self.name)

        reg = PluginRegistry()
        reg.register(SlowPlugin())
        results = await reg.run_all("example.com", {}, {}, timeout=0.05)
        assert len(results) == 1
        assert "timed out" in results[0].errors[0].lower()

    async def test_run_all_exception_produces_error_result(self):
        class BrokenPlugin:
            name        = "broken"
            version     = "1.0"
            category    = "test"
            description = "broken"
            author      = "x"

            async def run(self, target, config, context):
                raise RuntimeError("something went wrong")

        reg = PluginRegistry()
        reg.register(BrokenPlugin())
        results = await reg.run_all("example.com", {}, {})
        assert len(results) == 1
        assert results[0].errors
        assert "error" in results[0].errors[0].lower()

    async def test_run_all_multiple_plugins_concurrent(self):
        """Multiple plugins should all run and return results."""
        results_order = []

        class PluginA:
            name = "plugin-a"; version = "1.0"; category = "t"
            description = "A"; author = "x"
            async def run(self, target, config, context):
                await asyncio.sleep(0.01)
                results_order.append("A")
                return PluginResult(plugin_name=self.name)

        class PluginB:
            name = "plugin-b"; version = "1.0"; category = "t"
            description = "B"; author = "x"
            async def run(self, target, config, context):
                results_order.append("B")
                return PluginResult(plugin_name=self.name)

        reg = PluginRegistry()
        reg.register(PluginA())
        reg.register(PluginB())
        results = await reg.run_all("example.com", {}, {})
        assert len(results) == 2
        plugin_names = {r.plugin_name for r in results}
        assert plugin_names == {"plugin-a", "plugin-b"}


# ─────────────────────────────────────────────────────────────
# PluginResult dataclass
# ─────────────────────────────────────────────────────────────

class TestPluginResult:
    def test_defaults(self):
        pr = PluginResult(plugin_name="x")
        assert pr.findings == []
        assert pr.data == {}
        assert pr.errors == []

    def test_with_errors(self):
        pr = PluginResult(plugin_name="x", errors=["oops"])
        assert pr.errors == ["oops"]
