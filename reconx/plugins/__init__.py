"""
ReconX plugin system.

Plugins extend ReconX with additional checks without modifying the core.
See reconx/plugins/base.py for the plugin contract and reconx/plugins/example.py
for a minimal working example.
"""

from reconx.plugins.base import ReconPlugin, PluginResult, PluginRegistry, registry

__all__ = ["ReconPlugin", "PluginResult", "PluginRegistry", "registry"]
