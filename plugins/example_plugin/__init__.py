"""Example plugin for SPECTER"""

from specter.plugins.base import BasePlugin, PluginMetadata
import structlog

logger = structlog.get_logger()


class ExamplePlugin(BasePlugin):
    """Plugin de ejemplo que demuestra la API de plugins"""
    
    metadata = PluginMetadata(
        name="example_plugin",
        version="1.0.0",
        description="Plugin de ejemplo para SPECTER - demuestra la API de plugins",
        author="SPECTER Team",
        dependencies=[],
        skills=["custom_exploit"],
        tools=["example.tool"]
    )
    
    def initialize(self) -> bool:
        """Inicializa el plugin"""
        logger.info("Initializing example plugin")
        self._loaded = True
        return True
    
    def shutdown(self) -> None:
        """Limpia el plugin"""
        logger.info("Shutting down example plugin")
    
    def custom_action(self, param: str) -> str:
        """Acción custom del plugin"""
        return f"Plugin ejecutó acción con: {param}"