"""LLM integration package for SPECTER using Ollama"""

from .client import OllamaClient
from .prompt_builder import PromptBuilder

__all__ = ["OllamaClient", "PromptBuilder"]
