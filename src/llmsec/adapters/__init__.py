"""Model adapters."""

from __future__ import annotations

from llmsec.adapters.base import (
    AdapterError,
    Completion,
    GenerationParams,
    ModelAdapter,
    ModelInfo,
)
from llmsec.adapters.ollama import DEFAULT_OLLAMA_URL, OllamaAdapter
from llmsec.adapters.openai_compat import DEFAULT_OPENAI_URL, OpenAICompatAdapter
from llmsec.adapters.reference import ReferenceAdapter

ADAPTERS = ("ollama", "openai", "reference")


def make_adapter(
    kind: str,
    base_url: str | None = None,
    timeout: float = 300.0,
    allow_remote: bool = False,
    api_key_env: str | None = None,
) -> ModelAdapter:
    if kind == "ollama":
        return OllamaAdapter(base_url or DEFAULT_OLLAMA_URL, timeout, allow_remote)
    if kind == "openai":
        return OpenAICompatAdapter(
            base_url or DEFAULT_OPENAI_URL, timeout, allow_remote, api_key_env
        )
    if kind == "reference":
        return ReferenceAdapter()
    raise AdapterError(f"unknown adapter {kind!r}; choose from {', '.join(ADAPTERS)}")


__all__ = [
    "ADAPTERS",
    "AdapterError",
    "Completion",
    "GenerationParams",
    "ModelAdapter",
    "ModelInfo",
    "OllamaAdapter",
    "OpenAICompatAdapter",
    "ReferenceAdapter",
    "make_adapter",
]
