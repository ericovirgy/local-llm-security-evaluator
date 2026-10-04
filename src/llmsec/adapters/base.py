"""Adapter interface between the evaluator and a model endpoint.

Adapters move text and nothing else. They never interpret model output.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from llmsec.corpus.model import Message


class AdapterError(RuntimeError):
    """The endpoint could not be reached or returned something unexpected."""


@dataclass(frozen=True, slots=True)
class GenerationParams:
    temperature: float = 0.0
    seed: int = 1234
    max_tokens: int = 768
    num_ctx: int = 8192  # Ollama only; ignored by other adapters
    top_p: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "temperature": self.temperature,
            "seed": self.seed,
            "max_tokens": self.max_tokens,
            "num_ctx": self.num_ctx,
            "top_p": self.top_p,
        }


@dataclass(frozen=True, slots=True)
class ModelInfo:
    name: str
    digest: str | None = None
    family: str | None = None
    parameter_size: str | None = None
    quantization: str | None = None
    size_bytes: int | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "digest": self.digest,
            "family": self.family,
            "parameter_size": self.parameter_size,
            "quantization": self.quantization,
            "size_bytes": self.size_bytes,
            "extra": dict(self.extra),
        }


@dataclass(frozen=True, slots=True)
class Completion:
    text: str
    finish_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    reasoning: str | None = None  # separate reasoning channel, when the endpoint reports one

    @property
    def truncated(self) -> bool:
        return self.finish_reason == "length"


class ModelAdapter(Protocol):
    name: str

    def endpoint_label(self) -> str:
        """Endpoint description safe to store in results (no credentials)."""
        ...

    def list_models(self) -> list[ModelInfo]: ...

    def describe(self, model: str) -> ModelInfo: ...

    def chat(
        self, model: str, messages: Sequence[Message], params: GenerationParams
    ) -> Completion: ...
