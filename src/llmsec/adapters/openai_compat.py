"""Adapter for OpenAI-compatible chat endpoints served locally.

Examples: llama.cpp ``llama-server``, vLLM, LM Studio, or Ollama's ``/v1``
compatibility layer. ``base_url`` is the API root, for example
``http://127.0.0.1:8080/v1``.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

from llmsec.adapters._shape import get_int, get_str, opt_str
from llmsec.adapters.base import AdapterError, Completion, GenerationParams, ModelInfo
from llmsec.adapters.http import redact_url, request_json, validate_base_url
from llmsec.corpus.model import Message

DEFAULT_OPENAI_URL = "http://127.0.0.1:8080/v1"


class OpenAICompatAdapter:
    name = "openai"

    def __init__(
        self,
        base_url: str = DEFAULT_OPENAI_URL,
        timeout: float = 300.0,
        allow_remote: bool = False,
        api_key_env: str | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url, allow_remote)
        self.timeout = timeout
        self._headers: dict[str, str] = {}
        if api_key_env:
            key = os.environ.get(api_key_env)
            if not key:
                raise AdapterError(f"environment variable {api_key_env} is not set")
            self._headers["Authorization"] = f"Bearer {key}"

    def endpoint_label(self) -> str:
        return redact_url(self.base_url)

    def list_models(self) -> list[ModelInfo]:
        data = request_json("GET", f"{self.base_url}/models", None, self.timeout, self._headers)
        entries = data.get("data")
        if not isinstance(entries, list):
            raise AdapterError("/models: 'data' is not a list")
        out = []
        for entry in entries:
            name = get_str(entry, "id", "/models entry")
            assert name is not None
            out.append(ModelInfo(name=name, extra={"owned_by": opt_str(entry, "owned_by") or ""}))
        return sorted(out, key=lambda m: m.name)

    def describe(self, model: str) -> ModelInfo:
        for info in self.list_models():
            if info.name == model:
                return info
        raise AdapterError(f"model {model!r} is not available at {self.endpoint_label()}")

    def chat(self, model: str, messages: Sequence[Message], params: GenerationParams) -> Completion:
        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": params.temperature,
            "seed": params.seed,
            "max_tokens": params.max_tokens,
            "stream": False,
        }
        if params.top_p is not None:
            payload["top_p"] = params.top_p
        data = request_json(
            "POST", f"{self.base_url}/chat/completions", payload, self.timeout, self._headers
        )
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise AdapterError("/chat/completions: no choices returned")
        message = choices[0].get("message")
        text = get_str(message, "content", "/chat/completions message", optional=True) or ""
        raw_usage = data.get("usage")
        usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        return Completion(
            text=text,
            finish_reason=opt_str(choices[0], "finish_reason"),
            prompt_tokens=get_int(usage, "prompt_tokens"),
            completion_tokens=get_int(usage, "completion_tokens"),
            reasoning=opt_str(message, "reasoning_content"),
        )
