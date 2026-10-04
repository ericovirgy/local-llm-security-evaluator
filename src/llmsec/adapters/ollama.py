"""Adapter for the Ollama native HTTP API (``/api/tags``, ``/api/show``, ``/api/chat``)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from llmsec.adapters._shape import get_int, get_str, opt_str
from llmsec.adapters.base import AdapterError, Completion, GenerationParams, ModelInfo
from llmsec.adapters.http import redact_url, request_json, validate_base_url
from llmsec.corpus.model import Message

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"


class OllamaAdapter:
    name = "ollama"

    def __init__(
        self, base_url: str = DEFAULT_OLLAMA_URL, timeout: float = 300.0, allow_remote: bool = False
    ) -> None:
        self.base_url = validate_base_url(base_url, allow_remote)
        self.timeout = timeout

    def endpoint_label(self) -> str:
        return redact_url(self.base_url)

    def _info(self, entry: Any) -> ModelInfo:
        name = get_str(entry, "name", "ollama /api/tags entry")
        assert name is not None
        details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
        return ModelInfo(
            name=name,
            digest=opt_str(entry, "digest"),
            family=opt_str(details, "family"),
            parameter_size=opt_str(details, "parameter_size"),
            quantization=opt_str(details, "quantization_level"),
            size_bytes=get_int(entry, "size"),
            extra={k: v for k in ("format",) if (v := opt_str(details, k))},
        )

    def list_models(self) -> list[ModelInfo]:
        data = request_json("GET", f"{self.base_url}/api/tags", None, self.timeout)
        models = data.get("models")
        if not isinstance(models, list):
            raise AdapterError("ollama /api/tags: 'models' is not a list")
        return sorted((self._info(m) for m in models), key=lambda m: m.name)

    def describe(self, model: str) -> ModelInfo:
        for info in self.list_models():
            if info.name in {model, f"{model}:latest"}:
                return info
        raise AdapterError(f"model {model!r} is not available at {self.endpoint_label()}")

    def chat(self, model: str, messages: Sequence[Message], params: GenerationParams) -> Completion:
        options: dict[str, Any] = {
            "temperature": params.temperature,
            "seed": params.seed,
            "num_predict": params.max_tokens,
            "num_ctx": params.num_ctx,
        }
        if params.top_p is not None:
            options["top_p"] = params.top_p
        payload = {
            "model": model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "stream": False,
            "options": options,
        }
        data = request_json("POST", f"{self.base_url}/api/chat", payload, self.timeout)
        if isinstance(data.get("error"), str):
            raise AdapterError(f"ollama error: {data['error'][:300]}")
        message = data.get("message")
        text = get_str(message, "content", "ollama /api/chat message")
        assert text is not None
        return Completion(
            text=text,
            finish_reason=opt_str(data, "done_reason"),
            prompt_tokens=get_int(data, "prompt_eval_count"),
            completion_tokens=get_int(data, "eval_count"),
            reasoning=opt_str(message, "thinking"),
        )
