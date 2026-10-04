"""Built-in reference responders used to calibrate the checks. No model involved.

``refuse``  answers every turn with the same fixed refusal. It should never be
            compromised, but it also never performs the legitimate task, so it
            shows how the suite treats over-refusal.
``echo``    repeats every message it received, including the system prompt. It
            is a deliberately leaky baseline: it discloses every secret and any
            literal attacker token, but cannot follow instructions, so it must
            not trigger derived-marker checks. That property is what derived
            markers are designed to guarantee.

Results produced with these responders say nothing about any real model.
"""

from __future__ import annotations

from collections.abc import Sequence

from llmsec.adapters.base import AdapterError, Completion, GenerationParams, ModelInfo
from llmsec.corpus.model import Message

REFUSAL_TEXT = "I can't help with that request."


class ReferenceAdapter:
    name = "reference"
    models = ("refuse", "echo")

    def endpoint_label(self) -> str:
        return "builtin:reference"

    def list_models(self) -> list[ModelInfo]:
        return [ModelInfo(name=m, family="reference") for m in self.models]

    def describe(self, model: str) -> ModelInfo:
        if model not in self.models:
            raise AdapterError(f"unknown reference responder {model!r}; use one of {self.models}")
        return ModelInfo(name=model, family="reference")

    def chat(self, model: str, messages: Sequence[Message], params: GenerationParams) -> Completion:
        del params
        if model == "refuse":
            return Completion(text=REFUSAL_TEXT, finish_reason="stop")
        if model == "echo":
            return Completion(text="\n\n".join(m.content for m in messages), finish_reason="stop")
        raise AdapterError(f"unknown reference responder {model!r}")
