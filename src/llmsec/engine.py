"""Play scenarios against a model adapter and capture evidence.

The engine is observational: it sends the scenario's messages, records what
comes back, and hands the text to the deterministic checks. Model output is
appended to the transcript as plain data and is never interpreted.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from llmsec.adapters.base import AdapterError, GenerationParams, ModelAdapter
from llmsec.corpus.model import Message, Role, Scenario
from llmsec.evaluation import Verdict, evaluate


class RunAborted(RuntimeError):
    """Too many consecutive transport errors: the endpoint is probably down."""


@dataclass(frozen=True, slots=True)
class TurnRecord:
    index: int
    latency_s: float
    text: str
    finish_reason: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    reasoning: str | None


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    scenario_id: str
    category: str
    severity: str
    repeat: int
    seed: int
    started_at: str
    finished_at: str
    latency_s: float
    verdict: Verdict
    reason: str
    transcript: tuple[dict[str, str], ...]
    turns: tuple[TurnRecord, ...]
    checks: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "category": self.category,
            "severity": self.severity,
            "repeat": self.repeat,
            "seed": self.seed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "latency_s": round(self.latency_s, 4),
            "verdict": self.verdict.value,
            "reason": self.reason,
            "error": self.error,
            "checks": [dict(c) for c in self.checks],
            "turns": [
                {
                    "index": t.index,
                    "latency_s": round(t.latency_s, 4),
                    "text": t.text,
                    "finish_reason": t.finish_reason,
                    "prompt_tokens": t.prompt_tokens,
                    "completion_tokens": t.completion_tokens,
                    "reasoning": t.reasoning,
                }
                for t in self.turns
            ],
            "transcript": [dict(m) for m in self.transcript],
        }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _utf8_safe(text: str | None) -> str | None:
    """Replace lone surrogates so the evidence can always be written as UTF-8."""
    if text is None:
        return None
    return text.encode("utf-8", "replace").decode("utf-8")


ProgressFn = Callable[[int, int, Scenario, ExecutionRecord], None]


def execute_scenario(
    adapter: ModelAdapter,
    model: str,
    scenario: Scenario,
    params: GenerationParams,
    repeat: int = 0,
) -> ExecutionRecord:
    """Play one scenario once. Never raises for model or transport misbehaviour."""
    started = _now()
    t0 = time.perf_counter()
    history: list[Message] = []
    turns: list[TurnRecord] = []
    conv = scenario.conversation
    error: str | None = None
    try:
        for i, msg in enumerate(conv):
            history.append(msg)
            nxt = conv[i + 1] if i + 1 < len(conv) else None
            if msg.role is Role.USER and (nxt is None or nxt.role is not Role.ASSISTANT):
                t_call = time.perf_counter()
                completion = adapter.chat(model, tuple(history), params)
                text = _utf8_safe(completion.text) or ""
                turns.append(
                    TurnRecord(
                        index=len(turns),
                        latency_s=time.perf_counter() - t_call,
                        text=text,
                        finish_reason=completion.finish_reason,
                        prompt_tokens=completion.prompt_tokens,
                        completion_tokens=completion.completion_tokens,
                        reasoning=_utf8_safe(completion.reasoning),
                    )
                )
                history.append(Message(Role.ASSISTANT, text))
    except AdapterError as exc:
        error = _utf8_safe(str(exc))
    except Exception as exc:  # noqa: BLE001 - an execution must never take the run down
        error = _utf8_safe(f"internal error ({type(exc).__name__}): {exc}")

    transcript = tuple({"role": m.role.value, "content": m.content} for m in history)

    def record(
        verdict: Verdict, reason: str, checks: tuple[dict[str, Any], ...] = ()
    ) -> ExecutionRecord:
        return ExecutionRecord(
            scenario_id=scenario.id,
            category=scenario.category,
            severity=scenario.severity.value,
            repeat=repeat,
            seed=params.seed,
            started_at=started,
            finished_at=_now(),
            latency_s=time.perf_counter() - t0,
            verdict=verdict,
            reason=reason,
            transcript=transcript,
            turns=tuple(turns),
            checks=checks,
            error=error,
        )

    if error is not None:
        return record(Verdict.ERROR, error)
    responses = [t.text for t in turns]
    truncated = any(t.finish_reason == "length" for t in turns)
    result = evaluate(scenario, responses, truncated=truncated)
    checks = tuple(
        {
            "type": o.type,
            "description": o.description,
            "passed": o.passed,
            "effect": o.effect.value if o.effect else None,
            "reason": o.reason,
            "response_index": o.response_index,
        }
        for o in result.checks
    )
    return record(result.verdict, result.reason, checks)


def run_scenarios(
    adapter: ModelAdapter,
    model: str,
    scenarios: Sequence[Scenario],
    params: GenerationParams,
    repeat: int = 1,
    progress: ProgressFn | None = None,
    abort_after_errors: int = 3,
) -> list[ExecutionRecord]:
    """Run every scenario ``repeat`` times. Repeat ``r`` uses seed ``params.seed + r``."""
    if repeat < 1:
        raise ValueError("repeat must be >= 1")
    records: list[ExecutionRecord] = []
    total = len(scenarios) * repeat
    consecutive_errors = 0
    for r in range(repeat):
        p = replace(params, seed=params.seed + r)
        for scenario in scenarios:
            rec = execute_scenario(adapter, model, scenario, p, repeat=r)
            records.append(rec)
            if progress:
                progress(len(records), total, scenario, rec)
            consecutive_errors = consecutive_errors + 1 if rec.verdict is Verdict.ERROR else 0
            if abort_after_errors and consecutive_errors >= abort_after_errors:
                raise RunAborted(
                    f"{consecutive_errors} consecutive executions failed; last error: {rec.error}"
                )
    return records
