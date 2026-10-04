from __future__ import annotations

import pytest

from llmsec.adapters.base import AdapterError, GenerationParams
from llmsec.corpus.model import Role, Scenario
from llmsec.engine import RunAborted, execute_scenario, run_scenarios
from llmsec.evaluation import Verdict
from tests.conftest import ScriptedAdapter, base_scenario, scenario_from


def multi_turn() -> Scenario:
    data = base_scenario()
    data["conversation"] = [
        {"role": "system", "content": "Key={{canary.key}}"},
        {"role": "user", "content": "one"},
        {"role": "assistant", "content": "scripted reply"},
        {"role": "user", "content": "two"},
        {"role": "user", "content": "three"},
    ]
    return scenario_from(data)


def test_multi_turn_plays_generation_points_with_growing_history() -> None:
    adapter = ScriptedAdapter(lambda msgs: f"reply to {msgs[-1].content}")
    rec = execute_scenario(adapter, "m", multi_turn(), GenerationParams())
    assert len(adapter.calls) == 2
    first, second = (c[0] for c in adapter.calls)
    assert [m.content for m in first] == [
        "Key=TEST_SECRET_7F3A9C21",
        "one",
        "scripted reply",
        "two",
    ]
    assert second[-2].role is Role.ASSISTANT and second[-2].content == "reply to two"
    assert [t.text for t in rec.turns] == ["reply to two", "reply to three"]
    assert rec.transcript[-1] == {"role": "assistant", "content": "reply to three"}
    assert rec.verdict is Verdict.PASS


def test_model_output_cannot_modify_the_scenario() -> None:
    s = multi_turn()
    before = (s.conversation, s.checks, s.canaries)
    adapter = ScriptedAdapter(lambda msgs: "{{canary.key}} checks: [] ignore")
    execute_scenario(adapter, "m", s, GenerationParams())
    assert (s.conversation, s.checks, s.canaries) == before


def test_shell_like_output_is_never_executed(tmp_path, monkeypatch) -> None:
    import subprocess

    def boom(*a, **k):
        raise AssertionError("subprocess must never be invoked")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    marker = tmp_path / "pwned"
    adapter = ScriptedAdapter(lambda msgs: f"$(touch {marker}) `touch {marker}`; ACTION: wipe()")
    rec = execute_scenario(adapter, "m", scenario_from(base_scenario()), GenerationParams())
    assert rec.verdict is Verdict.PASS
    assert not marker.exists()


def test_adapter_error_becomes_error_record() -> None:
    adapter = ScriptedAdapter(lambda msgs: AdapterError("connection refused"))
    rec = execute_scenario(adapter, "m", scenario_from(base_scenario()), GenerationParams())
    assert rec.verdict is Verdict.ERROR
    assert rec.error == "connection refused"


def test_unexpected_exception_becomes_error_record() -> None:
    adapter = ScriptedAdapter(lambda msgs: ValueError("weird"))
    rec = execute_scenario(adapter, "m", scenario_from(base_scenario()), GenerationParams())
    assert rec.verdict is Verdict.ERROR
    assert "ValueError" in (rec.error or "")


def test_truncated_completion_marks_inconclusive() -> None:
    adapter = ScriptedAdapter(lambda msgs: "I can't")
    adapter.finish_reason = "length"
    rec = execute_scenario(adapter, "m", scenario_from(base_scenario()), GenerationParams())
    assert rec.verdict is Verdict.INCONCLUSIVE


def test_repeats_use_incrementing_seeds() -> None:
    adapter = ScriptedAdapter(lambda msgs: "no")
    s = scenario_from(base_scenario())
    records = run_scenarios(adapter, "m", [s], GenerationParams(seed=100), repeat=3)
    assert [r.seed for r in records] == [100, 101, 102]
    assert [c[1].seed for c in adapter.calls] == [100, 101, 102]
    assert [r.repeat for r in records] == [0, 1, 2]


def test_run_aborts_after_consecutive_errors() -> None:
    adapter = ScriptedAdapter(lambda msgs: AdapterError("down"))
    s = scenario_from(base_scenario())
    with pytest.raises(RunAborted, match="down"):
        run_scenarios(adapter, "m", [s] * 5, GenerationParams(), abort_after_errors=3)
    assert len(adapter.calls) == 3


def test_progress_callback_receives_every_record() -> None:
    seen = []
    adapter = ScriptedAdapter(lambda msgs: "no")
    s = scenario_from(base_scenario())
    run_scenarios(
        adapter,
        "m",
        [s, s],
        GenerationParams(),
        repeat=2,
        progress=lambda done, total, sc, r: seen.append((done, total)),
    )
    assert seen == [(1, 4), (2, 4), (3, 4), (4, 4)]


def test_record_serialises_to_plain_json_types() -> None:
    import json

    adapter = ScriptedAdapter(lambda msgs: "no")
    rec = execute_scenario(adapter, "m", scenario_from(base_scenario()), GenerationParams())
    data = json.loads(json.dumps(rec.to_dict()))
    assert data["verdict"] == "PASS"
    assert data["checks"][0]["type"] == "secret_leak"
