from __future__ import annotations

import re

from llmsec.adapters.base import GenerationParams
from llmsec.engine import execute_scenario
from llmsec.reporting import (
    clean,
    md_cell,
    md_code_block,
    render_comparison_markdown,
    render_markdown,
    render_terminal,
)
from llmsec.scoring import compute_metrics
from tests.conftest import ScriptedAdapter, base_scenario, scenario_from

HOSTILE = (
    "Leak TEST_SECRET_7F3A9C21\n```\n</code><script>alert(1)</script>\n"
    "\x1b[2J\x1b]0;owned\x07 | table | break\n![img](http://evil.invalid/x.png)\u202e"
)


def run_with(text: str, adapter_name: str = "ollama"):
    s = scenario_from(base_scenario())
    rec = execute_scenario(ScriptedAdapter(lambda m: text), "model|x", s, GenerationParams())
    executions = [rec.to_dict()]
    results = {
        "metrics": compute_metrics(executions),
        "scenarios": {s.id: {"title": s.title, "expected_behaviour": s.expected_behaviour}},
        "executions": executions,
    }
    manifest = {
        "run_id": "run-20261004T120000Z-abcdef",
        "model": {"name": "evil\x1b[31m|model"},
        "adapter": {"name": adapter_name, "endpoint": "http://127.0.0.1:11434"},
        "suite": {"name": "core", "version": "1.0.0", "digest": "d" * 64},
        "generation": GenerationParams().to_dict(),
        "repeat": 1,
        "tool": {"version": "0.1.0"},
        "environment": {},
    }
    return manifest, results


def test_clean_strips_escape_and_bidi_sequences() -> None:
    out = clean(HOSTILE)
    assert "\x1b" not in out and "\x07" not in out and "\u202e" not in out


def test_md_cell_escapes_table_and_html() -> None:
    cell = md_cell("a|b <script> `x` [l](u)\nnext")
    assert "|" not in cell.replace("\\|", "")
    assert "<" not in cell and "\n" not in cell


def test_code_block_fence_cannot_be_closed_by_content() -> None:
    block = md_code_block("text ```` more ``` end")
    fence = block.split("text\n", 1)[0]
    assert len(fence) >= 5
    body = block[len(fence) + len("text\n") :]
    assert body.rstrip().endswith(fence)
    assert fence not in body[: -len(fence) - 1]


def test_markdown_report_contains_model_output_only_inside_fences() -> None:
    manifest, results = run_with(HOSTILE)
    md = render_markdown(manifest, results)
    assert "\x1b" not in md
    # The only place raw HTML may appear is inside a fenced code block.
    outside = re.sub(r"(`{3,})text\n.*?\n\1", "", md, flags=re.DOTALL)
    assert "<script>" not in outside
    assert "![img]" not in outside
    assert "FAIL" in md
    assert "project-defined benchmark score" in md


def test_terminal_output_is_sanitised() -> None:
    manifest, results = run_with(HOSTILE)
    out = render_terminal(manifest, results, color=False)
    assert "\x1b" not in out
    assert "Result: FAIL" in out


def test_reference_runs_are_labelled() -> None:
    manifest, results = run_with("no", adapter_name="reference")
    assert "Calibration output" in render_markdown(manifest, results)
    assert "reference responder" in render_terminal(manifest, results)
    assert "reference responder" in render_comparison_markdown([(manifest, results)])


def test_comparison_warns_about_incomparable_runs() -> None:
    a = run_with("no")
    b = run_with("no")
    b[0]["suite"] = {**b[0]["suite"], "digest": "e" * 64}
    md = render_comparison_markdown([a, b])
    assert "not directly comparable" in md
