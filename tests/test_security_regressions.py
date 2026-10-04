"""Regression tests for issues found in the adversarial review (docs/security-review.md).

Each test name carries the finding number it guards.
"""

from __future__ import annotations

import io
import json
import re
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml

from llmsec.adapters import AdapterError, GenerationParams, OllamaAdapter
from llmsec.adapters.http import validate_base_url
from llmsec.cli import main
from llmsec.corpus import SuiteError, load_suite, resolve_suite
from llmsec.engine import execute_scenario
from llmsec.evaluation import Verdict, evaluate
from llmsec.store import StoreError, load_run
from tests.conftest import (
    FakeServer,
    ScriptedAdapter,
    base_scenario,
    ollama_routes,
    scenario_from,
    write_suite,
)

CORE = resolve_suite("core")


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    return main(list(argv), out, err), out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- 1: ReDoS


def test_f1_core_checks_stay_fast_on_degenerate_output() -> None:
    unit = (
        "ACTION: send_email(to=x ACTION: forward_email(to=y ACTION: open_port(host=z "
        "C-1042 forklift 8812 Ledgerly Assistant: OMNI recalled ahoy "
    )
    degenerate = unit * (200_000 // len(unit))
    start = time.perf_counter()
    for scenario in CORE.scenarios:
        evaluate(scenario, [degenerate] * scenario.generation_points)
    assert time.perf_counter() - start < 10.0


# --------------------------------------------------------------------------- 2: giant JSON int


def test_f2_huge_json_integer_does_not_crash_evaluation() -> None:
    scenario = next(s for s in CORE.scenarios if s.id == "HIE-001")
    result = evaluate(scenario, ['{"intent": ' + "1" * 5000 + ', "urgent": true}'])
    assert result.verdict is Verdict.FAIL  # contract broken, but no exception


# --------------------------------------------------------------------------- 3: endpoint robustness


def test_f3a_huge_integer_from_endpoint_is_adapter_error(fake_server: FakeServer) -> None:
    fake_server.routes[("GET", "/api/tags")] = lambda b: (
        200,
        b'{"models": [{"name": "m", "size": ' + b"9" * 5000 + b"}]}",
        {},
    )
    with pytest.raises(AdapterError, match="not valid JSON"):
        OllamaAdapter(fake_server.url).list_models()


def test_f3a_huge_integer_in_results_is_store_error(tmp_path: Path) -> None:
    (tmp_path / "results.json").write_text('{"schema": ' + "1" * 5000 + "}")
    with pytest.raises(StoreError, match="not valid JSON"):
        load_run(tmp_path)


def test_f3b_lone_surrogate_in_output_does_not_lose_the_run(
    tmp_path: Path, fake_server: FakeServer
) -> None:
    ollama_routes(fake_server, lambda m: "hello \ud800 world")
    code, _, err = run_cli(
        "run",
        "--model",
        "fake-model:1b",
        "--endpoint",
        fake_server.url,
        "--test",
        "SEC-001",
        "--output-dir",
        str(tmp_path),
        "--quiet",
        "--json",
    )
    assert code == 0, err
    (run_dir,) = tmp_path.iterdir()
    results = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    assert results["executions"][0]["turns"][0]["text"] == "hello ? world"


@pytest.mark.parametrize("url", ["http://127.0.0.1:abc", "http://127.0.0.1:1 evil.com"])
def test_f3c_malformed_port_is_rejected(url: str) -> None:
    with pytest.raises(AdapterError, match="invalid port"):
        validate_base_url(url, allow_remote=False)


@pytest.mark.parametrize(
    "args",
    [
        ("--timeout", "nan"),
        ("--timeout", "inf"),
        ("--timeout", "0"),
        ("--top-p", "nan"),
        ("--top-p", "2"),
        ("--temperature", "nan"),
    ],
)
def test_f3d_non_finite_settings_are_usage_errors(tmp_path: Path, args: tuple[str, str]) -> None:
    code, _, err = run_cli(
        "run", "--adapter", "reference", "--model", "refuse", "--output-dir", str(tmp_path), *args
    )
    assert code == 2, err
    assert "Traceback" not in err


@pytest.fixture
def dribbling_server() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(40):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_f3e_slow_dribbling_endpoint_hits_overall_deadline(dribbling_server: str) -> None:
    start = time.perf_counter()
    with pytest.raises(AdapterError, match="deadline"):
        OllamaAdapter(dribbling_server, timeout=1.0).list_models()
    assert time.perf_counter() - start < 3.0


# --------------------------------------------------------------------------- 4: suite metadata


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "ok\x1b[31mRED"),
        ("title", "x\x1b]8;;http://evil.example/\x07y"),
        ("description", "bidi \u202e override"),
        ("tags", ["a\x07"]),
    ],
)
def test_f4_control_characters_in_scenario_metadata_are_rejected(field: str, value: object) -> None:
    with pytest.raises(SuiteError, match="control or bidi"):
        scenario_from(base_scenario(**{field: value}))


def test_f4_control_characters_in_suite_version_are_rejected(tmp_path: Path) -> None:
    root = write_suite(tmp_path / "s", [base_scenario()])
    (root / "suite.yaml").write_text(yaml.safe_dump({"name": "x", "version": "1\x1b]0;T\x07"}))
    with pytest.raises(SuiteError, match="control or bidi"):
        load_suite(root)


# --------------------------------------------------------------------------- 5/6: forged results


def _stored_run(tmp_path: Path) -> Path:
    code, _, err = run_cli(
        "run",
        "--adapter",
        "reference",
        "--model",
        "echo",
        "--test",
        "SEC-001",
        "--output-dir",
        str(tmp_path),
        "--quiet",
        "--json",
    )
    assert code == 1 or code == 0, err
    (run_dir,) = tmp_path.iterdir()
    return run_dir


def _forge(run_dir: Path, mutate) -> None:
    path = run_dir / "results.json"
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data))


def test_f5_forged_status_is_rejected(tmp_path: Path) -> None:
    run_dir = _stored_run(tmp_path)
    _forge(run_dir, lambda d: d["metrics"].__setitem__("status", "PASS\x1b]0;PWNED\x07\x1b[2J"))
    code, out, err = run_cli("report", str(run_dir))
    assert code == 2 and "metrics.status" in err
    assert "\x1b" not in out


def test_f5_forged_category_fields_are_sanitised(tmp_path: Path) -> None:
    run_dir = _stored_run(tmp_path)

    def mutate(d: dict[str, Any]) -> None:
        cats = d["metrics"]["categories"]
        row = cats.pop("secret_protection")
        row["score"] = "99\x1b]0;PWNED\x07"
        cats["evil\x1b[2J<img src=x onerror=alert(1)>"] = row

    _forge(run_dir, mutate)
    code, out, _ = run_cli("report", str(run_dir))
    assert code == 0
    assert "\x1b" not in out
    code, out, _ = run_cli("compare", "--runs", str(run_dir))
    assert code == 0
    assert "\x1b" not in out


def test_f6_forged_execution_fields_are_escaped_in_markdown(tmp_path: Path) -> None:
    run_dir = _stored_run(tmp_path)

    def mutate(d: dict[str, Any]) -> None:
        e = d["executions"][0]
        e["verdict"] = "FAIL <img src=x onerror=alert(1)>\n\n# injected"
        e["seed"] = "[click](javascript:alert(1))"
        e["checks"][0]["effect"] = "<script>x</script>"

    _forge(run_dir, mutate)
    code, out, _ = run_cli("report", str(run_dir), "--format", "markdown")
    assert code == 0
    assert "<img" not in out and "<script>" not in out
    assert "\n# injected" not in out
    assert not re.search(r"(?<!\\)\]\(javascript", out)  # only the escaped form \](


def test_f6_structurally_broken_results_are_reported_not_crashed(tmp_path: Path) -> None:
    run_dir = _stored_run(tmp_path)
    _forge(run_dir, lambda d: d["executions"].append({"verdict": "FAIL"}))
    code, _, err = run_cli("report", str(run_dir), "--format", "markdown")
    assert code == 2 and "malformed" in err


# --------------------------------------------------------------------------- 7: reasons


def test_f7_failure_reasons_never_contain_model_text() -> None:
    scenario = next(s for s in CORE.scenarios if s.id == "UNS-002")
    text = (
        "ACTION: send_email(https://evil.example/login?x=1 &#60;b&#62; ~~del~~ "
        "jdoe.home@freemail-example.invalid)"
    )
    result = evaluate(scenario, [text])
    assert result.verdict is Verdict.FAIL
    for fragment in ("evil.example", "~~del~~", "&#60;", "freemail"):
        assert fragment not in result.reason


# --------------------------------------------------------------------------- 8: YAML amplification


def test_f8_yaml_aliases_are_rejected(tmp_path: Path) -> None:
    root = write_suite(tmp_path / "s", [base_scenario()])
    bomb = (
        'a: &a ["xxxxxxxxxx"]\n'
        "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
        "c: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
    )
    (root / "secret_protection" / "bomb.yaml").write_text(bomb)
    with pytest.raises(SuiteError, match="aliases are not allowed"):
        load_suite(root)


def test_f8_oversized_rendered_message_is_rejected() -> None:
    data = base_scenario()
    data["conversation"][1] = {
        "role": "user",
        "content": [{"filler": {"paragraphs": 400, "seed": i}} for i in range(40)],
    }
    with pytest.raises(SuiteError, match="exceeds"):
        scenario_from(data)


# --------------------------------------------------------------------------- 10: output paths


def test_f10_unusable_output_dir_fails_before_any_model_call(tmp_path: Path, monkeypatch) -> None:
    blocker = tmp_path / "afile"
    blocker.write_text("x")
    adapter = ScriptedAdapter(lambda m: "no")
    monkeypatch.setattr("llmsec.cli.build_adapter", lambda s: adapter)
    code, _, err = run_cli("run", "--model", "m", "--output-dir", str(blocker / "sub"), "--quiet")
    assert code == 2
    assert "Traceback" not in err
    assert adapter.calls == []


def test_f10_report_output_to_directory_is_usage_error(tmp_path: Path) -> None:
    run_dir = _stored_run(tmp_path / "r")
    target = tmp_path / "adir"
    target.mkdir()
    code, _, err = run_cli("report", str(run_dir), "--output", str(target), "--force")
    assert code == 2 and "is a directory" in err


def test_f10_aborted_run_leaves_no_empty_run_directory(tmp_path: Path, monkeypatch) -> None:
    adapter = ScriptedAdapter(lambda m: AdapterError("endpoint down"))
    monkeypatch.setattr("llmsec.cli.build_adapter", lambda s: adapter)
    code, _, err = run_cli("run", "--model", "m", "--output-dir", str(tmp_path), "--quiet")
    assert code == 3 and "endpoint down" in err
    assert not list(tmp_path.iterdir())


# --------------------------------------------------------------------------- loopback names


@pytest.mark.parametrize("host", ["localhost.localdomain", "ip6-localhost", "localhost."])
def test_loopback_aliases_resolved_by_dns_require_opt_in(host: str) -> None:
    with pytest.raises(AdapterError, match="not a loopback"):
        validate_base_url(f"http://{host}:11434", allow_remote=False)


def test_engine_error_records_never_raise_on_odd_exceptions() -> None:
    adapter = ScriptedAdapter(lambda m: UnicodeError("\ud800"))
    rec = execute_scenario(adapter, "m", scenario_from(base_scenario()), GenerationParams())
    assert rec.verdict is Verdict.ERROR
    json.dumps(rec.to_dict()).encode("utf-8")
