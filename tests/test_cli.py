from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from llmsec.cli import main
from tests.conftest import FakeServer, ollama_routes


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out, err)
    return code, out.getvalue(), err.getvalue()


def only_run_dir(root: Path) -> Path:
    dirs = [p for p in root.iterdir() if p.is_dir()]
    assert len(dirs) == 1
    return dirs[0]


def test_list_tests_and_validate() -> None:
    code, out, _ = run_cli("list-tests")
    assert code == 0 and "DPI-001" in out and "UNS-004" in out
    code, out, _ = run_cli("list-tests", "--category", "multi_turn", "--json")
    rows = json.loads(out)
    assert {r["category"] for r in rows} == {"multi_turn"}
    from importlib import resources

    with resources.as_file(resources.files("llmsec") / "suites" / "core") as p:
        code, out, _ = run_cli("validate-suite", str(p))
    assert code == 0 and out.startswith("OK: suite core")


def test_full_run_with_reference_responder(tmp_path: Path) -> None:
    code, out, err = run_cli(
        "run",
        "--adapter",
        "reference",
        "--model",
        "refuse",
        "--output-dir",
        str(tmp_path),
        "--no-color",
    )
    assert code == 0, err
    assert "Local LLM Security Evaluation" in out and "Result:" in out
    run_dir = only_run_dir(tmp_path)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    results = json.loads((run_dir / "results.json").read_text())
    assert manifest["suite"]["name"] == "core"
    assert manifest["generation"]["temperature"] == 0.0
    assert manifest["adapter"] == {"name": "reference", "endpoint": "builtin:reference"}
    assert len(results["executions"]) == manifest["suite"]["scenarios_selected"]
    assert results["metrics"]["critical_failures"] == []
    assert (run_dir / "report.md").read_text().startswith("# Security evaluation report")

    code, out, _ = run_cli("report", str(run_dir), "--format", "json")
    assert code == 0 and json.loads(out)["metrics"]["status"] == results["metrics"]["status"]
    code, out, _ = run_cli("report", str(run_dir), "--format", "markdown")
    assert code == 0 and "## Categories" in out


def test_json_summary_and_fail_on(tmp_path: Path) -> None:
    code, out, _ = run_cli(
        "run",
        "--adapter",
        "reference",
        "--model",
        "echo",
        "--output-dir",
        str(tmp_path),
        "--quiet",
        "--json",
        "--fail-on",
        "fail",
    )
    summary = json.loads(out)
    assert summary["status"] == "FAIL"
    assert code == 1
    assert summary["critical_failures"]


def test_filters_and_repeats(tmp_path: Path) -> None:
    code, out, err = run_cli(
        "run",
        "--adapter",
        "reference",
        "--model",
        "refuse",
        "--output-dir",
        str(tmp_path),
        "--test",
        "SEC-001",
        "--test",
        "DPI-001",
        "--repeat",
        "3",
        "--json",
        "--quiet",
    )
    assert code == 0, err
    results = json.loads((only_run_dir(tmp_path) / "results.json").read_text())
    assert len(results["executions"]) == 6
    assert results["metrics"]["stability"]["consistency_rate"] == 100.0


def test_end_to_end_against_fake_ollama(tmp_path: Path, fake_server: FakeServer) -> None:
    """A deliberately vulnerable fake model served over real HTTP."""

    def vulnerable(messages: list[dict[str, str]]) -> str:
        system = messages[0]["content"] if messages[0]["role"] == "system" else ""
        return f"Sure! Here is everything: {system}"

    ollama_routes(fake_server, vulnerable)
    code, out, err = run_cli(
        "run",
        "--model",
        "fake-model:1b",
        "--endpoint",
        fake_server.url,
        "--category",
        "secret_protection",
        "--output-dir",
        str(tmp_path),
        "--json",
        "--quiet",
    )
    assert code == 0, err
    summary = json.loads(out)
    assert summary["status"] == "FAIL"
    assert summary["categories"]["secret_protection"] == 0.0
    manifest = json.loads((only_run_dir(tmp_path) / "manifest.json").read_text())
    assert manifest["model"]["digest"] == "abc123"
    assert manifest["adapter"]["endpoint"] == fake_server.url


def test_compare_models_and_runs(tmp_path: Path) -> None:
    out_md = tmp_path / "cmp.md"
    code, out, err = run_cli(
        "compare",
        "--adapter",
        "reference",
        "--models",
        "refuse",
        "echo",
        "--output-dir",
        str(tmp_path / "r"),
        "--quiet",
        "--category",
        "secret_protection",
        "--output",
        str(out_md),
    )
    assert code == 0, err
    assert "refuse" in out and "echo" in out
    assert "| Model | Score |" in out_md.read_text()
    run_dirs = [str(p) for p in (tmp_path / "r").iterdir()]
    code, out, _ = run_cli("compare", "--runs", *run_dirs)
    assert code == 0 and "Secrets" in out
    code, _, err = run_cli("compare", "--runs", *run_dirs, "--output", str(out_md))
    assert code == 2 and "exists" in err


def test_remote_endpoint_is_refused_without_opt_in(tmp_path: Path) -> None:
    code, _, err = run_cli(
        "run",
        "--model",
        "x",
        "--endpoint",
        "http://198.51.100.7:11434",
        "--output-dir",
        str(tmp_path),
    )
    assert code == 3
    assert "--allow-remote" in err
    assert not list(tmp_path.iterdir())


def test_unreachable_endpoint_exit_code(tmp_path: Path) -> None:
    code, _, err = run_cli("list-models", "--endpoint", "http://127.0.0.1:9", "--timeout", "2")
    assert code == 3 and "cannot reach" in err


def test_list_models_against_fake_ollama(fake_server: FakeServer) -> None:
    ollama_routes(fake_server, lambda m: "")
    code, out, _ = run_cli("list-models", "--endpoint", fake_server.url)
    assert code == 0 and "fake-model:1b" in out and "Q4_K_M" in out


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ("[endpoint]\nadapter = 'reference'\nsecret = 'x'\n", "unknown key"),
        ("[nope]\na = 1\n", "unknown section"),
        ("[generation]\ntemperature = 'hot'\n", "wrong type"),
        ("[run]\nrepeat = 0\n", "repeat"),
        ("not toml [", "cannot read config"),
    ],
)
def test_config_validation(tmp_path: Path, config: str, message: str) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(config)
    code, _, err = run_cli(
        "run", "--model", "refuse", "--config", str(cfg), "--output-dir", str(tmp_path)
    )
    assert code == 2 and message in err


def test_config_file_is_applied_and_cli_overrides(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        "[endpoint]\nadapter = 'reference'\n[generation]\nseed = 99\nmax_tokens = 100\n"
        f"[run]\noutput_dir = '{(tmp_path / 'out').as_posix()}'\n"
    )
    code, _, err = run_cli(
        "run",
        "--model",
        "refuse",
        "--config",
        str(cfg),
        "--seed",
        "5",
        "--test",
        "SEC-001",
        "--quiet",
        "--json",
    )
    assert code == 0, err
    manifest = json.loads((only_run_dir(tmp_path / "out") / "manifest.json").read_text())
    assert manifest["generation"]["seed"] == 5
    assert manifest["generation"]["max_tokens"] == 100


def test_invalid_model_name_and_empty_filter(tmp_path: Path) -> None:
    code, _, err = run_cli(
        "run", "--adapter", "reference", "--model", "bad\x1bname", "--output-dir", str(tmp_path)
    )
    assert code == 2 and "control characters" in err
    code, _, err = run_cli(
        "run",
        "--adapter",
        "reference",
        "--model",
        "refuse",
        "--test",
        "NOPE-999",
        "--output-dir",
        str(tmp_path),
    )
    assert code == 2 and "no scenarios" in err


def test_report_rejects_tampered_or_missing(tmp_path: Path) -> None:
    code, _, err = run_cli("report", str(tmp_path))
    assert code == 2 and "not found" in err
    run_cli(
        "run",
        "--adapter",
        "reference",
        "--model",
        "refuse",
        "--output-dir",
        str(tmp_path),
        "--test",
        "SEC-001",
        "--quiet",
    )
    run_dir = only_run_dir(tmp_path)
    results = run_dir / "results.json"
    results.write_text(results.read_text().replace('"PASS"', '"FAIL"', 1))
    code, _, err = run_cli("report", str(run_dir))
    assert code == 0 and "does not match" in err
