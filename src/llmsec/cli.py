"""Command-line interface. Parsing and orchestration only; no evaluation logic here."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from llmsec import RESULT_SCHEMA, __version__
from llmsec.adapters import ADAPTERS, AdapterError, GenerationParams, ModelAdapter, make_adapter
from llmsec.corpus import CATEGORIES, Scenario, Suite, SuiteError, load_suite, resolve_suite
from llmsec.engine import ExecutionRecord, RunAborted, run_scenarios
from llmsec.reporting import (
    clean,
    render_comparison_markdown,
    render_comparison_terminal,
    render_markdown,
    render_terminal,
)
from llmsec.scoring import compute_metrics
from llmsec.store import (
    StoreError,
    base_manifest,
    create_run_dir,
    load_run,
    new_run_id,
    write_atomic,
    write_run,
)

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2
EXIT_ENDPOINT = 3

_CONFIG_SCHEMA: dict[str, dict[str, type | tuple[type, ...]]] = {
    "endpoint": {
        "adapter": str,
        "url": str,
        "timeout_s": (int, float),
        "allow_remote": bool,
        "api_key_env": str,
    },
    "generation": {
        "temperature": (int, float),
        "seed": int,
        "max_tokens": int,
        "num_ctx": int,
        "top_p": (int, float),
    },
    "run": {"suite": str, "repeat": int, "output_dir": str},
}


class UsageError(Exception):
    pass


@dataclass
class Settings:
    adapter: str = "ollama"
    url: str | None = None
    timeout_s: float = 300.0
    allow_remote: bool = False
    api_key_env: str | None = None
    temperature: float = 0.0
    seed: int = 1234
    max_tokens: int = 768
    num_ctx: int = 8192
    top_p: float | None = None
    suite: str = "core"
    repeat: int = 1
    output_dir: str = "results"


def load_config(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise UsageError(f"cannot read config {path}: {exc}") from None
    flat: dict[str, Any] = {}
    for section, values in data.items():
        if section not in _CONFIG_SCHEMA or not isinstance(values, dict):
            raise UsageError(f"config: unknown section [{section}]")
        for key, value in values.items():
            expected = _CONFIG_SCHEMA[section].get(key)
            if expected is None:
                raise UsageError(f"config: unknown key {section}.{key}")
            if not isinstance(value, expected) or isinstance(value, bool) != (expected is bool):
                raise UsageError(f"config: {section}.{key} has the wrong type")
            flat["url" if key == "url" else key] = value
    return flat


def resolve_settings(args: argparse.Namespace) -> Settings:
    s = Settings()
    if getattr(args, "config", None):
        for key, value in load_config(Path(args.config)).items():
            setattr(s, key, value)
    mapping = {
        "adapter": "adapter",
        "endpoint": "url",
        "timeout": "timeout_s",
        "api_key_env": "api_key_env",
        "temperature": "temperature",
        "seed": "seed",
        "max_tokens": "max_tokens",
        "num_ctx": "num_ctx",
        "top_p": "top_p",
        "suite": "suite",
        "repeat": "repeat",
        "output_dir": "output_dir",
    }
    for arg, attr in mapping.items():
        value = getattr(args, arg, None)
        if value is not None:
            setattr(s, attr, value)
    if getattr(args, "allow_remote", False):
        s.allow_remote = True
    if s.adapter not in ADAPTERS:
        raise UsageError(f"unknown adapter {s.adapter!r}; choose from {', '.join(ADAPTERS)}")
    if not 0.0 <= s.temperature <= 2.0:
        raise UsageError("temperature must be between 0 and 2")
    if not 1 <= s.max_tokens <= 32768:
        raise UsageError("max-tokens must be between 1 and 32768")
    if not 1 <= s.repeat <= 50:
        raise UsageError("repeat must be between 1 and 50")
    if s.timeout_s <= 0:
        raise UsageError("timeout must be positive")
    return s


def build_adapter(s: Settings) -> ModelAdapter:
    return make_adapter(s.adapter, s.url, s.timeout_s, s.allow_remote, s.api_key_env or None)


def params_from(s: Settings) -> GenerationParams:
    return GenerationParams(
        temperature=float(s.temperature),
        seed=int(s.seed),
        max_tokens=int(s.max_tokens),
        num_ctx=int(s.num_ctx),
        top_p=None if s.top_p is None else float(s.top_p),
    )


def _validate_model_name(name: str) -> str:
    if not name or len(name) > 200 or clean(name, single_line=True) != name:
        raise UsageError("model name is empty, too long or contains control characters")
    return name


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- run


def _progress(stream: TextIO) -> Any:
    def report(done: int, total: int, scenario: Scenario, rec: ExecutionRecord) -> None:
        width = len(str(total))
        stream.write(
            f"[{done:>{width}}/{total}] {scenario.id:<8} r{rec.repeat} "
            f"{rec.verdict.value:<12} {rec.latency_s:6.1f}s  {scenario.title[:48]}\n"
        )
        stream.flush()

    return report


def execute_run(
    s: Settings,
    model: str,
    suite: Suite,
    categories: tuple[str, ...],
    ids: tuple[str, ...],
    quiet: bool,
    err: TextIO,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    adapter = build_adapter(s)
    scenarios = suite.select(categories, ids)
    if not scenarios:
        raise UsageError("the filters selected no scenarios")
    info = adapter.describe(model)
    params = params_from(s)
    run_id = new_run_id()
    started = _now()
    if not quiet:
        err.write(
            f"llmsec {__version__}: {len(scenarios)} scenario(s) x {s.repeat} against "
            f"{clean(model, True)} via {adapter.name} ({adapter.endpoint_label()})\n"
        )
    records = run_scenarios(
        adapter, model, scenarios, params, s.repeat, None if quiet else _progress(err)
    )
    finished = _now()
    executions = [r.to_dict() for r in records]
    metrics = compute_metrics(executions)
    manifest = base_manifest(run_id)
    manifest.update(
        {
            "started_at": started,
            "finished_at": finished,
            "model": info.to_dict(),
            "adapter": {"name": adapter.name, "endpoint": adapter.endpoint_label()},
            "suite": {
                "name": suite.name,
                "version": suite.version,
                "digest": suite.digest,
                "scenarios_selected": len(scenarios),
                "scenarios_total": len(suite.scenarios),
                "categories": list(categories),
                "ids": list(ids),
            },
            "generation": params.to_dict(),
            "repeat": s.repeat,
            "seed_policy": "repeat r uses seed + r",
        }
    )
    results = {
        "schema": RESULT_SCHEMA,
        "run_id": run_id,
        "metrics": metrics,
        "scenarios": {
            sc.id: {
                "title": sc.title,
                "category": sc.category,
                "severity": sc.severity.value,
                "description": sc.description,
                "expected_behaviour": sc.expected_behaviour,
                "rationale": sc.rationale,
                "tags": list(sc.tags),
                "source_file": sc.source_file,
            }
            for sc in scenarios
        },
        "executions": executions,
    }
    run_dir = create_run_dir(Path(s.output_dir), run_id)
    write_run(run_dir, manifest, results, render_markdown(manifest, results))
    return run_dir, manifest, results


def _summary_json(run_dir: Path, manifest: dict[str, Any], results: dict[str, Any]) -> str:
    m = results["metrics"]
    return json.dumps(
        {
            "run_id": manifest["run_id"],
            "run_dir": str(run_dir),
            "model": manifest["model"]["name"],
            "status": m["status"],
            "status_reasons": m["status_reasons"],
            "security_score": m["security_score"],
            "worst_case_score": m["worst_case_score"],
            "raw_pass_rate": m["raw_pass_rate"],
            "coverage": m["coverage"],
            "critical_failures": m["critical_failures"],
            "high_failures": m["high_failures"],
            "categories": {k: v["score"] for k, v in m["categories"].items()},
        },
        indent=2,
    )


def _fails_threshold(status: str, fail_on: str | None) -> bool:
    if fail_on == "fail":
        return status == "FAIL"
    if fail_on == "review":
        return status in {"FAIL", "REVIEW"}
    return False


def cmd_run(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    s = resolve_settings(args)
    model = _validate_model_name(args.model)
    suite = resolve_suite(s.suite)
    run_dir, manifest, results = execute_run(
        s, model, suite, tuple(args.category or ()), tuple(args.test or ()), args.quiet, err
    )
    if args.json:
        out.write(_summary_json(run_dir, manifest, results) + "\n")
    else:
        color = not args.no_color and out.isatty()
        out.write(render_terminal(manifest, results, color, str(run_dir / "report.md")) + "\n")
    return EXIT_THRESHOLD if _fails_threshold(results["metrics"]["status"], args.fail_on) else 0


def cmd_compare(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    runs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if args.runs:
        for path in args.runs:
            manifest, results, integrity = load_run(Path(path))
            if integrity is False:
                err.write(f"warning: {path}: results.json does not match its manifest digest\n")
            runs.append((manifest, results))
    else:
        s = resolve_settings(args)
        suite = resolve_suite(s.suite)
        cats, ids = tuple(args.category or ()), tuple(args.test or ())
        for model in args.models:
            _, manifest, results = execute_run(
                s, _validate_model_name(model), suite, cats, ids, args.quiet, err
            )
            runs.append((manifest, results))
    out.write(render_comparison_terminal(runs) + "\n")
    if args.output:
        target = Path(args.output)
        if target.exists() and not args.force:
            raise UsageError(f"{target} exists; pass --force to overwrite")
        write_atomic(target, render_comparison_markdown(runs).encode("utf-8"))
        err.write(f"comparison written to {target}\n")
    return 0


# --------------------------------------------------------------------------- other commands


def cmd_list_models(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    del err
    s = resolve_settings(args)
    adapter = build_adapter(s)
    models = adapter.list_models()
    if args.json:
        out.write(json.dumps([m.to_dict() for m in models], indent=2) + "\n")
        return 0
    if not models:
        out.write(f"No models available at {adapter.endpoint_label()}.\n")
        return 0
    for m in models:
        bits = [b for b in (m.parameter_size, m.quantization, m.family) if b]
        out.write(f"{clean(m.name, True):<40} {clean(' '.join(bits), True)}\n")
    return 0


def cmd_list_tests(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    del err
    suite = resolve_suite(args.suite)
    scenarios = suite.select(tuple(args.category or ()))
    if args.json:
        out.write(
            json.dumps(
                [
                    {
                        "id": sc.id,
                        "category": sc.category,
                        "severity": sc.severity.value,
                        "title": sc.title,
                        "tags": list(sc.tags),
                        "calls": sc.generation_points,
                    }
                    for sc in scenarios
                ],
                indent=2,
            )
            + "\n"
        )
        return 0
    out.write(f"Suite {suite.name} {suite.version}  ({len(scenarios)} scenarios)\n")
    out.write(f"digest sha256:{suite.digest}\n\n")
    for sc in scenarios:
        out.write(f"{sc.id:<8} {sc.category:<22} {sc.severity.value:<9} {sc.title}\n")
    return 0


def cmd_validate(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    del err
    suite = load_suite(Path(args.path))
    counts: dict[str, int] = {}
    for sc in suite.scenarios:
        counts[sc.category] = counts.get(sc.category, 0) + 1
    out.write(f"OK: suite {suite.name} {suite.version}, {len(suite.scenarios)} scenarios\n")
    for cat in CATEGORIES:
        if cat in counts:
            out.write(f"  {cat:<22} {counts[cat]}\n")
    out.write(f"digest sha256:{suite.digest}\n")
    return 0


def cmd_report(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    manifest, results, integrity = load_run(Path(args.run))
    if integrity is False:
        err.write(
            "warning: results.json does not match the digest recorded in manifest.json; "
            "the file changed after the run\n"
        )
    if args.format == "markdown":
        text = render_markdown(manifest, results)
    elif args.format == "json":
        text = json.dumps({"manifest": manifest, "metrics": results["metrics"]}, indent=2)
    else:
        color = not args.no_color and out.isatty() and not args.output
        text = render_terminal(manifest, results, color)
    if args.output:
        target = Path(args.output)
        if target.exists() and not args.force:
            raise UsageError(f"{target} exists; pass --force to overwrite")
        write_atomic(target, (text + "\n").encode("utf-8"))
        err.write(f"report written to {target}\n")
    else:
        out.write(text + "\n")
    return 0


# --------------------------------------------------------------------------- parser


def _endpoint_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("endpoint")
    g.add_argument("--config", help="TOML configuration file (see examples/llmsec.example.toml)")
    g.add_argument("--adapter", choices=ADAPTERS, help="model adapter (default: ollama)")
    g.add_argument("--endpoint", help="endpoint base URL (default depends on adapter)")
    g.add_argument("--timeout", type=float, help="per-request timeout in seconds")
    g.add_argument(
        "--allow-remote",
        action="store_true",
        help="permit non-loopback endpoints (prompts and outputs leave this machine)",
    )
    g.add_argument("--api-key-env", help="name of an env var holding a bearer token (openai only)")


def _run_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("evaluation")
    g.add_argument("--suite", help="built-in suite name or suite directory (default: core)")
    g.add_argument(
        "--category",
        action="append",
        choices=list(CATEGORIES),
        help="restrict to a category (repeatable)",
    )
    g.add_argument("--test", action="append", metavar="ID", help="restrict to a scenario id")
    g.add_argument("--repeat", type=int, help="executions per scenario (default 1)")
    g.add_argument("--temperature", type=float)
    g.add_argument("--seed", type=int, help="base seed; repeat r uses seed + r")
    g.add_argument("--max-tokens", type=int)
    g.add_argument("--num-ctx", type=int, help="context window (ollama only)")
    g.add_argument("--top-p", type=float)
    g.add_argument("--output-dir", help="directory for run results (default: results)")
    g.add_argument("--quiet", action="store_true", help="no progress output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llmsec",
        description="Local-first security evaluation for LLMs. Measures behaviour under "
        "adversarial scenarios; never executes model output.",
    )
    parser.add_argument("--version", action="version", version=f"llmsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list-models", help="list models exposed by the endpoint")
    _endpoint_opts(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list_models)

    p = sub.add_parser("list-tests", help="list scenarios in a suite")
    p.add_argument("--suite", default="core")
    p.add_argument("--category", action="append", choices=list(CATEGORIES))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list_tests)

    p = sub.add_parser("validate-suite", help="validate a scenario suite directory")
    p.add_argument("path")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("run", help="evaluate one model")
    p.add_argument("--model", required=True)
    _endpoint_opts(p)
    _run_opts(p)
    p.add_argument("--json", action="store_true", help="print a JSON summary instead of text")
    p.add_argument("--no-color", action="store_true")
    p.add_argument(
        "--fail-on",
        choices=["review", "fail"],
        help="exit 1 if the overall status is at or above this level",
    )
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("compare", help="evaluate several models, or compare stored runs")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--models", nargs="+", metavar="MODEL")
    src.add_argument("--runs", nargs="+", metavar="RUN_DIR")
    _endpoint_opts(p)
    _run_opts(p)
    p.add_argument("--output", help="also write the comparison as Markdown to this file")
    p.add_argument("--force", action="store_true", help="overwrite --output if it exists")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("report", help="render a stored run")
    p.add_argument("run", help="run directory or results.json")
    p.add_argument("--format", choices=["terminal", "markdown", "json"], default="terminal")
    p.add_argument("--output", help="write to a file instead of stdout")
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.set_defaults(func=cmd_report)
    return parser


def main(
    argv: Sequence[str] | None = None, out: TextIO | None = None, err: TextIO | None = None
) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args, out, err))
    except (UsageError, SuiteError, StoreError) as exc:
        err.write(f"error: {clean(exc)}\n")
        return EXIT_USAGE
    except (AdapterError, RunAborted) as exc:
        err.write(f"error: {clean(exc)}\n")
        return EXIT_ENDPOINT
    except KeyboardInterrupt:
        err.write("interrupted\n")
        return 130
