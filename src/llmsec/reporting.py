"""Terminal, Markdown and comparison rendering.

Everything that originates from a model or an endpoint (responses, model names,
error strings) is treated as hostile text: control characters and terminal
escape sequences are stripped, Markdown table cells are escaped, and model
output is only ever placed inside fenced code blocks whose fence is longer than
any backtick run in the content. Nothing is rendered as HTML or executed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from llmsec.corpus.model import CATEGORIES

DISCLAIMER = (
    "This is a project-defined benchmark score, not a universal or industry-certified "
    "security rating. Results depend on the model, its configuration and this test suite. "
    "Passing does not prove a model is secure; failing a scenario does not by itself "
    "demonstrate a real-world vulnerability."
)
REFERENCE_NOTICE = (
    "Produced with a built-in reference responder (adapter 'reference'), not a language "
    "model. These numbers only illustrate how the checks behave and say nothing about any "
    "real model."
)

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
EXCERPT_CHARS = 1500


def clean(text: Any, single_line: bool = False) -> str:
    """Strip escape sequences, control and bidi-override characters."""
    s = _ANSI_RE.sub("", str(text))
    s = _CTRL_RE.sub("", s.replace("\r\n", "\n"))
    if single_line:
        s = " ".join(s.split())
    return s


def md_cell(text: Any) -> str:
    s = clean(text, single_line=True)
    for ch, rep in (
        ("\\", "\\\\"),
        ("|", "\\|"),
        ("`", "\\`"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("[", "\\["),
        ("]", "\\]"),
        ("*", "\\*"),
        ("_", "\\_"),
    ):
        s = s.replace(ch, rep)
    return s


def md_code_block(text: str, limit: int = EXCERPT_CHARS) -> str:
    body = clean(text)
    note = ""
    if len(body) > limit:
        note = (
            f"\n_(truncated: showing {limit} of {len(body)} characters; full text in results.json)_"
        )
        body = body[:limit]
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{body}\n{fence}{note}"


def _fmt(value: Any, suffix: str = "") -> str:
    return "n/a" if value is None else f"{value}{suffix}"


def _model_label(manifest: Mapping[str, Any]) -> str:
    model = manifest.get("model", {})
    return clean(model.get("name", "?"), single_line=True)


def _is_reference(manifest: Mapping[str, Any]) -> bool:
    return bool(manifest.get("adapter", {}).get("name") == "reference")


# --------------------------------------------------------------------------- terminal


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text


_STATUS_CODE = {"PASS": "1;32", "REVIEW": "1;33", "FAIL": "1;31"}


def _bar(score: float | None, width: int = 20) -> str:
    if score is None:
        return " " * width
    filled = round(width * score / 100)
    return "█" * filled + "░" * (width - filled)


def render_terminal(
    manifest: Mapping[str, Any],
    results: Mapping[str, Any],
    color: bool = False,
    report_path: str | None = None,
) -> str:
    st = _Style(color)
    m = results["metrics"]
    suite = manifest.get("suite", {})
    adapter = manifest.get("adapter", {})
    rule = "─" * 60
    lines = [st("Local LLM Security Evaluation", "1"), rule]
    if _is_reference(manifest):
        lines += [st("NOTE: reference responder, not a model. Calibration output only.", "1;33")]
    lines += [
        f"Model:    {_model_label(manifest)}  "
        f"({clean(adapter.get('name', '?'), True)} @ {clean(adapter.get('endpoint', '?'), True)})",
        f"Suite:    {clean(suite.get('name', '?'), True)} {clean(suite.get('version', ''), True)}"
        f"  ({m['scenarios']} scenarios x {m['repeats']} repeat(s) = {m['executions']} executions)",
        f"Run:      {clean(manifest.get('run_id', '?'), True)}",
        "",
        f"Security score:     {_fmt(m['security_score'])} / 100"
        + (f"   (worst case {_fmt(m['worst_case_score'])})" if m["repeats"] > 1 else ""),
        f"Raw pass rate:      {_fmt(m['raw_pass_rate'], '%')}",
        f"Coverage:           {m['coverage']:.0%}",
        f"Critical failures:  {len(m['critical_failures'])}",
        f"High failures:      {len(m['high_failures'])}",
        "Verdicts:           " + "  ".join(f"{k} {v}" for k, v in m["verdict_counts"].items() if v),
    ]
    lat = m["latency"]
    if lat["mean_s"] is not None:
        lines.append(
            f"Latency (s):        mean {lat['mean_s']}  median {lat['median_s']}  "
            f"p95 {lat['p95_s']}"
        )
    if m["repeats"] > 1:
        stab = m["stability"]
        lines.append(
            f"Consistency:        {_fmt(stab['consistency_rate'], '%')} of scenarios "
            "identical across repeats"
        )
        lines.append(
            "Stability:          " + ", ".join(f"{k} {v}" for k, v in stab["classes"].items())
        )
    lines += ["", f"{'Category':<30} {'Score':>6}  {'':20}  {'Fail':>5}"]
    for cat, row in m["categories"].items():
        label = CATEGORIES.get(cat, cat)
        lines.append(
            f"{label:<30} {_fmt(row['score']):>6}  {_bar(row['score'])}  "
            f"{len(row['failed_scenarios']):>5}"
        )
    status = m["status"]
    lines += ["", "Result: " + st(status, _STATUS_CODE.get(status, "1"))]
    lines += [f"  - {clean(r, True)}" for r in m["status_reasons"]]
    if report_path:
        lines += ["", f"Evidence: {clean(report_path, True)}"]
    lines += ["", st(DISCLAIMER, "2")]
    return "\n".join(lines)


# --------------------------------------------------------------------------- markdown


def render_markdown(manifest: Mapping[str, Any], results: Mapping[str, Any]) -> str:
    m = results["metrics"]
    suite = manifest.get("suite", {})
    adapter = manifest.get("adapter", {})
    model = manifest.get("model", {})
    gen = manifest.get("generation", {})
    out: list[str] = [f"# Security evaluation report: {md_cell(_model_label(manifest))}", ""]
    if _is_reference(manifest):
        out += [f"> **Calibration output.** {REFERENCE_NOTICE}", ""]
    out += [f"> {DISCLAIMER}", ""]

    out += ["## Result", "", f"**Status: {m['status']}**", ""]
    out += [f"- {md_cell(r)}" for r in m["status_reasons"]]
    out += [
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Security score (severity-weighted, 0-100) | {_fmt(m['security_score'])} |",
    ]
    if m["repeats"] > 1:
        out.append(f"| Worst-case score (minimum per scenario) | {_fmt(m['worst_case_score'])} |")
    out += [
        f"| Raw pass rate | {_fmt(m['raw_pass_rate'], '%')} |",
        f"| Coverage (determinate executions) | {m['coverage']:.0%} |",
        f"| Critical-severity failures | {len(m['critical_failures'])} |",
        f"| High-severity failures | {len(m['high_failures'])} |",
        f"| Scenarios / repeats / executions | {m['scenarios']} / {m['repeats']} / "
        f"{m['executions']} |",
        f"| Mean latency per execution | {_fmt(m['latency']['mean_s'], ' s')} |",
        f"| p95 latency per execution | {_fmt(m['latency']['p95_s'], ' s')} |",
        "",
        "Verdicts: " + ", ".join(f"{k} {v}" for k, v in m["verdict_counts"].items()),
        "",
        "## Categories",
        "",
        "| Category | Scenarios | Score | Pass rate | Failure rate | Failed scenarios |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for row in m["categories"].values():
        out.append(
            f"| {md_cell(row['label'])} | {row['scenarios']} | {_fmt(row['score'])} | "
            f"{_fmt(row['pass_rate'], '%')} | {_fmt(row['failure_rate'], '%')} | "
            f"{md_cell(', '.join(row['failed_scenarios']) or '-')} |"
        )

    if m["repeats"] > 1:
        out += [
            "",
            "## Stability across repeats",
            "",
            f"Consistency rate: {_fmt(m['stability']['consistency_rate'], '%')}",
            "",
            "| Class | Scenarios |",
            "|---|---:|",
        ]
        out += [f"| {md_cell(k)} | {v} |" for k, v in m["stability"]["classes"].items()]

    scenarios = results["scenarios"]
    out += [
        "",
        "## Scenario results",
        "",
        "| ID | Category | Severity | Verdict(s) | Stability | Title |",
        "|---|---|---|---|---|---|",
    ]
    for sid, row in m["per_scenario"].items():
        title = scenarios.get(sid, {}).get("title", "")
        out.append(
            f"| {md_cell(sid)} | {md_cell(row['category'])} | {md_cell(row['severity'])} | "
            f"{md_cell(' '.join(row['verdicts']))} | {md_cell(row['stability'])} | "
            f"{md_cell(title)} |"
        )

    notable = [e for e in results["executions"] if e["verdict"] != "PASS"]
    out += ["", "## Evidence for non-passing executions", ""]
    if not notable:
        out.append("Every execution passed. Full transcripts are in `results.json`.")
    for e in notable:
        meta = scenarios.get(e["scenario_id"], {})
        out += [
            f"### {md_cell(e['scenario_id'])} (repeat {e['repeat']}): {e['verdict']}",
            "",
            f"**{md_cell(meta.get('title', ''))}** | severity {md_cell(e['severity'])} | "
            f"seed {e['seed']} | {e['latency_s']} s",
            "",
            f"Expected behaviour: {md_cell(meta.get('expected_behaviour', ''))}",
            "",
            f"Verdict reason: {md_cell(e['reason'])}",
            "",
        ]
        if e["checks"]:
            out += ["| Check | Result | Detail |", "|---|---|---|"]
            for c in e["checks"]:
                res = "pass" if c["passed"] else f"**{c['effect']}**"
                out.append(f"| {md_cell(c['description'])} | {res} | {md_cell(c['reason'])} |")
            out.append("")
        for t in e["turns"]:
            label = f"Model response {t['index'] + 1}" if len(e["turns"]) > 1 else "Model response"
            out += [
                f"{label} (finish: {md_cell(t['finish_reason'] or 'n/a')}):",
                "",
                md_code_block(t["text"]),
                "",
            ]

    out += ["## Run configuration", "", "| Field | Value |", "|---|---|"]
    rows = [
        ("Run ID", manifest.get("run_id")),
        ("Started / finished", f"{manifest.get('started_at')} / {manifest.get('finished_at')}"),
        ("Model", model.get("name")),
        ("Model digest", model.get("digest")),
        (
            "Model family / size / quantization",
            f"{model.get('family')} / {model.get('parameter_size')} / {model.get('quantization')}",
        ),
        ("Adapter / endpoint", f"{adapter.get('name')} / {adapter.get('endpoint')}"),
        ("Suite", f"{suite.get('name')} {suite.get('version')}"),
        ("Suite digest (sha256)", suite.get("digest")),
        (
            "Filters",
            f"categories={suite.get('categories') or 'all'} ids={suite.get('ids') or 'all'}",
        ),
        ("Generation", ", ".join(f"{k}={v}" for k, v in gen.items())),
        ("Repeats", manifest.get("repeat")),
        ("Tool", f"llmsec {manifest.get('tool', {}).get('version')}"),
        ("Environment", ", ".join(f"{k}={v}" for k, v in manifest.get("environment", {}).items())),
    ]
    out += [f"| {k} | {md_cell(v)} |" for k, v in rows]
    out += ["", "Reproduce:", "", md_code_block(reproduce_command(manifest), 2000), ""]
    return "\n".join(out)


def reproduce_command(manifest: Mapping[str, Any]) -> str:
    adapter = manifest.get("adapter", {})
    suite = manifest.get("suite", {})
    gen = manifest.get("generation", {})
    parts = [
        "llmsec run",
        f"--adapter {adapter.get('name')}",
        f"--model {_model_label(manifest)}",
        f"--suite {suite.get('name')}",
        f"--repeat {manifest.get('repeat')}",
        f"--temperature {gen.get('temperature')}",
        f"--seed {gen.get('seed')}",
        f"--max-tokens {gen.get('max_tokens')}",
    ]
    if adapter.get("name") not in {"reference", None}:
        parts.append(f"--endpoint {adapter.get('endpoint')}")
    for cat in suite.get("categories") or []:
        parts.append(f"--category {cat}")
    for sid in suite.get("ids") or []:
        parts.append(f"--test {sid}")
    return clean(" ".join(str(p) for p in parts), single_line=True)


# --------------------------------------------------------------------------- comparison

_COMPARE_CATS = (
    ("direct_injection", "Injection"),
    ("indirect_injection", "Indirect"),
    ("secret_protection", "Secrets"),
    ("instruction_hierarchy", "Hierarchy"),
    ("obfuscation", "Obfusc."),
    ("context_pollution", "Pollution"),
    ("multi_turn", "Multi-turn"),
    ("unsafe_requests", "Unsafe"),
)


def comparison_rows(runs: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> list[list[str]]:
    rows = []
    for manifest, results in runs:
        m = results["metrics"]
        cats = m["categories"]
        rows.append(
            [
                _model_label(manifest),
                _fmt(m["security_score"]),
                m["status"],
                str(len(m["critical_failures"])),
                str(len(m["high_failures"])),
            ]
            + [_fmt(cats.get(c, {}).get("score")) for c, _ in _COMPARE_CATS]
            + [_fmt(m["latency"]["mean_s"], " s"), clean(manifest.get("run_id", ""), True)]
        )
    return rows


def _comparison_header() -> list[str]:
    return (
        ["Model", "Score", "Status", "Critical", "High"]
        + [label for _, label in _COMPARE_CATS]
        + ["Avg latency", "Run"]
    )


def _comparable(runs: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> list[str]:
    notes = []
    digests = {r[0].get("suite", {}).get("digest") for r in runs}
    if len(digests) > 1:
        notes.append(
            "Runs used different suite contents (digests differ); scores are not "
            "directly comparable."
        )
    gens = {tuple(sorted(r[0].get("generation", {}).items())) for r in runs}
    if len(gens) > 1:
        notes.append("Runs used different generation settings.")
    filters = {
        (
            tuple(r[0].get("suite", {}).get("categories") or ()),
            tuple(r[0].get("suite", {}).get("ids") or ()),
        )
        for r in runs
    }
    if len(filters) > 1:
        notes.append("Runs used different scenario filters.")
    if any(_is_reference(r[0]) for r in runs):
        notes.append(REFERENCE_NOTICE)
    return notes


def render_comparison_markdown(
    runs: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> str:
    header = _comparison_header()
    out = ["# Model comparison", "", f"> {DISCLAIMER}", ""]
    out += [f"> **Note:** {md_cell(n)}" for n in _comparable(runs)]
    aligns = ["---", "---:", "---"] + ["---:"] * (len(header) - 4) + ["---"]
    out += ["", "| " + " | ".join(header) + " |", "|" + "|".join(aligns) + "|"]
    out += ["| " + " | ".join(md_cell(c) for c in row) + " |" for row in comparison_rows(runs)]
    out.append("")
    return "\n".join(out)


def render_comparison_terminal(
    runs: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> str:
    header = _comparison_header()[:-1]
    rows = [r[:-1] for r in comparison_rows(runs)]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(header)]
    fmt = "  ".join(f"{{:<{w}}}" if i == 0 else f"{{:>{w}}}" for i, w in enumerate(widths))
    lines = [fmt.format(*header), "  ".join("─" * w for w in widths)]
    lines += [fmt.format(*r) for r in rows]
    lines += ["", *(_comparable(runs)), DISCLAIMER]
    return "\n".join(lines)
