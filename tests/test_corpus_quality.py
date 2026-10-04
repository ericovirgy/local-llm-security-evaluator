"""Properties every built-in scenario must have. These guard the corpus itself."""

from __future__ import annotations

from pathlib import Path

import pytest

from llmsec.adapters import GenerationParams, ReferenceAdapter
from llmsec.corpus import CATEGORIES, CanaryKind, resolve_suite
from llmsec.engine import execute_scenario
from llmsec.evaluation import Verdict

SUITE = resolve_suite("core")
DOCS = Path(__file__).resolve().parents[1] / "docs"


@pytest.mark.parametrize("scenario", SUITE.scenarios, ids=lambda s: s.id)
def test_scenario_metadata_is_complete(scenario) -> None:
    assert len(scenario.description) > 40
    assert len(scenario.rationale) > 40
    assert len(scenario.expected_behaviour) > 20
    assert scenario.tags
    assert scenario.id.split("-")[0] in {"DPI", "IPI", "SEC", "HIE", "OBF", "CTX", "MTP", "UNS"}


@pytest.mark.parametrize("scenario", SUITE.scenarios, ids=lambda s: s.id)
def test_markers_are_derived(scenario) -> None:
    """Every marker must be derived so a model that quotes the attack cannot trip it."""
    for canary in scenario.canaries:
        if canary.kind is CanaryKind.MARKER:
            assert canary.derived, canary.name


@pytest.mark.parametrize("scenario", SUITE.scenarios, ids=lambda s: s.id)
def test_echo_never_trips_marker_checks(scenario) -> None:
    """Echoing the input verbatim must not count as following an injected instruction."""
    rec = execute_scenario(ReferenceAdapter(), "echo", scenario, GenerationParams())
    for check in rec.checks:
        if check["type"] == "marker_absent":
            assert check["passed"], check


@pytest.mark.parametrize("scenario", SUITE.scenarios, ids=lambda s: s.id)
def test_echo_trips_every_secret_check(scenario) -> None:
    """The leaky echo baseline must be caught by every secret check."""
    rec = execute_scenario(ReferenceAdapter(), "echo", scenario, GenerationParams())
    for check in rec.checks:
        if check["type"] == "secret_leak":
            assert not check["passed"], check


@pytest.mark.parametrize("scenario", SUITE.scenarios, ids=lambda s: s.id)
def test_plain_refusal_is_never_scored_as_compromise(scenario) -> None:
    """A fixed refusal must not FAIL on secret, marker or action checks."""
    rec = execute_scenario(ReferenceAdapter(), "refuse", scenario, GenerationParams())
    for check in rec.checks:
        if check["type"] in {"secret_leak", "marker_absent", "not_matches", "not_contains"}:
            assert check["passed"], check


def test_refusal_baseline_has_no_fail_outside_format_contracts() -> None:
    fails = []
    for s in SUITE.scenarios:
        rec = execute_scenario(ReferenceAdapter(), "refuse", s, GenerationParams())
        if rec.verdict is Verdict.FAIL:
            fails.append(s.id)
    # HIE-001 requires JSON output; a prose refusal breaks that contract by design.
    assert fails == ["HIE-001"]


def test_every_category_is_documented() -> None:
    text = (DOCS / "categories.md").read_text(encoding="utf-8")
    for key, label in CATEGORIES.items():
        assert f"`{key}`" in text, key
        assert label in text, label
