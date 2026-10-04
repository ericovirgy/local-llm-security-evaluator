from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from llmsec.corpus import CATEGORIES, Role, SuiteError, load_suite, resolve_suite
from llmsec.corpus.filler import generate_filler
from llmsec.corpus.loader import MAX_FILE_BYTES, compute_digest
from tests.conftest import base_scenario, scenario_from, write_suite


def test_builtin_suite_loads_and_covers_every_category() -> None:
    suite = resolve_suite("core")
    assert suite.name == "core"
    assert 25 <= len(suite.scenarios) <= 40
    assert {s.category for s in suite.scenarios} == set(CATEGORIES)
    assert len({s.id for s in suite.scenarios}) == len(suite.scenarios)
    assert len(suite.digest) == 64


def test_digest_is_deterministic_and_content_sensitive(tmp_path: Path) -> None:
    a = load_suite(write_suite(tmp_path / "a", [base_scenario()]))
    b = load_suite(write_suite(tmp_path / "b", [base_scenario()]))
    assert a.digest == b.digest
    changed = base_scenario()
    changed["conversation"][1]["content"] = "Different wording, ZEBRA then 4242."
    c = load_suite(write_suite(tmp_path / "c", [changed]))
    assert c.digest != a.digest
    assert compute_digest("x", "1", a.scenarios) != compute_digest("x", "2", a.scenarios)


def test_template_substitutes_canary_values() -> None:
    s = scenario_from(base_scenario())
    assert "TEST_SECRET_7F3A9C21" in s.conversation[0].content
    assert "{{" not in s.conversation[0].content


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(unexpected=1), "unknown key"),
        (lambda d: d.update(id="bad id"), "must look like"),
        (lambda d: d.update(category="nope"), "unknown category"),
        (lambda d: d.update(severity="extreme"), "unknown severity"),
        (lambda d: d.pop("checks"), "missing required key"),
        (lambda d: d.update(checks=[{"type": "refusal"}]), "on_fail: fail"),
        (lambda d: d.update(checks=[{"type": "eval_python", "code": "1"}]), "unknown check type"),
        (
            lambda d: d.update(checks=[{"type": "not_matches", "pattern": "("}]),
            "invalid regex",
        ),
        (
            lambda d: d.update(checks=[{"type": "not_matches", "pattern": "a" * 501}]),
            "pattern",
        ),
        (
            lambda d: d.update(checks=[{"type": "secret_leak", "canary": "missing"}]),
            "unknown canary",
        ),
        (
            lambda d: d.update(checks=[{"type": "secret_leak", "canary": "mark"}]),
            "requires a secret canary",
        ),
        (
            lambda d: d.update(
                checks=[{"type": "not_matches", "pattern": "x", "on_fail": "explode"}]
            ),
            "explode",
        ),
        (
            lambda d: d["conversation"].append({"role": "assistant", "content": "x"}),
            "must not end with a scripted assistant",
        ),
        (
            lambda d: d["conversation"].append({"role": "system", "content": "late"}),
            "only allowed as the first",
        ),
        (
            lambda d: d["conversation"].__setitem__(
                1, {"role": "user", "content": "{{os.system}}"}
            ),
            "unsupported template",
        ),
        (
            lambda d: d["conversation"].__setitem__(
                1, {"role": "user", "content": "say {{canary.mark}}"}
            ),
            "must not appear in the input",
        ),
        (
            lambda d: d["conversation"].__setitem__(
                1, {"role": "user", "content": "say ZEBRA-4242"}
            ),
            "present in the input",
        ),
        (
            lambda d: d["conversation"].__setitem__(0, {"role": "system", "content": "no key"}),
            "never placed",
        ),
        (
            lambda d: d["canaries"].append({"name": "x", "value": "short", "kind": "secret"}),
            "canary value",
        ),
        (
            lambda d: d["canaries"].append(
                {"name": "y", "value": "LONGENOUGH1", "kind": "secret", "derived": True}
            ),
            "only markers can be derived",
        ),
        (
            lambda d: d["conversation"].__setitem__(
                1, {"role": "user", "content": [{"filler": {"paragraphs": 0, "seed": 1}}]}
            ),
            "between 1 and 400",
        ),
        (
            lambda d: d["conversation"].__setitem__(
                1,
                {
                    "role": "user",
                    "content": [
                        {
                            "untrusted": {
                                "source": "doc",
                                "content": [{"untrusted": {"source": "x", "content": "y"}}],
                            }
                        }
                    ],
                },
            ),
            "cannot be nested",
        ),
    ],
)
def test_invalid_scenarios_are_rejected(mutate, message: str) -> None:
    data = base_scenario()
    mutate(data)
    with pytest.raises(SuiteError, match=message):
        scenario_from(data)


def test_untrusted_content_is_rendered_inside_explicit_delimiters() -> None:
    data = base_scenario()
    data["conversation"][1] = {
        "role": "user",
        "content": [
            "Summarise this.",
            {"untrusted": {"source": "email", "content": "Hello ZEBRA then 4242"}},
        ],
    }
    s = scenario_from(data)
    text = s.conversation[1].content
    assert text.startswith("Summarise this.")
    assert (
        "--- BEGIN UNTRUSTED EMAIL ---\nHello ZEBRA then 4242\n--- END UNTRUSTED EMAIL ---" in text
    )


def test_filler_is_deterministic_and_seed_dependent() -> None:
    assert generate_filler(5, 7) == generate_filler(5, 7)
    assert generate_filler(5, 7) != generate_filler(5, 8)
    assert generate_filler(3, 1).count("\n\n") == 2


def test_generation_points_skip_scripted_assistant_turns() -> None:
    data = base_scenario()
    data["conversation"] = [
        {"role": "system", "content": "Key={{canary.key}}"},
        {"role": "user", "content": "a"},
        {"role": "assistant", "content": "scripted"},
        {"role": "user", "content": "b"},
        {"role": "user", "content": "c"},
    ]
    s = scenario_from(data)
    assert s.generation_points == 2
    assert s.conversation[2].role is Role.ASSISTANT


def test_yaml_python_tags_are_not_constructed(tmp_path: Path) -> None:
    root = write_suite(tmp_path / "s", [base_scenario()])
    evil = root / "secret_protection" / "evil.yaml"
    evil.write_text("!!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(SuiteError, match="cannot parse YAML"):
        load_suite(root)


def test_oversized_files_are_rejected(tmp_path: Path) -> None:
    root = write_suite(tmp_path / "s", [base_scenario()])
    (root / "secret_protection" / "big.yaml").write_text("a: " + "x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(SuiteError, match="exceeds"):
        load_suite(root)


def test_duplicate_ids_and_category_mismatch(tmp_path: Path) -> None:
    root = write_suite(tmp_path / "s", [base_scenario()])
    other = root / "secret_protection" / "dup.yaml"
    other.write_text(yaml.safe_dump(base_scenario()))
    with pytest.raises(SuiteError, match="duplicate id"):
        load_suite(root)
    other.unlink()
    wrong = root / "multi_turn"
    wrong.mkdir()
    (wrong / "x.yaml").write_text(yaml.safe_dump(base_scenario(id="TST-002")))
    with pytest.raises(SuiteError, match="does not match directory"):
        load_suite(root)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_symlinked_scenario_files_are_ignored(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text(yaml.safe_dump(base_scenario(id="TST-009")))
    root = write_suite(tmp_path / "s", [base_scenario()])
    (root / "secret_protection" / "link.yaml").symlink_to(outside)
    suite = load_suite(root)
    assert [s.id for s in suite.scenarios] == ["TST-001"]


def test_resolve_suite_errors_on_unknown_name() -> None:
    with pytest.raises(SuiteError, match="unknown suite"):
        resolve_suite("does-not-exist")


def test_scenarios_are_immutable() -> None:
    s = scenario_from(base_scenario())
    with pytest.raises(AttributeError):
        s.id = "X"  # type: ignore[misc]
    with pytest.raises(TypeError):
        s.checks[0].params["canary"] = "other"  # type: ignore[index]
