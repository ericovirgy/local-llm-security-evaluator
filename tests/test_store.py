from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from llmsec import RESULT_SCHEMA
from llmsec.scoring import compute_metrics
from llmsec.store import (
    RUN_ID_RE,
    StoreError,
    base_manifest,
    create_run_dir,
    load_run,
    new_run_id,
    write_run,
)


def minimal_results(run_id: str) -> dict[str, object]:
    record = {
        "scenario_id": "A-001",
        "verdict": "PASS",
        "severity": "high",
        "category": "direct_injection",
        "repeat": 0,
        "latency_s": 1.0,
    }
    return {
        "schema": RESULT_SCHEMA,
        "run_id": run_id,
        "metrics": compute_metrics([record]),
        "scenarios": {},
        "executions": [record],
    }


def test_run_ids_are_well_formed_and_unique() -> None:
    now = datetime(2026, 10, 4, 12, 0, 0, tzinfo=UTC)
    ids = {new_run_id(now) for _ in range(50)}
    assert len(ids) == 50
    assert all(RUN_ID_RE.match(i) for i in ids)
    assert next(iter(ids)).startswith("run-20261004T120000Z-")


@pytest.mark.parametrize(
    "bad",
    [
        "../escape",
        "run-1",
        "/etc/passwd",
        "run-20261004T120000Z-zzzzzz",
        "run-20261004T120000Z-abcdef/..",
    ],
)
def test_invalid_run_ids_are_rejected(tmp_path: Path, bad: str) -> None:
    with pytest.raises(StoreError, match="invalid run id"):
        create_run_dir(tmp_path, bad)


def test_existing_run_directory_is_never_overwritten(tmp_path: Path) -> None:
    rid = new_run_id()
    create_run_dir(tmp_path, rid)
    with pytest.raises(StoreError, match="refusing to overwrite"):
        create_run_dir(tmp_path, rid)


def test_write_and_load_roundtrip_with_integrity(tmp_path: Path) -> None:
    rid = new_run_id()
    run_dir = create_run_dir(tmp_path, rid)
    write_run(run_dir, base_manifest(rid), minimal_results(rid), "# report\n")
    assert sorted(p.name for p in run_dir.iterdir()) == [
        "manifest.json",
        "report.md",
        "results.json",
    ]
    manifest, results, ok = load_run(run_dir)
    assert ok is True
    assert manifest["run_id"] == rid
    assert results["schema"] == RESULT_SCHEMA
    _, _, ok2 = load_run(run_dir / "results.json")
    assert ok2 is True


def test_modified_results_are_detected(tmp_path: Path) -> None:
    rid = new_run_id()
    run_dir = create_run_dir(tmp_path, rid)
    write_run(run_dir, base_manifest(rid), minimal_results(rid), "")
    path = run_dir / "results.json"
    data = json.loads(path.read_text())
    data["metrics"]["status"] = "PASS"
    path.write_text(json.dumps(data))
    assert load_run(run_dir)[2] is False


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "not valid JSON"),
        ("[1,2]", "JSON object"),
        ('{"schema": "other/9"}', "unsupported schema"),
        (
            json.dumps({"schema": RESULT_SCHEMA, "metrics": [], "executions": [], "scenarios": {}}),
            "metrics",
        ),
    ],
)
def test_malformed_results_are_rejected(tmp_path: Path, content: str, message: str) -> None:
    (tmp_path / "results.json").write_text(content)
    with pytest.raises(StoreError, match=message):
        load_run(tmp_path)


def test_no_temp_files_left_behind(tmp_path: Path) -> None:
    rid = new_run_id()
    run_dir = create_run_dir(tmp_path, rid)
    write_run(run_dir, base_manifest(rid), minimal_results(rid), "")
    assert not [p for p in run_dir.iterdir() if p.name.startswith(".tmp-")]
