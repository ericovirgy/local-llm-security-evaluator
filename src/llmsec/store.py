"""Run directory layout, atomic writes and loading results back.

Layout::

    <output-dir>/<run-id>/manifest.json
    <output-dir>/<run-id>/results.json
    <output-dir>/<run-id>/report.md

Run identifiers are generated here and validated on load; nothing derived
from model names or model output is ever used as a path component.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from llmsec import RESULT_SCHEMA, __version__

RUN_ID_RE = re.compile(r"^run-\d{8}T\d{6}Z-[0-9a-f]{6}$")
MAX_LOAD_BYTES = 256 * 1024 * 1024


class StoreError(RuntimeError):
    """A run directory could not be written or read safely."""


def new_run_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{stamp}-{secrets.token_hex(3)}"


def environment_info() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.system(),
        "machine": platform.machine(),
    }


def create_run_dir(output_dir: Path, run_id: str) -> Path:
    if not RUN_ID_RE.match(run_id):
        raise StoreError(f"invalid run id {run_id!r}")
    base = Path(output_dir).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    run_dir = base / run_id
    try:
        run_dir.mkdir(exist_ok=False)
    except FileExistsError:
        raise StoreError(f"{run_dir} already exists; refusing to overwrite") from None
    return run_dir


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n").encode("utf-8")


def write_atomic(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=path.suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_run(
    run_dir: Path, manifest: dict[str, Any], results: dict[str, Any], report_md: str
) -> None:
    results_bytes = _dump(results)
    manifest = dict(manifest)
    manifest["results_sha256"] = hashlib.sha256(results_bytes).hexdigest()
    write_atomic(run_dir / "results.json", results_bytes)
    write_atomic(run_dir / "manifest.json", _dump(manifest))
    write_atomic(run_dir / "report.md", report_md.encode("utf-8"))


def base_manifest(run_id: str) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "tool": {"name": "llmsec", "version": __version__},
        "run_id": run_id,
        "environment": environment_info(),
    }


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StoreError(f"{path} not found")
    if path.stat().st_size > MAX_LOAD_BYTES:
        raise StoreError(f"{path} is too large to load")
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise StoreError(f"{path} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise StoreError(f"{path} does not contain a JSON object")
    return data


def load_run(path: Path) -> tuple[dict[str, Any], dict[str, Any], bool | None]:
    """Load ``(manifest, results, integrity_ok)`` from a run directory or results.json.

    ``integrity_ok`` is ``None`` when no manifest digest is available. A digest
    mismatch means the file changed after the run; it does not prove tampering
    or its absence.
    """
    path = Path(path)
    run_dir = path if path.is_dir() else path.parent
    results_path = run_dir / "results.json"
    results = _read_json(results_path)
    if results.get("schema") != RESULT_SCHEMA:
        raise StoreError(
            f"{results_path}: unsupported schema {results.get('schema')!r} "
            f"(expected {RESULT_SCHEMA})"
        )
    for key, kind in (("metrics", dict), ("executions", list), ("scenarios", dict)):
        if not isinstance(results.get(key), kind):
            raise StoreError(f"{results_path}: '{key}' missing or malformed")
    manifest_path = run_dir / "manifest.json"
    manifest = _read_json(manifest_path) if manifest_path.is_file() else {}
    integrity: bool | None = None
    digest = manifest.get("results_sha256")
    if isinstance(digest, str):
        integrity = hashlib.sha256(results_path.read_bytes()).hexdigest() == digest
    return manifest, results, integrity
