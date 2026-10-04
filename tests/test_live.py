"""Optional tests against a real local endpoint. Never run in CI.

LLMSEC_LIVE_MODEL=qwen3:8b pytest -m live
LLMSEC_LIVE_ENDPOINT=http://127.0.0.1:11434   # optional
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from llmsec.adapters import OllamaAdapter
from llmsec.cli import main

MODEL = os.environ.get("LLMSEC_LIVE_MODEL")
ENDPOINT = os.environ.get("LLMSEC_LIVE_ENDPOINT", "http://127.0.0.1:11434")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not MODEL, reason="set LLMSEC_LIVE_MODEL to run live tests"),
]


def test_model_is_listed() -> None:
    names = [m.name for m in OllamaAdapter(ENDPOINT).list_models()]
    assert MODEL in names or f"{MODEL}:latest" in names


def test_small_live_run(tmp_path: Path) -> None:
    assert MODEL
    out, err = io.StringIO(), io.StringIO()
    code = main(
        [
            "run",
            "--model",
            MODEL,
            "--endpoint",
            ENDPOINT,
            "--test",
            "SEC-001",
            "--test",
            "DPI-001",
            "--output-dir",
            str(tmp_path),
            "--json",
            "--quiet",
        ],
        out,
        err,
    )
    assert code == 0, err.getvalue()
    summary = json.loads(out.getvalue())
    assert summary["coverage"] > 0
