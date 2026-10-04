# Contributing

Contributions are welcome, especially new scenarios with a clear rationale,
and improvements to the deterministic checks.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate            # fish: source .venv/bin/activate.fish
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests && mypy && pytest
```

The test suite never needs a running model. Live tests against a real local
endpoint are opt-in:

```bash
LLMSEC_LIVE_MODEL=qwen3:8b pytest -m live
```

## Adding a scenario

1. Pick the category directory under `src/llmsec/suites/core/` and the next
   free id (`DPI-006`, `SEC-007`, ...).
2. Fill in every field: `description`, `rationale` (why it matters) and
   `expected_behaviour` are part of the evidence a reader sees in reports.
3. Use only synthetic values: secrets like `TEST_SECRET_XXXXXXXX`, domains under
   `.invalid` or `.example`, actions as text lines.
4. When testing whether an injected instruction was followed, use a **derived
   marker**: describe how to build the token instead of writing it. The loader
   rejects a derived marker that appears literally in the input.
5. Give at least one `on_fail: fail` check that captures the security property,
   and `partial` checks for task preservation.
6. Run `llmsec validate-suite src/llmsec/suites/core` and `pytest`. The corpus
   tests check, for every scenario, that the `echo` baseline never trips a
   marker and the `refuse` baseline is never scored as compromised.
7. Bump the suite version in `suite.yaml` (minor for added scenarios, major for
   changed ones) and note it in `CHANGELOG.md`. Scores across suite versions are
   not comparable.

Avoid adding scenarios that only rephrase an existing one. A smaller suite
with a clear rationale per scenario is the goal.

## Code changes

- Keep the evaluator observational. Nothing a model returns may be executed,
  rendered as HTML, used as a path or interpreted as a template.
- Prefer substring checks (`contains_all`, `not_contains`) to regexes. When a
  regex is needed, avoid unbounded `.*` between two alternatives and use
  bounded quantifiers such as `[^)\n]{0,300}`.
- New check types need tests for both passing and failing responses, and an
  entry in `docs/methodology.md`.
- Keep runtime dependencies minimal (currently only PyYAML).
