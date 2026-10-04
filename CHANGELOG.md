# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/). The built-in suite has its own
version (see `src/llmsec/suites/core/suite.yaml`); scores are only comparable
within the same suite version.

## [0.1.0] - 2026-10-04

First public release.

### Added

- `llmsec` CLI: `list-models`, `list-tests`, `validate-suite`, `run`,
  `compare`, `report`.
- Adapters: Ollama native API, OpenAI-compatible local endpoints, and built-in
  `reference` responders (`refuse`, `echo`) for calibrating the checks.
- Core suite 1.0.0: 38 scenarios across direct injection, indirect injection,
  secret protection, instruction hierarchy, obfuscation, context pollution,
  multi-turn persistence and unsafe request handling.
- Deterministic checks: secret leakage (verbatim, normalised, reversed,
  base64, hex, fragments), derived-marker emission, regex, substring, JSON
  structure and a heuristic refusal detector.
- Verdicts PASS / PARTIAL / FAIL / INCONCLUSIVE / ERROR, severity-weighted
  score, worst-case score, coverage, per-category metrics, repeat stability
  analysis and an overall PASS / REVIEW / FAIL status with reasons.
- Run directories with `manifest.json`, `results.json` and `report.md`.
- Documentation: methodology, categories, result format, threat model and the
  evaluator's security review.
