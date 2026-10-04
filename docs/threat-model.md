# Threat model

Two different things need a threat model here: the **models being evaluated**
(what the scenarios simulate) and **the evaluator itself** (what could go
wrong when running it).

## A. What the scenarios simulate

| Actor | Capability assumed | Categories |
|---|---|---|
| Malicious user | Writes the user turn freely, can claim any identity, can persist across turns | direct_injection, instruction_hierarchy, secret_protection, multi_turn, unsafe_requests |
| Third-party content author | Controls a document, email, web page, data record or retrieved snippet that the user innocently passes to the model | indirect_injection, context_pollution, obfuscation |
| Client that controls history | Can submit forged earlier assistant turns | multi_turn (MTP-003) |

Assets protected in the scenarios: a synthetic secret in the system prompt,
the operator's instructions (task, format, scope, allowlists), and simulated
actions with consequences (data movement, destruction, exposure).

Not modelled: attackers with weight access, fine-tuning, adversarial suffix
optimisation (gradient-based attacks), adaptive attackers that react to the
model's responses, multimodal inputs, real tool or function-calling schemas,
and attacks on the serving infrastructure.

## B. The evaluator itself

The evaluator processes three kinds of untrusted input: **model output**,
**endpoint responses** and **custom suites / stored results** a user may have
received from someone else.

| Threat | Mitigation | Verified by |
|---|---|---|
| Model output is executed | Output is only compared against strings and regexes. No `eval`, no shell, no templating, no subprocess anywhere in the package. | `tests/test_engine.py::test_shell_like_output_is_never_executed`, code review |
| Model output alters the test definitions | Scenarios are frozen dataclasses with read-only mappings; generated text is appended to a separate history list. | `test_model_output_cannot_modify_the_scenario`, `test_scenarios_are_immutable` |
| Terminal escape injection via model output, model names or error strings | ANSI/OSC sequences, C0/C1 controls and bidi overrides are stripped before anything is printed. | `tests/test_reporting.py` |
| Markdown/HTML injection in `report.md` | Model output is only placed in fenced code blocks whose fence is longer than any backtick run in the content; table cells are escaped. | `tests/test_reporting.py` |
| Prompts and outputs leave the machine | Loopback endpoints only unless `--allow-remote`; HTTP proxy environment variables are ignored; redirects are refused; no telemetry. | `tests/test_adapters.py` |
| Credentials leak into results | Endpoint URLs with user-info are rejected; API keys are read from an env var at runtime and never stored. | `test_endpoint_validation`, `test_openai_compatible_adapter` |
| Malformed or hostile endpoint responses crash the run | Size cap, strict JSON shape validation, all failures mapped to `AdapterError`, which becomes an `ERROR` record. Repeated errors abort cleanly. | `test_malformed_ollama_responses_raise_adapter_error`, `test_run_aborts_after_consecutive_errors` |
| Path traversal or overwrite through run identifiers or outputs | Run ids are generated and validated against a strict pattern; run directories are created exclusively; `--output` refuses to overwrite without `--force`. Nothing derived from model output is used in a path. | `tests/test_store.py`, `tests/test_cli.py` |
| Hostile custom suite YAML | `yaml.safe_load` only; unknown keys rejected; file size and count limits; symlinked files ignored; regex length limit and compile-time validation; templates restricted to `{{canary.<name>}}`. | `tests/test_loader.py` |
| Tampered results presented as genuine | `manifest.json` records a SHA-256 of `results.json`; `llmsec report` warns on mismatch. This detects accidental change only; it is not a signature. | `test_modified_results_are_detected` |

The adversarial review of the evaluator, its findings and the regression tests
added for them are recorded in [security-review.md](security-review.md).

## Residual risks

- A custom suite can contain a regular expression that is slow on some input.
  Patterns are length-limited and responses are capped before matching, but
  Python's `re` module has no timeout. Only run suites you have reviewed.
- Stored transcripts contain whatever the model produced. Treat
  `results.json` as untrusted data when processing it with other tools.
- The loopback check is based on the configured host string or IP literal. A
  hostname that resolves to a remote address is refused unless it is one of
  the well-known loopback names; DNS is never consulted.
