# Security review of the evaluator (pre-release, 2026-10-04)

Before the first release the evaluator itself was reviewed adversarially:
an independent reviewer tried to break result parsing, suite loading, scoring,
report generation, malicious model output handling, endpoint handling, path
handling and configuration handling, using the project's own virtual
environment (Python 3.11, PyYAML 6.0.3) with crafted inputs and a hostile fake
endpoint.

**Outcome.** No path to code execution and no way to send prompts off-machine
without `--allow-remote` was found. The observational invariant held. Ten
issues were confirmed (denial of service, crashes that lost a finished run, and
escape/markup injection from untrusted suites or stored results). All were
fixed; every fix has a regression test in `tests/test_security_regressions.py`
(test names are prefixed `f1_`, `f2_`, ... after the finding number).

## Findings and fixes

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | Medium | Quadratic regex backtracking in six built-in check patterns (`A[\s\S]*B\|B[\s\S]*A`, `\([^)\n]*suffix`). A model stuck in a repetition loop held one check for up to ~49 s at 200 KB. | New `contains_all` check replaces the alternations; action patterns use bounded `{0,300}` quantifiers; regex checks only inspect the first 32,000 characters. Worst case across the suite now ~0.05 s. |
| 2 | Medium | A JSON integer longer than 4300 digits in a model response raised an uncaught `ValueError` in the `json_object` check and aborted the whole run. | `ValueError` is handled; the check simply fails. |
| 3a | Medium/Low | The same oversized integer from an endpoint or in a stored `results.json` crashed `list-models` / `report`. | Mapped to `AdapterError` / `StoreError`. |
| 3b | Medium | A lone UTF-16 surrogate in model output passed evaluation but made writing `results.json` fail after every execution had finished, losing the run. | Generated text is normalised to valid UTF-8 at capture time; JSON is written with replacement as a second line of defence. |
| 3c | Low | A malformed port (`http://127.0.0.1:abc`) passed URL validation and crashed later. | Port is validated together with the rest of the URL. |
| 3d | Low | `--timeout nan`/`inf` and unvalidated `top_p` caused tracebacks. | Finite-range validation for timeout, temperature and top-p. |
| 3e | Low | The timeout applied per socket read, so an endpoint dribbling one byte at a time could hold a request indefinitely. | Response bodies are read in chunks against an overall deadline. |
| 4 | Low | Scenario titles and suite versions from a custom suite were printed raw, allowing terminal escapes (window title, screen clear, OSC 8 hyperlinks) in `list-tests`, `validate-suite` and run progress. | The loader rejects control and bidi characters in display metadata; the CLI also sanitises those fields. |
| 5 | Low | A forged `results.json` could inject terminal escapes through `status`, scores and category keys in `report` and `compare --runs`. | `load_run` validates the shape of the metrics (closed set for `status`, numeric types); every interpolated value is sanitised; structurally broken files produce an error instead of a traceback. |
| 6 | Low | A forged `results.json` could inject HTML/Markdown into `report --format markdown` via verdict, seed, latency and check-effect fields. | All such fields are escaped. |
| 7 | Low | `not_matches` failure reasons quoted up to 80 characters of model output, which was then rendered outside code blocks (auto-linked URLs, strikethrough). | Reasons now give the offset and length of the match only; model text appears only in fenced blocks. |
| 8 | Medium | YAML aliases in a custom suite allowed exponential expansion: a 25 KB file exhausted memory during `validate-suite`. | Aliases are rejected before construction; each rendered message is capped at 1,000,000 characters. |
| 9 | Low | A suite author can supply a catastrophically backtracking pattern (`(a\|aa)+$`), stalling a run. | Documented as a residual risk: custom suites are code and must be reviewed. Regex input is capped at 32,000 characters, which limits but does not eliminate the effect. |
| 10 | Low | The run directory was created only after all executions, so an unusable `--output-dir` discarded a finished run; `report --output <directory>` raised a traceback. | The run directory is created before any model call and removed again if the run fails; directory targets and `OSError` produce a clean error. |

Also hardened: only the literal name `localhost` is accepted as a loopback
host without `--allow-remote`. Aliases such as `localhost.localdomain` and
`ip6-localhost` are often absent from `/etc/hosts` and fall through to DNS,
which an attacker may control.

## Tested and held up

- Built-in regular expressions (refusal heuristic, base64/hex token scanners,
  code-fence matcher) against 19 adversarial 200 KB inputs: worst case 49 ms.
- Model output containing ANSI/OSC sequences, CRLF, backtick and tilde fences,
  Markdown headers, inline HTML and bidi overrides stayed inside a code fence
  in `report.md` and was stripped from terminal output.
- Redirects are refused (`HTTP 302` becomes an error, the target is not
  contacted). `http_proxy`, `HTTP_PROXY` and `all_proxy` pointing to a local
  listener received zero connections.
- Non-JSON, truncated, wrongly typed and deeply nested endpoint responses, and
  responses over 8 MB, all become `AdapterError`.
- Loopback validation rejected `localhost.`, `2130706433`, `127.1`,
  `0x7f000001`, `0177.0.0.1`, `0.0.0.0`, `127.0.0.1.nip.io`, user-info tricks
  (`evil.com\@127.0.0.1`), tab characters, `fe80::1%lo`, `file:` URLs, query
  strings and fragments. The URL actually used is the one reconstructed from
  the parse, so there is no parser differential.
- The API key from `--api-key-env` only reaches the `Authorization` header;
  error messages name the variable, not the value; the manifest stores only a
  credential-free endpoint label.
- Configuration: unknown sections/keys and wrong types are rejected.
- Run ids are generated and pattern-validated; run directories are never
  overwritten; `--output` refuses existing files without `--force`, and with
  `--force` replaces a symlink itself rather than its target. Output files are
  created with mode 0600.
- Symlinked files and directories inside a suite are ignored. Templates only
  substitute `{{canary.<name>}}` once, with values restricted to
  `[A-Za-z0-9_-]`. `yaml.safe_load` does not construct Python objects.

## Residual risks

See [threat-model.md](threat-model.md#residual-risks). In short: custom suites
are trusted code; stored results are untrusted data; and the integrity digest
detects accidental change, not deliberate tampering.
