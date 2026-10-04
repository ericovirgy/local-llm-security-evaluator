# Security policy

## Scope

This project evaluates model behaviour. Reports about **the evaluator itself**
are in scope, for example:

- model output, endpoint responses or stored results that can execute code,
  inject terminal escapes, or inject active content into reports;
- prompts, outputs or credentials leaving the machine without `--allow-remote`;
- path traversal or file overwrite through CLI options, run ids or suites;
- crashes or hangs triggered by hostile model output or suite files.

Findings about a particular **model** failing a scenario are not security
vulnerabilities in this project. Share them as regular issues if you think a
scenario or check is wrong.

## Reporting

Please use GitHub's private vulnerability reporting ("Report a vulnerability"
in the repository's Security tab). Do not open a public issue for an
unpatched vulnerability. Include the version (`llmsec --version`), a minimal
reproduction and the observed impact.

This is a volunteer project without a formal response SLA. Reports are
acknowledged on a best-effort basis.

## Design notes

See [docs/threat-model.md](docs/threat-model.md) for the evaluator's threat
model and [docs/security-review.md](docs/security-review.md) for the
adversarial review performed before the first release.
