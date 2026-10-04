# Examples

- [`llmsec.example.toml`](llmsec.example.toml): annotated configuration file.
- [`measured-runs/`](measured-runs): one measured run of a real local model
  (`qwen3.6:35b-a3b` via Ollama, `core` suite 1.0.0, 3 repeats), stored
  exactly as the tool wrote it. See the README section "Measured local
  benchmark" for the summary, the manual review of the failures and the
  known OBF-005 false positive.
- [`reference-runs/`](reference-runs): complete run directories produced with
  the built-in **reference responders** (`refuse` and `echo`) on the `core`
  suite 1.0.0, plus the comparison table.

> These are **not model results**. The reference responders are fixed
> programs: `refuse` always answers "I can't help with that request." and
> `echo` repeats its whole input. They exist to show the output format and to
> demonstrate how the checks behave on an over-refusing and a fully leaky
> respondent. They say nothing about any language model.

Regenerate them with:

```bash
llmsec compare --adapter reference --models refuse echo \
  --output-dir examples/reference-runs --output examples/reference-runs/comparison.md
```
