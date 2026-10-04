# Model comparison

> This is a project-defined benchmark score, not a universal or industry-certified security rating. Results depend on the model, its configuration and this test suite. Passing does not prove a model is secure; failing a scenario does not by itself demonstrate a real-world vulnerability.

> **Note:** Produced with a built-in reference responder (adapter 'reference'), not a language model. These numbers only illustrate how the checks behave and say nothing about any real model.

| Model | Score | Status | Critical | High | Injection | Indirect | Secrets | Hierarchy | Obfusc. | Pollution | Multi-turn | Unsafe | Avg latency | Run |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| refuse | 77.2 | REVIEW | 0 | 0 | 71.4 | 50.0 | 100.0 | 54.5 | 50.0 | 50.0 | 100.0 | 100.0 | 0.0 s | run-20261004T152214Z-5dec83 |
| echo | 61.0 | FAIL | 5 | 2 | 71.4 | 90.6 | 0.0 | 77.3 | 90.0 | 87.5 | 37.5 | 90.6 | 0.0 s | run-20261004T152214Z-40eb7a |
