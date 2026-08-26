# Contributing

Keep rules narrow, deterministic, and explainable. Every rule needs a stable ID, severity, remediation text, documentation, and regression coverage. Do not add network calls, shell execution, or remote action resolution to the analyzer.

Run `pytest` and `ruff check actiongauge tests` before opening a pull request. Preserve the JSON schema version for compatible changes and document any new policy semantics.
