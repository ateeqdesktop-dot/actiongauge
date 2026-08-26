# ActionGauge

**Security, resilience, and cost posture for GitHub Actions — as a deterministic local gate.**

GitHub Actions workflows are production infrastructure. A missing permission declaration, floating third-party action, privileged trigger, interpolated pull-request value, uncancelled duplicate run, or unbounded artifact retention can become a security incident, a stuck deployment, or a needless bill. ActionGauge reads workflow YAML without contacting GitHub and produces explainable findings that belong in code review.

> ActionGauge is not a replacement for `actionlint` or `zizmor`. It complements syntax and security linters with a small policy surface focused on **operational posture**: permissions, trigger privilege, concurrency, artifact retention, and actionable remediation.

## Why it exists

GitHub documents least-privilege `GITHUB_TOKEN` permissions, warns about privileged triggers and untrusted checkout, and recommends auditing third-party actions. `zizmor` is an excellent security-focused analyzer with thousands of stars. The practical gap is a repository-owned, dependency-light gate that turns security, resilience, and cost hygiene into deterministic rules and a versioned report suitable for a pull request.

## Features

| Area | Rules in v0.1.0 |
|---|---|
| Token security | Explicit permissions policy; reject `write-all` |
| Trigger security | Flag `pull_request_target` and `workflow_run` privilege boundaries |
| Supply chain | Detect actions not pinned to a 40-character commit SHA |
| Injection | Detect direct shell interpolation of untrusted GitHub contexts |
| Reliability | Detect missing workflow concurrency policy |
| Cost hygiene | Detect unbounded artifact retention |
| Reports | Markdown, sorted JSON, and SARIF-style output |
| Safety | 2 MiB input limit; safe YAML loading; no network or code execution |

## Quick start

```bash
python -m pip install .
actiongauge .github/workflows/ci.yml
actiongauge .github/workflows/ci.yml --format json --fail-on high > actiongauge.json
actiongauge .github/workflows/ci.yml --format sarif > actiongauge.sarif
```

The default gate fails on high and critical findings. Use `--fail-on never` for an informational report or choose `low`, `medium`, `high`, or `critical` as the minimum severity that blocks CI.

## Example CI step

```yaml
- name: Audit GitHub Actions posture
  run: |
    python -m pip install .
    actiongauge .github/workflows/*.yml --format markdown --fail-on high
```

## Architecture

The parser reads bounded YAML with `yaml.safe_load`, the rule engine evaluates a plain mapping, and the reporter emits a versioned result. Every finding has a stable rule ID, category, path, severity, remediation, and SHA-256 fingerprint. Findings are sorted to make output reviewable and reproducible.

ActionGauge is offline-first. It does not resolve action tags, call the GitHub API, fetch commits, inspect secrets, or execute workflow commands. SHA pinning is therefore a syntactic policy; teams may pair it with an allowlist or a separate dependency review process.

## Development

```bash
python -m pip install -e '.[dev]'  # or install pytest and ruff separately
pytest
ruff check actiongauge tests
```

New rules should be narrow, explainable, deterministic, and covered by regression fixtures. Do not add network access or dynamic code execution to the analyzer.

## Roadmap

Planned extensions include reusable-workflow expansion, policy files with organization-specific severities, action allowlists, line-aware YAML locations, GitHub Checks annotations, SARIF schema conformance, and a cost estimator using recorded run durations. These belong at explicit boundaries so the core remains portable.

## License

Apache-2.0. See [LICENSE](LICENSE).
