# ActionGauge: Product and Architecture

## Product vision

ActionGauge treats GitHub Actions workflows as production infrastructure and compiles their security, resilience, and cost posture into a reviewable policy report. It is designed to run locally or inside any CI provider without sending workflow contents to a service.

## Problem statement

Workflow YAML can silently grant broad token permissions, execute under privileged triggers, consume redundant runners, retain artifacts indefinitely, or interpolate attacker-controlled context into a shell. Existing syntax and security tools are valuable, but teams often need a small repository-owned policy gate that also covers operational hygiene and explains exactly how to remediate each finding.

## Target users

The target users are maintainers, platform engineers, DevSecOps teams, and open-source projects that use GitHub Actions and want an auditable baseline without a hosted control plane. The output is useful in pull requests, release reviews, and repository bootstrap checks.

## MVP

The MVP reads one or more workflow YAML files with bounded safe parsing. It evaluates explicit token permissions, privileged triggers, action SHA pinning, direct untrusted context interpolation in `run`, concurrency policy, and artifact retention. It emits deterministic Markdown, JSON, and SARIF-style reports and supports severity-based CI exit codes.

## Architecture

```text
workflow YAML files
        |
        v
bounded safe YAML loader
        |
        v
plain workflow mapping
        |
        v
rule engine: security / supply-chain / resilience / cost
        |
        v
stable Finding records with rule ID and fingerprint
        |
        +--> Markdown
        +--> JSON schema v1
        +--> SARIF-style output
        |
        v
severity-aware process exit code
```

The parser is intentionally not a workflow executor. The rule engine is pure over an in-memory mapping, and reporters consume only normalized findings. Rule IDs and SHA-256 fingerprints make output stable across runs. A future line-aware parser can improve locations without changing the policy model.

## Security model

Workflow files are untrusted input. ActionGauge uses `yaml.safe_load`, rejects non-mapping roots, and enforces a 2 MiB file limit. It never resolves remote actions, calls the GitHub API, reads secrets, executes shell commands, or evaluates expressions. SHA pinning is a syntactic rule and must be combined with organizational allowlists or dependency review for provenance assurance.

## Configuration and observability

The initial release keeps policy in code to make the result predictable and dependency-light. Future policy files will override severities and enable repository-specific rules. CLI output is the observability surface: it includes source, category, path, severity, remediation, and fingerprint. The process status is the integration contract.

## Performance and scalability

The analysis is linear in workflow size and number of steps. Bounded parsing prevents accidental memory amplification from oversized inputs. Multiple files can be aggregated in one invocation. A future repository mode can discover workflows and reusable workflow relationships, while preserving local execution and deterministic serialization.

## Roadmap

Planned work includes reusable-workflow expansion, organization policies, action allowlists, line-aware locations, GitHub Checks annotations, standards-compliant SARIF, and a cost estimator based on recorded run durations. None of these require a hosted database for the core use case.
