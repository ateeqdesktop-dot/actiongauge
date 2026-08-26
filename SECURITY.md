# Security Policy

## Scope

ActionGauge is an offline static analyzer for GitHub Actions YAML. It does not execute workflow steps, resolve remote actions, call GitHub APIs, or access secrets.

## Defensive guarantees

The loader uses `yaml.safe_load`, rejects non-mapping roots, and limits each workflow to 2 MiB. Findings are advisory and should be reviewed against the repository's trust model; a finding is not a proof of exploitability.

## Reporting

Please report vulnerabilities privately through GitHub Security Advisories. Do not include private workflow contents, tokens, or credentials in public issues.
