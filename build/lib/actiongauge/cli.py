from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import Finding, analyze_file, report


def markdown(data: dict) -> str:
    s = data["summary"]
    lines = ["# ActionGauge report", "", f"Source: `{data['source']}`  ", f"Findings: **{s['findings']}** | Critical: **{s['critical']}** | High: **{s['high']}** | Medium: **{s['medium']}** | Low: **{s['low']}**", "", "| Rule | Severity | Category | Location | Finding | Remediation |", "|---|---|---|---|---|---|"]
    for f in data["findings"]:
        lines.append(f"| `{f['rule_id']}` | {f['severity']} | {f['category']} | `{f['path']}` | {f['message']} | {f['remediation']} |")
    return "\n".join(lines) + "\n"


def sarif(data: dict) -> dict:
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "ActionGauge", "informationUri": "https://github.com/ateeqdesktop-dot/actiongauge", "rules": [{"id": f["rule_id"], "shortDescription": {"text": f["message"]}} for f in data["findings"]]}}, "results": [{"ruleId": f["rule_id"], "level": "error" if f["severity"] in {"critical", "high"} else "warning", "message": {"text": f["message"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": data["source"]}, "region": {"startLine": 1}}}]} for f in data["findings"]]}]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="actiongauge", description="Deterministic GitHub Actions security, resilience, and cost audit")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown")
    parser.add_argument("--fail-on", choices=["never", "low", "medium", "high", "critical"], default="high")
    args = parser.parse_args(argv)
    findings: list[Finding] = []
    for path in args.files:
        findings.extend(analyze_file(path))
    data = report(findings, ", ".join(str(x) for x in args.files))
    payload = sarif(data) if args.format == "sarif" else data
    print(json.dumps(payload, indent=2, sort_keys=True) if args.format == "json" or args.format == "sarif" else markdown(data), end="")
    ranks = {"never": 99, "low": 3, "medium": 2, "high": 1, "critical": 0}
    return 1 if args.fail_on != "never" and any(ranks[f.severity] <= ranks[args.fail_on] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
