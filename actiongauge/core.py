from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    category: str
    path: str
    message: str
    remediation: str
    fingerprint: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _finding(rule_id: str, severity: str, category: str, path: str, message: str, remediation: str) -> Finding:
    key = f"{rule_id}|{path}|{message}"
    return Finding(rule_id, severity, category, path, message, remediation, hashlib.sha256(key.encode()).hexdigest()[:16])


def _walk_steps(workflow: dict[str, Any]):
    for job_id, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                yield job_id, index, step


def analyze_document(document: dict[str, Any], source: str = "workflow.yml") -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(document, dict):
        raise TypeError("workflow must be a YAML mapping")
    permissions = document.get("permissions")
    if permissions is None:
        findings.append(_finding("AG001", "high", "security", "permissions", "Workflow does not declare an explicit GITHUB_TOKEN permission policy.", "Set top-level permissions: read-all or none, then grant only required job permissions."))
    elif permissions == "write-all":
        findings.append(_finding("AG002", "critical", "security", "permissions", "Workflow grants write-all token permissions.", "Replace write-all with least-privilege permissions."))
    on = document.get("on", document.get(True, {}))
    triggers = on if isinstance(on, list) else list(on.keys()) if isinstance(on, dict) else [str(on)]
    if "pull_request_target" in triggers:
        findings.append(_finding("AG003", "critical", "security", "on.pull_request_target", "Privileged pull_request_target trigger requires strict separation from untrusted checkout.", "Prefer pull_request, or isolate privileged operations and never checkout fork code."))
    if "workflow_run" in triggers:
        findings.append(_finding("AG004", "high", "security", "on.workflow_run", "workflow_run executes with elevated context and must treat artifacts as untrusted.", "Validate and isolate artifacts before using them in a privileged job."))
    if not document.get("concurrency"):
        findings.append(_finding("AG005", "medium", "efficiency", "concurrency", "Workflow has no concurrency group or cancellation policy.", "Add concurrency with a stable group and cancel-in-progress for superseded pull-request runs."))
    for job_id, index, step in _walk_steps(document):
        path = f"jobs.{job_id}.steps[{index}]"
        uses = step.get("uses")
        if isinstance(uses, str) and "@" in uses:
            ref = uses.rsplit("@", 1)[1]
            if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                findings.append(_finding("AG006", "high", "supply-chain", f"{path}.uses", f"Action {uses} is not pinned to a full commit SHA.", "Pin third-party actions to a reviewed 40-character commit SHA."))
        run = step.get("run")
        if isinstance(run, str) and "${{" in run and any(token in run for token in ("github.event.", "github.head_ref", "github.event.pull_request.title")):
            findings.append(_finding("AG007", "high", "security", f"{path}.run", "Untrusted GitHub context is interpolated directly into a shell command.", "Pass the context through an env variable and quote it, or use an action input."))
        if isinstance(uses, str) and uses.startswith(("actions/cache", "actions/upload-artifact")):
            withs = step.get("with") or {}
            if uses.startswith("actions/upload-artifact") and "retention-days" not in withs:
                findings.append(_finding("AG008", "low", "cost", f"{path}.with", "Artifact retention is not explicitly bounded.", "Set retention-days to the shortest period needed for debugging or compliance."))
    return sorted(findings, key=lambda f: (f.severity, f.rule_id, f.path), reverse=True)


def analyze_file(path: str | Path) -> list[Finding]:
    p = Path(path)
    raw = p.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError(f"workflow exceeds {MAX_BYTES} bytes")
    doc = yaml.safe_load(raw) or {}
    return analyze_document(doc, str(p))


def report(findings: list[Finding], source: str) -> dict[str, Any]:
    counts = {level: sum(f.severity == level for f in findings) for level in ("critical", "high", "medium", "low")}
    return {"schema_version": 1, "source": source, "summary": {"findings": len(findings), **counts}, "findings": [f.to_dict() for f in findings]}
