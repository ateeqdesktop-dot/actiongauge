from pathlib import Path

import pytest

from actiongauge.core import analyze_document, analyze_file


def test_detects_security_resilience_and_cost_rules():
    doc = {
        "on": ["pull_request_target"],
        "permissions": "write-all",
        "jobs": {"build": {"steps": [
            {"uses": "actions/checkout@v4"},
            {"run": "echo ${{ github.event.pull_request.title }}"},
            {"uses": "actions/upload-artifact@v4", "with": {}},
        ]}},
    }
    ids = {f.rule_id for f in analyze_document(doc)}
    assert {"AG002", "AG003", "AG006", "AG007", "AG008", "AG005"} <= ids


def test_sha_pinning_is_accepted_and_order_is_stable():
    sha = "a" * 40
    doc = {"permissions": "read-all", "concurrency": {"group": "x"}, "jobs": {"a": {"steps": [{"uses": f"org/action@{sha}"}]}}}
    first = analyze_document(doc)
    second = analyze_document(doc)
    assert first == second
    assert not any(f.rule_id == "AG006" for f in first)


def test_parse_file_limit(tmp_path: Path):
    p = tmp_path / "workflow.yml"
    p.write_text("jobs: {}\n")
    assert {f.rule_id for f in analyze_file(p)} == {"AG001", "AG005"}


def test_non_mapping_rejected(tmp_path: Path):
    p = tmp_path / "workflow.yml"
    p.write_text("- invalid\n")
    with pytest.raises(TypeError):
        analyze_file(p)
