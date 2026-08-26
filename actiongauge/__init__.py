"""Deterministic GitHub Actions posture auditing."""

from .core import Finding, analyze_document, analyze_file, report

__all__ = ["Finding", "analyze_document", "analyze_file", "report"]
