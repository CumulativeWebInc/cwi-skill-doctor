"""skill-doctor — a static, offline linter for installed AI-agent skills.

Detects prompt-injection text, exfiltration lines, approval-disabling
instructions, and embedded secret material in SKILL.md and code files.

Stdlib only. No network, no telemetry. Signature-based triage, not a
trust certificate.
"""

__version__ = "1.0.0"

from .rules import RULES, RULES_VERSION  # noqa: F401
from .scanner import scan_dir, rule_count  # noqa: F401
from .report import render_text, render_json  # noqa: F401

__all__ = ["__version__", "RULES", "RULES_VERSION", "scan_dir", "rule_count",
           "render_text", "render_json"]
