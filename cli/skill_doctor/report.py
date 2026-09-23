"""Skill Doctor Lite — report rendering.

Two renderers over a scan result:
  render_text(...) -> human-readable, severity-triaged, explicit PASS/FAIL
  render_json(...) -> machine-readable report dict

Both are deterministic: two scans of the same directory are byte-identical
modulo scanned_at.
"""
import json
from datetime import datetime, timezone

from .rules import RULES_VERSION, SEVERITIES
from .scanner import scan_dir

SCHEMA_VERSION = "1.0"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def summarize(findings):
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1
    counts["total"] = len(findings)
    return counts


def verdict_for(findings, fail_on="medium"):
    """PASS if no finding is at or above the fail_on severity."""
    threshold = SEVERITY_RANK[fail_on]
    for f in findings:
        if SEVERITY_RANK[f["severity"]] <= threshold:
            return "FAIL"
    return "PASS"


def _triaged(findings):
    by_sev = {sev: [] for sev in SEVERITIES}
    for f in findings:
        by_sev[f["severity"]].append(f)
    return by_sev


def render_text(skills_scanned, findings, fail_on="medium", min_severity="low",
                scanned_at=None):
    """Human-readable report. min_severity hides lower findings from display;
    fail_on only affects the verdict line."""
    shown = [f for f in findings if SEVERITY_RANK[f["severity"]] <= SEVERITY_RANK[min_severity]]
    verdict = verdict_for(findings, fail_on)
    stamped = scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    L = []
    L.append("Skill Doctor Lite v%s — scan report" % _version())
    L.append("rules: %s   scanned: %s" % (RULES_VERSION, stamped))
    L.append("skills scanned: %d   findings: %d (shown: %d)" % (
        len(skills_scanned), len(findings), len(shown)))
    L.append("")
    if verdict == "PASS":
        L.append("VERDICT: PASS — no findings at or above %s" % fail_on)
    else:
        n = sum(1 for f in findings if SEVERITY_RANK[f["severity"]] <= SEVERITY_RANK[fail_on])
        L.append("VERDICT: FAIL — %d finding(s) at or above %s" % (n, fail_on))
    L.append("")
    if not shown:
        L.append("No findings to display.")
        L.append("")
        return "\n".join(L)
    by_sev = _triaged(shown)
    for sev in SEVERITIES:
        group = by_sev[sev]
        if not group:
            continue
        L.append("[%s] %d finding(s)" % (sev.upper(), len(group)))
        for f in group:
            L.append("  skill: %s   file: %s:%d   rule: %s" % (
                f["skill"], f["file"], f["line"], f["rule_id"]))
            L.append("  category: %s" % f["category"])
            L.append("  matched: %r" % f["matched_text"])
            L.append("  guidance: %s" % f["guidance"])
            L.append("")
    L.append("Honest note: this is signature-based triage, not proof of "
             "safety. A PASS means no known-bad patterns matched — it does "
             "not mean the skill is safe.")
    L.append("")
    return "\n".join(L)


def render_json(skills_scanned, findings, fail_on="medium", min_severity="low",
                scanned_at=None):
    """Machine-readable report dict with a fixed key order."""
    shown = [f for f in findings if SEVERITY_RANK[f["severity"]] <= SEVERITY_RANK[min_severity]]
    stamped = scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "schema_version": SCHEMA_VERSION,
        "rules_version": RULES_VERSION,
        "scanned_at": stamped,
        "skills_scanned": list(skills_scanned),
        "min_severity": min_severity,
        "fail_on": fail_on,
        "verdict": verdict_for(findings, fail_on),
        "summary": summarize(findings),
        "findings": [
            {
                "skill": f["skill"],
                "file": f["file"],
                "line": f["line"],
                "rule_id": f["rule_id"],
                "category": f["category"],
                "severity": f["severity"],
                "matched_text": f["matched_text"],
                "guidance": f["guidance"],
            }
            for f in shown
        ],
    }
    return report


def report_json_text(skills_scanned, findings, fail_on="medium",
                     min_severity="low", scanned_at=None):
    return json.dumps(
        render_json(skills_scanned, findings, fail_on, min_severity, scanned_at),
        indent=2, ensure_ascii=False) + "\n"


def _version():
    from . import __version__
    return __version__
