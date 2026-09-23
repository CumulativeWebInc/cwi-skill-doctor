/* Skill Doctor Lite — in-browser scanner (JS port of skill_doctor/scanner.py).
 *
 * Rule-for-rule port of the Python engine:
 *  - same 25-rule catalog (rules.json, rules version 1.0.0, generated from rules.py)
 *  - same line-by-line scan, case-insensitive regex per rule
 *  - same snippet rule (strip, truncate at 120 chars + "…")
 *  - same deterministic sort (skill, file, line, rule_id)
 *  - same verdict logic (verdict_for, SEVERITY_RANK, fail_on default "medium")
 *
 * Honest limits: signature-based triage, never a certificate of safety.
 * A PASS means no known signatures matched — not proof the skill is safe.
 */
"use strict";

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITIES = ["critical", "high", "medium", "low"];
const SNIPPET_MAX = 120;

function snippetFor(line) {
  const s = line.trim();
  return s.length > SNIPPET_MAX ? s.slice(0, SNIPPET_MAX) + "…" : s;
}

/**
 * Scan one text blob.
 * @param {string} skill   skill name (immediate subdirectory name, or "pasted-skill")
 * @param {string} file    relative path shown in the report
 * @param {string} text    file contents
 * @param {object} catalog parsed rules.json
 * @returns {Array} findings, in (file, line, rule_id) order
 */
function scanText(skill, file, text, catalog) {
  const compiled = catalog.rules.map((rule) => ({
    rule,
    rx: new RegExp(rule.pattern, "i"),
  }));
  const findings = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { rule, rx } of compiled) {
      if (rx.test(line)) {
        findings.push({
          skill,
          file,
          line: i + 1,
          rule_id: rule.id,
          category: rule.category,
          severity: rule.severity,
          matched_text: snippetFor(line),
          guidance: rule.guidance,
        });
      }
    }
  }
  return findings;
}

/**
 * Scan many files: [{skill, file, text}] -> findings sorted by (skill, file, line, rule_id).
 */
function scanFiles(entries, catalog) {
  const findings = [];
  for (const e of entries) {
    findings.push(...scanText(e.skill, e.file, e.text, catalog));
  }
  findings.sort((a, b) =>
    a.skill < b.skill ? -1 : a.skill > b.skill ? 1
    : a.file < b.file ? -1 : a.file > b.file ? 1
    : a.line - b.line ||
      (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0)
  );
  return findings;
}

/** PASS if no finding is at or above the fail_on severity. */
function verdictFor(findings, failOn = "medium") {
  const threshold = SEVERITY_RANK[failOn];
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] <= threshold) return "FAIL";
  }
  return "PASS";
}

function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  counts.total = findings.length;
  return counts;
}

function buildReport(skillsScanned, findings, catalog, opts = {}) {
  const failOn = opts.failOn || "medium";
  return {
    schema_version: "1.0",
    tool: "skill-doctor",
    rules_version: catalog.rules_version,
    scanned_at: new Date().toISOString(),
    skills_scanned: skillsScanned,
    verdict: verdictFor(findings, failOn),
    fail_on: failOn,
    counts: summarize(findings),
    findings,
    honest_limits:
      "Signature-based triage, never a certificate of safety. " +
      "A PASS means no known signatures matched — not proof the skill is safe.",
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    scanText, scanFiles, verdictFor, summarize, buildReport,
    SEVERITY_RANK, SEVERITIES, SNIPPET_MAX,
  };
}
