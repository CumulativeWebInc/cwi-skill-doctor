# Skill Doctor Lite

> A static, offline linter for installed AI-agent skills. Scans SKILL.md and
> code files for prompt-injection text, exfiltration lines, approval-disabling
> instructions, and embedded secret material — before you install.
> **Signature-based triage, not a trust certificate.**

## Relationship to Skill Sentinel (#30)

Skill Sentinel is the web demo you try in a browser; Skill Doctor Lite is the
tool you wire into your install pipeline. Skill Sentinel (#30) is CWI's
web-based skill scanner — browser UI, A–F grades, `?scan=` deep links, free
tool, not on the money page. Skill Doctor Lite is deliberately different:

- **Local-first CLI, not a web page.** Runs entirely on your machine — no
  browser, no upload, no network. Point it at your own skills directory.
- **Built for supply-chain gating.** Exit codes (0 clean / 1 findings /
  2 error) and `--fail-on` thresholds are designed for CI gates and
  install-time checks: scan, then decide whether the install proceeds.
- **Machine-readable by design.** The JSON report is built for agent
  consumption — schema_version, rules_version, findings, summary counts.
- **Auditable verdicts.** The versioned, pinned rule catalog means every
  report carries `rules_version`: a "clean" verdict can be checked against
  the exact rules that produced it.
- **No A–F grades.** Grading implies a scored trust verdict; this tool does
  severity-triaged PASS/FAIL instead — triage, never a trust certificate.

## Install

No install needed. Stdlib Python only (3.8+), no dependencies, no network,
no telemetry.

```bash
cd ~/workspace/cwi-company/apps/skill-doctor-lite
python3 -m skill_doctor version   # 1.0.0
```

## Quickstart (under 5 minutes)

The repo ships with fixture skills — one benign, several planted with the
attacks the rules target. Scan them:

```bash
# 1. Scan the clean fixture — should PASS, exit 0
python3 -m skill_doctor scan tests/fixtures/clean-skill

# 2. Scan a mixed dir (clean + injection) — should FAIL, exit 1
python3 -m skill_doctor scan tests/fixtures/multi

# 3. Same scan as JSON, for pipelines
python3 -m skill_doctor scan tests/fixtures/multi --format json

# 4. Only fail on high-or-worse findings
python3 -m skill_doctor scan tests/fixtures/multi --fail-on high

# 5. See the whole rule catalog (25 rules, versioned 1.0.0)
python3 -m skill_doctor rules
```

Real use: point it at a directory of installed skills, where each immediate
subdirectory is one skill:

```bash
python3 -m skill_doctor scan ~/.skills
```

Exit codes: `0` = clean (or only findings below `--fail-on`), `1` = findings
at or above `--fail-on` (default: medium), `2` = usage/IO error.

## What it does NOT do

- **No sandbox, no runtime analysis.** It reads text; it never executes
  skill code.
- **It can miss novel attacks.** The rules are signatures for known-bad
  patterns. A cleverly reworded injection will not match.
- **It can false-positive.** Benign writing trips signatures (e.g. a
  creative-writing skill saying "act as if"). Every finding carries guidance
  — you decide, the tool only triages.
- **Published rules can be studied by attackers.** The catalog is readable
  on purpose (auditability beats obscurity), which means an adversary can
  reword around it. See the signature-game tradeoff in PRODUCT.md.
- **A PASS is not a safety certificate.** It means no known-bad pattern
  matched — nothing more.

## Honesty

This tool sells triage, never certainty. The Twenty Minds build decision
record (2026-09-18) is explicit: the demand signal is mostly our own security
anxiety, the false-positive/false-negative treadmill is real, rule curation
is ongoing product work (not a one-time script), and a trusted "clean" badge
on a poisoned skill would be worse than no scan at all. The design answer to
that last risk: rules are versioned and pinned per release, and every report
carries `rules_version` — so a clean verdict is auditable against the exact
rules that produced it, never a trust certificate.

No fabricated claims anywhere in this repo: no invented users, revenue,
adoption, or metrics. Status is exactly what it is — a tested v1 awaiting
its first real-world users.
