# PRODUCT.md — Skill Doctor Lite (slug: `skill-doctor-lite`)

## Purpose

AI-agent operators install third-party skills — directories of instructions
and code written by strangers — and hand them to a trusted agent. Skill text
is executable instruction from strangers: the same prompt-injection class
our own Security Policy flags. Skill Doctor Lite exists to give that
operator a one-command, offline scan before installing: it lints a skills
directory for prompt-injection text, exfiltration lines, approval-disabling
instructions, and embedded secret material, and returns a severity-triaged
report with an explicit PASS/FAIL verdict.

## Real audience

AI-agent operators who install third-party skills. First: CWI's own
departments — we install skills constantly, and this tightens our own supply
chain first. Then: external operators running agents with community skills
(Moltbook agents, open-source agent harnesses, MCP/skill marketplaces).
The operator who benefits most is the one installing skills *before* this
tool exists — the scan slots into the install workflow: install, scan, decide.

## Result

The buyer walks away with a deterministic, auditable pre-install triage:
a text or JSON report listing every matched pattern (skill, file, line,
rule id, severity, guidance), severity-triaged groups, and an explicit
VERDICT: PASS/FAIL line suitable for CI gates (`--fail-on` sets the
threshold; exit code 1 on fail). What they do *not* walk away with: proof of
safety. The tool sells triage, not certainty — and says so on every report.

## Mechanism

Pure static text scanning, stdlib Python only, no network, no telemetry,
no execution:

1. **Rule catalog** (`skill_doctor/rules.py`) — 25 versioned signature rules
   across 4 categories: prompt-injection (8), exfiltration (7),
   approval-disabling (6), embedded-secret (4). Each rule: id, category,
   regex pattern, severity (critical/high/medium/low), title, guidance.
2. **Scanner** (`skill_doctor/scanner.py`) — walks a skills directory (each
   immediate subdirectory = one skill), scans `SKILL.md`, `*.md`, `*.py`,
   `*.sh`, `*.js` line by line, skips binary files and `.git` dirs, emits
   findings sorted deterministically (skill, file, line, rule_id).
3. **Report** (`skill_doctor/report.py`) — text renderer (severity-triaged
   groups, explicit PASS/FAIL verdict) and JSON renderer (schema_version,
   rules_version, scanned_at, skills_scanned, findings, summary counts).
4. **CLI** (`skill_doctor/cli.py`) — `scan`, `rules`, `version` subcommands
   with documented exit codes (0 clean / 1 findings ≥ fail-on / 2 error).

## Verification

52 unittest tests, all green (`python3 -m unittest discover -s tests`):

- **Catalog integrity (8 tests):** 20–30 rules, unique ids, valid
  categories/severities, every regex compiles, titles and guidance present.
- **Positive controls (2 tests):** every one of the 25 rules fires on its
  family's planted fixture (injection/exfil/approval/secrets skills), and
  each fixture only produces its own family's findings.
- **Negative control (3 tests):** the realistic benign clean fixture
  produces zero findings, standalone and inside a multi-skill dir.
- **Scanner behavior (12 tests):** deterministic ordering, two scans
  byte-identical, `.git` and binary files skipped, only listed extensions
  scanned, correct error types on missing dir / non-dir.
- **Reports (11 tests):** JSON schema keys present, summary counts match
  findings, findings sorted, PASS/FAIL verdict lines, `--min-severity`
  filtering, byte-identical JSON modulo `scanned_at`.
- **CLI end-to-end (12 tests):** `scan` on clean exits 0, on mixed exits 1
  with real findings; missing dir / bad flags / bad format exit 2;
  `--fail-on high` exits 0 when only medium findings exist; `rules` lists
  all 25; `version` prints 1.0.0.

What the suite proves: the rules match what they claim to match, stay silent
on benign text, and the CLI/report pipeline is deterministic and honest.
What it does *not* prove: real-world false-positive/false-negative rates —
that needs scans of real skills with human review, which is the product work
ahead (see kill rule).

## Differentiation from Skill Sentinel (#30)

Skill Sentinel is CWI's web-based skill scanner (browser UI, A–F grades,
`?scan=` deep links, free tool, not on the money page). Skill Doctor Lite is
not a re-skin — it is the local-first CLI counterpart for supply-chain
gating: install-time scanning, exit codes for CI/pipelines, machine-readable
JSON designed for agent consumption, and a versioned/pinned rule catalog so
a "clean" verdict is auditable. It deliberately avoids the A–F grade
framing — a grade implies a scored trust verdict, while this tool sells
severity-triaged PASS/FAIL triage. Honest line: Skill Sentinel is the web
demo you try in a browser; Skill Doctor Lite is the tool you wire into your
install pipeline.

## Kill rule

**Fewer than 5 external uses with receipts in 30 days → delist.**
A "use with receipt" = a scan run on a real (non-fixture) skills directory
with the JSON report kept on file. The Twenty Minds decision record's
contrarian dissent stands: zero revenue plus another SKU is inventory disease,
so distribution (the pending→live Gumroad path, needs Black's tap) is the
loudest line in every status report until real revenue exists.

## Open-source-maintainer risk: the signature-game tradeoff

Publishing the rule set lets attackers study it — they can reword injections
to dodge signatures. We publish anyway, because a security tool earns trust
only as readable code with auditable, forkable rules. The design answer:

- **Rules are versioned and pinned per release** (`RULES_VERSION`).
- **Every report carries `rules_version`**, so a "clean" verdict is
  auditable against the exact rule set that produced it.
- A clean verdict is **never a trust certificate** — the text report says
  so explicitly: "this is signature-based triage, not proof of safety."
- Rule curation is ongoing product work: new rules ship with new versions,
  old reports stay reproducible because they name their version.

## Price

TBD — pending Black's approval. Never publish a price without it.
