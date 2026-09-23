# Skill Doctor Lite — Cumulative Web Inc

Local-first **skill supply-chain linter** for AI-agent skills: 25 versioned signature rules across prompt-injection, exfiltration, approval-disabling, and embedded-secret categories. Severity-triaged PASS/FAIL verdicts, text + machine-readable JSON reports, CI-ready exit codes. A CWI trust-layer product.

- **Live interactive demo:** https://cumulativewebinc.github.io/cwi-skill-doctor/ — runs the real engine in your browser: paste skill text or scan the bundled dogfood fixtures, browse the 25-rule catalog, download JSON reports.
- **Installable CLI:** `cli/` — stdlib-only Python, no network, no telemetry. Exit `0` clean · `1` findings at/above `--fail-on` · `2` usage/IO error. 52/52 tests green.

```bash
git clone https://github.com/CumulativeWebInc/cwi-skill-doctor.git
cd cwi-skill-doctor/cli
python3 -m skill_doctor scan /path/to/skills --format text
python3 -m skill_doctor scan /path/to/skills --format json --fail-on high
python3 -m skill_doctor rules
```

## Files

| Path | What |
|---|---|
| `index.html` | Interactive web demo (paste/upload skill text, dogfood fixtures, rule catalog) |
| `scanner.js` | Engine port: line-by-line scan, snippet rule, deterministic sort, verdict logic — parity-verified finding-for-finding against the Python engine on all fixtures |
| `rules.json` | The 25-rule catalog v1.0.0, machine-readable (generated from `cli/skill_doctor/rules.py`) |
| `cli/` | Full Python CLI: `skill_doctor/` package, `tests/` (incl. planted-injection fixtures), `README.md`, `PRODUCT.md` |
| `brand/logo.jpg` | CWI logo |

## Honest limits

Signature-based triage, **never a certificate of safety**. A PASS means no known signatures matched — not proof the skill is safe. Novel attacks, obfuscation, and non-text payloads are out of scope by design. Every report pins its rules version so a clean verdict is auditable.

## Contact

© 2026 Cumulative Web Inc · licensing/integration: [hp@cumulativeweb.com](mailto:hp@cumulativeweb.com) · pricing on request, never published without approval.
