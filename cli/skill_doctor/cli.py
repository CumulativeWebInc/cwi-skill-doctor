"""Skill Doctor Lite — scan your installed agent skills for risky text.

Static, offline, stdlib-only. Scans SKILL.md and code files for
prompt-injection text, exfiltration lines, approval-disabling instructions,
and embedded secret material.

Subcommands:
  scan <skills-dir> [--format text|json] [--min-severity SEV] [--fail-on SEV]
  rules
  version

Exit codes:
  0 = clean (or only findings below --fail-on)
  1 = findings at or above --fail-on
  2 = usage / IO error
"""
import argparse
import sys

from . import __version__
from .report import (SEVERITY_RANK, render_text, report_json_text,
                     verdict_for)
from .rules import CATEGORIES, RULES, RULES_VERSION, SEVERITIES
from .scanner import scan_dir


def cmd_scan(args):
    if args.min_severity not in SEVERITIES:
        print("skill-doctor: bad --min-severity: %s (choose from %s)" % (
            args.min_severity, ", ".join(SEVERITIES)), file=sys.stderr)
        return 2
    if args.fail_on not in SEVERITIES:
        print("skill-doctor: bad --fail-on: %s (choose from %s)" % (
            args.fail_on, ", ".join(SEVERITIES)), file=sys.stderr)
        return 2
    try:
        skills_scanned, findings = scan_dir(args.skills_dir)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print("skill-doctor: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("skill-doctor: could not read skills directory: %s" % exc,
              file=sys.stderr)
        return 2
    if args.format == "json":
        sys.stdout.write(report_json_text(
            skills_scanned, findings,
            fail_on=args.fail_on, min_severity=args.min_severity))
    else:
        sys.stdout.write(render_text(
            skills_scanned, findings,
            fail_on=args.fail_on, min_severity=args.min_severity))
    return 1 if verdict_for(findings, args.fail_on) == "FAIL" else 0


def cmd_rules(_args):
    print("Skill Doctor Lite rule catalog  (rules version %s)" % RULES_VERSION)
    for rule in RULES:
        print("%s  [%s/%s]  %s" % (
            rule["id"], rule["category"], rule["severity"], rule["title"]))
    return 0


def cmd_version(_args):
    print(__version__)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="skill-doctor",
        description=("Static, offline linter for installed AI-agent skills. "
                     "Detects prompt-injection text, exfiltration lines, "
                     "approval-disabling instructions, and embedded secrets. "
                     "Signature-based triage, not a trust certificate."))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a skills directory.")
    s.add_argument("skills_dir", help="Directory of installed skills "
                                     "(each immediate subdirectory = one skill).")
    s.add_argument("--format", choices=["text", "json"], default="text",
                   help="Report format (default: text).")
    s.add_argument("--min-severity", default="low", metavar="SEV",
                   help="Hide findings below this severity "
                        "(default: low). One of: %s." % ", ".join(SEVERITIES))
    s.add_argument("--fail-on", default="medium", metavar="SEV",
                   help="Exit 1 when a finding is at or above this severity "
                        "(default: medium). One of: %s." % ", ".join(SEVERITIES))
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="Print the rule catalog.")
    r.set_defaults(func=cmd_rules)

    v = sub.add_parser("version", help="Print the version.")
    v.set_defaults(func=cmd_version)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
