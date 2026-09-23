"""Skill Doctor Lite — static scanner.

Walks a skills directory (each immediate subdirectory = one skill),
scans text files line by line against the rule catalog, and emits
findings sorted deterministically (skill, file, line, rule_id).

Static text scanning only: no execution, no network, no sandbox.
"""
import os
import re

from .rules import RULES, RULES_VERSION

# File types that can plausibly carry skill instructions or code.
SCAN_EXTENSIONS = (".md", ".py", ".sh", ".js")

_COMPILED = [(rule, re.compile(rule["pattern"], re.IGNORECASE)) for rule in RULES]

SNIPPET_MAX = 120


def _is_binary(path):
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True  # unreadable -> treat as unscannable, skip silently


def _scan_file(skill, relpath, abspath):
    """Scan one file. Returns a list of finding dicts (possibly empty)."""
    findings = []
    if _is_binary(abspath):
        return findings
    try:
        with open(abspath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return findings
    for lineno, line in enumerate(lines, start=1):
        for rule, rx in _COMPILED:
            if rx.search(line):
                snippet = line.strip()
                if len(snippet) > SNIPPET_MAX:
                    snippet = snippet[:SNIPPET_MAX] + "…"
                findings.append({
                    "skill": skill,
                    "file": relpath,
                    "line": lineno,
                    "rule_id": rule["id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "matched_text": snippet,
                    "guidance": rule["guidance"],
                })
    return findings


def _iter_skill_files(skills_dir):
    """Yield (skill, relpath, abspath) for scannable files, deterministic."""
    skills_dir = os.path.abspath(skills_dir)
    for skill in sorted(os.listdir(skills_dir)):
        skill_path = os.path.join(skills_dir, skill)
        if not os.path.isdir(skill_path):
            continue
        for root, dirs, files in os.walk(skill_path):
            # Skip version-control metadata, never skip anything else.
            dirs[:] = sorted(d for d in dirs if d != ".git")
            for name in sorted(files):
                if name.lower().endswith(SCAN_EXTENSIONS):
                    abspath = os.path.join(root, name)
                    relpath = os.path.relpath(abspath, skills_dir)
                    yield skill, relpath, abspath


def scan_dir(skills_dir):
    """Scan a skills directory.

    Returns (skills_scanned, findings):
      skills_scanned: sorted list of skill names (immediate subdirectories)
      findings: list of finding dicts, sorted by (skill, file, line, rule_id)

    Raises FileNotFoundError if the directory does not exist.
    Raises NotADirectoryError if the path is not a directory.
    """
    skills_dir = os.path.abspath(skills_dir)
    if not os.path.exists(skills_dir):
        raise FileNotFoundError("skills directory not found: %s" % skills_dir)
    if not os.path.isdir(skills_dir):
        raise NotADirectoryError("not a directory: %s" % skills_dir)
    skills_scanned = sorted(
        d for d in os.listdir(skills_dir)
        if os.path.isdir(os.path.join(skills_dir, d))
    )
    findings = []
    for skill, relpath, abspath in _iter_skill_files(skills_dir):
        findings.extend(_scan_file(skill, relpath, abspath))
    findings.sort(key=lambda f: (f["skill"], f["file"], f["line"], f["rule_id"]))
    return skills_scanned, findings


def rule_count():
    return len(RULES)


__all__ = ["scan_dir", "rule_count", "RULES_VERSION", "SCAN_EXTENSIONS"]
