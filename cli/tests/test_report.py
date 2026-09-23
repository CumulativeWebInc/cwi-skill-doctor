"""Report rendering: JSON shape, text verdicts, filters, determinism."""
import json
import unittest

from skill_doctor.report import (render_json, render_text, report_json_text,
                                 summarize, verdict_for)
from skill_doctor.scanner import scan_dir

from helpers import FIXTURES_DIR

STAMP = "2026-09-18T10:00:00Z"


class TestSummarize(unittest.TestCase):
    def test_counts_by_severity(self):
        findings = [{"severity": "critical"}, {"severity": "high"},
                    {"severity": "high"}, {"severity": "low"}]
        self.assertEqual(summarize(findings),
                         {"critical": 1, "high": 2, "medium": 0,
                          "low": 1, "total": 4})

    def test_verdict_for_thresholds(self):
        findings = [{"severity": "medium"}]
        self.assertEqual(verdict_for(findings, "medium"), "FAIL")
        self.assertEqual(verdict_for(findings, "high"), "PASS")
        self.assertEqual(verdict_for([], "medium"), "PASS")


class TestJsonReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skills, cls.findings = scan_dir(FIXTURES_DIR)

    def _report(self, **kw):
        kw.setdefault("scanned_at", STAMP)
        return render_json(self.skills, self.findings, **kw)

    def test_required_keys(self):
        rep = self._report()
        for key in ("schema_version", "rules_version", "scanned_at",
                    "skills_scanned", "min_severity", "fail_on", "verdict",
                    "summary", "findings"):
            self.assertIn(key, rep, key)

    def test_summary_matches_findings(self):
        rep = self._report()
        self.assertEqual(rep["summary"], summarize(self.findings))
        self.assertEqual(rep["summary"]["total"], len(rep["findings"]))

    def test_findings_sorted(self):
        rep = self._report()
        keys = [(f["skill"], f["file"], f["line"], f["rule_id"])
                for f in rep["findings"]]
        self.assertEqual(keys, sorted(keys))

    def test_findings_shape(self):
        rep = self._report()
        for f in rep["findings"]:
            self.assertEqual(set(f.keys()),
                             {"skill", "file", "line", "rule_id", "category",
                              "severity", "matched_text", "guidance"})

    def test_verdict_fail_when_findings(self):
        self.assertEqual(self._report()["verdict"], "FAIL")

    def test_min_severity_filters_displayed(self):
        rep = self._report(min_severity="critical")
        self.assertTrue(rep["findings"])
        for f in rep["findings"]:
            self.assertEqual(f["severity"], "critical")
        # summary still reflects ALL findings, not the display filter
        self.assertEqual(rep["summary"]["total"], len(self.findings))

    def test_deterministic_modulo_scanned_at(self):
        a = report_json_text(self.skills, self.findings, scanned_at=STAMP)
        b = report_json_text(self.skills, self.findings, scanned_at=STAMP)
        self.assertEqual(a, b)
        c = json.loads(report_json_text(self.skills, self.findings,
                                        scanned_at="2026-01-01T00:00:00Z"))
        d = json.loads(a)
        c["scanned_at"] = d["scanned_at"]
        self.assertEqual(c, d)


class TestTextReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skills, cls.findings = scan_dir(FIXTURES_DIR)

    def test_fail_verdict_line(self):
        text = render_text(self.skills, self.findings, scanned_at=STAMP)
        self.assertIn("VERDICT: FAIL", text)

    def test_severity_triage_groups(self):
        text = render_text(self.skills, self.findings, scanned_at=STAMP)
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            self.assertIn("[%s]" % sev, text)

    def test_pass_verdict_line_clean(self):
        text = render_text(["clean-skill"], [], scanned_at=STAMP)
        self.assertIn("VERDICT: PASS", text)

    def test_min_severity_hides_lower(self):
        text = render_text(self.skills, self.findings,
                           min_severity="critical", scanned_at=STAMP)
        self.assertIn("[CRITICAL]", text)
        self.assertNotIn("[MEDIUM]", text)

    def test_honesty_note_present(self):
        text = render_text(self.skills, self.findings, scanned_at=STAMP)
        self.assertIn("not proof of safety", text)


if __name__ == "__main__":
    unittest.main()
