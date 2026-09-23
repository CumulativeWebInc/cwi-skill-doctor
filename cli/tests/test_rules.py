"""Rule catalog integrity + positive/negative control tests."""
import collections
import re
import unittest

from skill_doctor.rules import (CATEGORIES, RULES, RULES_VERSION, SEVERITIES,
                                validate)
from skill_doctor.scanner import scan_dir

from helpers import FIXTURES_DIR

# Which fixture skill exercises each rule family.
FAMILY_FIXTURE = {
    "prompt-injection": "injection-skill",
    "exfiltration": "exfil-skill",
    "approval-disabling": "approval-skill",
    "embedded-secret": "secrets-skill",
}


class TestCatalogIntegrity(unittest.TestCase):
    def test_rule_count_in_range(self):
        self.assertGreaterEqual(len(RULES), 20)
        self.assertLessEqual(len(RULES), 30)

    def test_ids_unique(self):
        ids = [r["id"] for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_categories_valid(self):
        for r in RULES:
            self.assertIn(r["category"], CATEGORIES, r["id"])

    def test_severities_valid(self):
        for r in RULES:
            self.assertIn(r["severity"], SEVERITIES, r["id"])

    def test_regexes_compile(self):
        for r in RULES:
            re.compile(r["pattern"], re.IGNORECASE)  # must not raise

    def test_titles_and_guidance_present(self):
        for r in RULES:
            self.assertTrue(r["title"].strip(), r["id"])
            self.assertTrue(r["guidance"].strip(), r["id"])

    def test_validate_returns_count(self):
        self.assertEqual(validate(), len(RULES))

    def test_version_pinned(self):
        self.assertRegex(RULES_VERSION, r"^\d+\.\d+\.\d+$")


class TestPositiveControls(unittest.TestCase):
    """Every rule fires on its family's positive-control fixture."""

    @classmethod
    def setUpClass(cls):
        cls.skills, cls.findings = scan_dir(FIXTURES_DIR)

    def test_every_rule_fires_on_its_fixture(self):
        for rule in RULES:
            fixture = FAMILY_FIXTURE[rule["category"]]
            hits = [f for f in self.findings
                    if f["rule_id"] == rule["id"]
                    and f["file"].startswith(fixture + "/")
                    and "/multi/" not in f["file"]]
            self.assertTrue(hits,
                            "rule %s (%s) did not fire on %s" %
                            (rule["id"], rule["category"], fixture))

    def test_each_fixture_covers_expected_family_only(self):
        for category, fixture in FAMILY_FIXTURE.items():
            hits = [f for f in self.findings
                    if f["file"].startswith(fixture + "/")
                    and "/multi/" not in f["file"]]
            self.assertTrue(hits, "fixture %s produced no findings" % fixture)
            for f in hits:
                self.assertEqual(f["category"], category,
                                 "%s leaked into %s" % (f["rule_id"], fixture))


class TestNegativeControl(unittest.TestCase):
    """The clean fixture must produce zero findings from any rule."""

    def test_clean_skill_has_zero_findings(self):
        _, findings = scan_dir(FIXTURES_DIR)
        clean_hits = [f for f in findings
                      if f["file"].startswith("clean-skill/")]
        self.assertEqual(clean_hits, [])

    def test_clean_skill_dir_scanned_directly(self):
        skills, findings = scan_dir(FIXTURES_DIR + "/multi")
        multi_clean = [f for f in findings if f["skill"] == "clean-skill"]
        self.assertEqual(multi_clean, [])

    def test_clean_fixture_scanned_as_skills_dir(self):
        # A skills dir whose only skill is the clean one: no findings.
        import tempfile, shutil, os
        tmp = tempfile.mkdtemp()
        try:
            shutil.copytree(FIXTURES_DIR + "/clean-skill",
                            os.path.join(tmp, "clean-skill"))
            skills, findings = scan_dir(tmp)
            self.assertEqual(skills, ["clean-skill"])
            self.assertEqual(findings, [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
