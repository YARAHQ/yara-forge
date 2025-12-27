"""
Tests for rule package output guardrails.
"""
import os
import tempfile
import unittest

from plyara import Plyara

from main.rule_output import write_yara_packages


TEST_CONFIG = {
    "yara_rule_packages": [
        {
            "name": "core",
            "description": "Test package",
            "minimum_quality": 0,
            "force_include_importance_level": 100,
            "force_exclude_importance_level": -1,
            "minimum_age": 0,
            "minimum_score": 0,
            "max_age": 10000,
        }
    ],
    "repo_header": "# Repo {repo_name} total {total_rules}\n",
    "rule_set_header": "# Package {rule_package_name} total {total_rules}\n",
    "rule_base_score": 75,
}


RULE_TEXT_TWO = """
rule SampleOne {
    meta:
        description = "Rule one"
        score = 80
        quality = 80
        date = "2024-01-01"
        modified = "2024-01-02"
    condition:
        true
}

rule SampleTwo {
    meta:
        description = "Rule two"
        score = 80
        quality = 80
        date = "2024-01-01"
        modified = "2024-01-02"
    condition:
        true
}
"""

RULE_TEXT_ONE = """
rule OnlyRule {
    meta:
        description = "Single rule"
        score = 80
        quality = 80
        date = "2024-01-01"
        modified = "2024-01-02"
    condition:
        true
}
"""


def build_repo_payload(rules):
    return [
        {
            "name": "SampleRepo",
            "url": "https://example.com/sample",
            "author": "Sample Author",
            "owner": "sample",
            "repo": "sample",
            "branch": "main",
            "rules_sets": [
                {
                    "file_path": "detections/yara/sample.yar",
                    "rules": rules,
                }
            ],
            "quality": 80,
            "license": "N/A",
            "license_url": "N/A",
            "commit_hash": "abc123",
            "retrieval_date": "2024-01-01 00:00:00",
            "repo_path": "/tmp/sample",
        }
    ]


class TestRuleOutputGuardrails(unittest.TestCase):
    def setUp(self):
        parser = Plyara()
        self.rules_two = parser.parse_string(RULE_TEXT_TWO)
        self.rules_one = parser.parse_string(RULE_TEXT_ONE)

    def _render_package(self, rules):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                package_files = write_yara_packages(
                    build_repo_payload(rules),
                    program_version="1.0.0",
                    yaraqa_commit="testhash",
                    YARA_FORGE_CONFIG=TEST_CONFIG,
                )
                with open(package_files[0]["file_path"], "r", encoding="utf-8") as f:
                    return f.read()
            finally:
                os.chdir(cwd)

    @staticmethod
    def _count_rules(package_text):
        return sum(
            1 for line in package_text.splitlines() if line.strip().startswith("rule ")
        )

    def test_rule_count_guardrail(self):
        package_text = self._render_package(self.rules_two)
        self.assertEqual(self._count_rules(package_text), 2)

    def test_package_not_empty(self):
        package_text = self._render_package(self.rules_one)
        self.assertGreater(self._count_rules(package_text), 0)


if __name__ == "__main__":
    unittest.main()
