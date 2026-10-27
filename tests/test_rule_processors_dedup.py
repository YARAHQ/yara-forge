"""
Tests for logic hash deduplication in rule processing.
"""
import datetime
import os
import unittest

from plyara import Plyara

from main.rule_processors import (
    date_lookup_cache,
    private_rule_mapping,
    process_yara_rules,
)


TEST_CONFIG = {
    "rule_base_score": 75,
    "meta_data_order": [
        "description",
        "author",
        "id",
        "date",
        "modified",
        "old_rule_name",
        "reference",
        "source_url",
        "license_url",
        "hash",
        "logic_hash",
        "score",
        "quality",
        "tags",
    ],
}


RULE_TEXT_DUP = """
rule DupRule {
    meta:
        description = "duplicate one"
    condition:
        true
}

rule DupRule {
    meta:
        description = "duplicate two"
    condition:
        true
}
"""


class TestRuleProcessorDedup(unittest.TestCase):
    def setUp(self):
        date_lookup_cache.clear()
        private_rule_mapping.clear()
        self.parser = Plyara()

    def test_duplicates_are_removed(self):
        rules = self.parser.parse_string(RULE_TEXT_DUP)
        repo_path = "dummy_repo"
        file_path = "detections/yara/dups.yar"
        date_lookup_cache[os.path.join(repo_path, file_path)] = (
            datetime.datetime(2024, 1, 1),
            datetime.datetime(2024, 1, 2),
        )

        repo_payload = [
            {
                "name": "DupRepo",
                "url": "https://example.com/dup",
                "author": "Author",
                "owner": "owner",
                "repo": "repo",
                "branch": "main",
                "rules_sets": [
                    {
                        "file_path": file_path,
                        "rules": rules,
                    }
                ],
                "quality": 80,
                "license": "N/A",
                "license_url": "N/A",
                "commit_hash": "abc123",
                "retrieval_date": "2024-01-01 00:00:00",
                "repo_path": repo_path,
            }
        ]

        processed = process_yara_rules(repo_payload, TEST_CONFIG)
        resulting_rules = processed[0]["rules_sets"][0]["rules"]
        self.assertEqual(len(resulting_rules), 1)


if __name__ == "__main__":
    unittest.main()
