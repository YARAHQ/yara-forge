"""
Tests for case-insensitive meta key matching in rule processing.
"""
import unittest

from main.rule_processors import (
    align_yara_rule_author,
    align_yara_rule_description,
    align_yara_rule_reference,
)


class TestAlignYaraRuleAuthor(unittest.TestCase):
    """
    Test that align_yara_rule_author recognizes the capitalized key variants
    documented in https://github.com/YARAHQ/yara-forge/issues/74 (e.g. 'Author'
    vs 'author'), the same way align_yara_rule_hashes already does for hashes.
    """

    def test_capitalized_author_key_is_recognized(self):
        rule_meta_data = [{'Author': 'Jane Doe'}]

        result = align_yara_rule_author(rule_meta_data, 'Default Repo Author')

        self.assertEqual(result, [{'author': 'Jane Doe'}])

    def test_capitalized_author_key_is_not_duplicated(self):
        # Before the fix, the unmatched 'Author' entry stayed in the meta data
        # and a second, default-value 'author' entry was appended on top of it.
        rule_meta_data = [{'Author': 'Jane Doe'}]

        result = align_yara_rule_author(rule_meta_data, 'Default Repo Author')

        self.assertEqual(len(result), 1)
        keys = [k for m in result for k in m]
        self.assertEqual(keys.count('Author'), 0)
        self.assertEqual(keys.count('author'), 1)


class TestAlignYaraRuleReference(unittest.TestCase):
    """
    Test that align_yara_rule_reference recognizes capitalized key variants
    ('Reference', 'URL', ...) the same way it already recognizes the
    lowercase forms. Values deliberately don't start with http(s):// so the
    existing value-prefix fallback can't mask a key-matching failure.
    """

    def test_capitalized_reference_key_is_recognized(self):
        rule_meta_data = [{'Reference': 'internal-report-4471'}]

        result = align_yara_rule_reference(rule_meta_data, 'https://example.com/ruleset')

        self.assertEqual(result, [{'reference': 'internal-report-4471'}])

    def test_capitalized_url_key_is_not_duplicated(self):
        rule_meta_data = [{'URL': 'internal-report-4471'}]

        result = align_yara_rule_reference(rule_meta_data, 'https://example.com/ruleset')

        self.assertEqual(len(result), 1)
        keys = [k for m in result for k in m]
        self.assertEqual(keys.count('URL'), 0)
        self.assertEqual(keys.count('reference'), 1)


class TestAlignYaraRuleDescription(unittest.TestCase):
    """
    Test that align_yara_rule_description recognizes capitalized key variants
    ('Description' vs 'description'). The threat-name fallback branch already
    lowercases its own key check; the primary description-key check did not.
    Values deliberately don't start with 'Detects ' so the existing
    value-prefix fallback can't mask a key-matching failure.
    """

    def test_capitalized_description_key_is_recognized(self):
        rule_meta_data = [{'Description': 'A known malware family'}]

        result = align_yara_rule_description(rule_meta_data, 'Some Repo')

        self.assertEqual(result, [{'description': 'A known malware family'}])

    def test_capitalized_description_key_is_not_duplicated(self):
        # Before the fix, the unmatched 'Description' entry was left in place
        # and a second, quality-penalized 'description' fallback was appended.
        rule_meta_data = [{'Description': 'A known malware family'}]

        result = align_yara_rule_description(rule_meta_data, 'Some Repo')

        self.assertEqual(len(result), 1)
        keys = [k for m in result for k in m]
        self.assertEqual(keys.count('Description'), 0)
        self.assertEqual(keys.count('description'), 1)


if __name__ == '__main__':
    unittest.main()
