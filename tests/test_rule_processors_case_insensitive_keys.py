"""
Tests for case-insensitive meta key matching in rule processing.
"""
import datetime
import os
import unittest

from main.rule_processors import (
    align_yara_rule_author,
    align_yara_rule_date,
    align_yara_rule_description,
    align_yara_rule_reference,
    align_yara_rule_uuid,
    date_lookup_cache,
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


class TestAlignYaraRuleUuid(unittest.TestCase):
    """
    Test that align_yara_rule_uuid recognizes capitalized key variants
    ('UUID', 'ID', ...) the same way the other align_yara_rule_* functions
    already recognize theirs.
    """

    def test_capitalized_uuid_key_is_recognized(self):
        rule_meta_data = [{'UUID': '550e8400-e29b-41d4-a716-446655440000'}]

        result = align_yara_rule_uuid(rule_meta_data, 'fallback-uuid')

        self.assertEqual(result, [{'id': '550e8400-e29b-41d4-a716-446655440000'}])

    def test_capitalized_id_key_is_not_duplicated(self):
        # Before the fix, the unmatched 'ID' entry stayed in the meta data
        # and a second, fallback 'id' entry was appended on top of it.
        rule_meta_data = [{'ID': '550e8400-e29b-41d4-a716-446655440000'}]

        result = align_yara_rule_uuid(rule_meta_data, 'fallback-uuid')

        self.assertEqual(len(result), 1)
        keys = [k for m in result for k in m]
        self.assertEqual(keys.count('ID'), 0)
        self.assertEqual(keys.count('id'), 1)


class TestAlignYaraRuleDate(unittest.TestCase):
    """
    Test that align_yara_rule_date recognizes capitalized key variants
    ('Date', 'Modified') the same way it already recognizes the lowercase
    forms. The git-log lookup is short-circuited via date_lookup_cache so
    the test doesn't need a real git repository.
    """

    def setUp(self):
        date_lookup_cache.clear()
        self.repo_path = 'dummy_repo'
        self.file_path = 'detections/case_insensitive_date_test.yar'
        date_lookup_cache[os.path.join(self.repo_path, self.file_path)] = (
            datetime.datetime(2024, 1, 1),
            datetime.datetime(2024, 1, 2),
        )

    def test_capitalized_date_key_is_recognized_over_an_unrelated_date_value(self):
        # 'first_seen' isn't a recognized date key, but its value still
        # parses as a date, so the generic any-value date fallback would
        # grab it too if the 'Date' key itself weren't matched first. This
        # is what actually isolates the date_names lookup, since a lone
        # 'Date' entry gets rescued by that same fallback either way.
        rule_meta_data = [{'Date': '2023-05-17'}, {'first_seen': '2020-01-01'}]

        result = align_yara_rule_date(rule_meta_data, self.repo_path, self.file_path)

        values = {k: v for m in result for k, v in m.items()}
        self.assertEqual(values['date'], '2023-05-17')
        self.assertEqual(values['first_seen'], '2020-01-01')

    def test_capitalized_date_key_is_not_duplicated(self):
        # Before the fix, 'Date' wasn't matched by the primary lookup, so
        # both it and the unrelated 'first_seen' value fell through to the
        # any-value date fallback and were each rewritten to their own
        # 'date' entry, producing two conflicting 'date' fields.
        rule_meta_data = [{'Date': '2023-05-17'}, {'first_seen': '2020-01-01'}]

        result = align_yara_rule_date(rule_meta_data, self.repo_path, self.file_path)

        keys = [k for m in result for k in m]
        self.assertEqual(keys.count('Date'), 0)
        self.assertEqual(keys.count('date'), 1)

    def test_capitalized_modified_key_is_recognized(self):
        # A separate, already-recognized 'date' entry keeps the creation-date
        # pass from consuming 'Modified' via its own any-value date fallback,
        # so this isolates the modified_names lookup specifically.
        rule_meta_data = [{'date': '2023-01-01'}, {'Modified': '2023-05-18'}]

        result = align_yara_rule_date(rule_meta_data, self.repo_path, self.file_path)

        values = {k: v for m in result for k, v in m.items()}
        self.assertEqual(values['modified'], '2023-05-18')

    def test_capitalized_modified_key_is_not_duplicated(self):
        # Before the fix, the unmatched 'Modified' entry stayed in the meta
        # data and a second, git-derived 'modified' entry was appended on top.
        rule_meta_data = [{'date': '2023-01-01'}, {'Modified': '2023-05-18'}]

        result = align_yara_rule_date(rule_meta_data, self.repo_path, self.file_path)

        keys = [k for m in result for k in m]
        self.assertEqual(keys.count('Modified'), 0)
        self.assertEqual(keys.count('modified'), 1)


if __name__ == '__main__':
    unittest.main()
