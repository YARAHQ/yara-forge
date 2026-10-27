"""Regression cases for valid YARA metadata that is not a valid date or score."""
import datetime
import unittest
from unittest.mock import patch

from main.rule_processors import (
    align_yara_rule_date,
    align_yara_rule_description,
    date_lookup_cache,
    evaluate_yara_rule_score,
)


class TestMetadataRobustness(unittest.TestCase):
    def setUp(self):
        date_lookup_cache.clear()
        self.git_dates = (datetime.datetime(2020, 1, 2), datetime.datetime(2021, 3, 4))

    def normalize_dates(self, metadata):
        with patch('main.rule_processors.get_rule_age_git', return_value=self.git_dates):
            return align_yara_rule_date(metadata, 'repo', 'rule.yar')

    def test_non_string_dates_use_git_fallback(self):
        for value in (20240101, True):
            with self.subTest(value=value):
                result = self.normalize_dates([{'date': value}, {'modified': value}])
                self.assertEqual(result, [{'date': '2020-01-02'}, {'modified': '2021-03-04'}])

    def test_invalid_modified_alias_does_not_erase_valid_date(self):
        result = self.normalize_dates([
            {'date': '2020-01-02'}, {'modified': '2024-05-06'}, {'updated': 'invalid'},
        ])
        self.assertEqual(result, [{'date': '2020-01-02'}, {'modified': '2024-05-06'}])

    def test_modified_is_not_consumed_as_creation_date(self):
        result = self.normalize_dates([{'modified': '2024-05-06'}])
        self.assertIn({'date': '2020-01-02'}, result)
        self.assertIn({'modified': '2024-05-06'}, result)

    def test_unrelated_metadata_is_preserved(self):
        result = self.normalize_dates([{'description': 'May'}, {'author': 'June'}])
        self.assertIn({'description': 'May'}, result)
        self.assertIn({'author': 'June'}, result)
        self.assertIn({'date': '2020-01-02'}, result)

    def test_date_aliases_produce_one_canonical_value(self):
        result = self.normalize_dates([{'date': '2020-01-02'}, {'created': '2020-01-03'}])
        self.assertEqual(sum('date' in item for item in result), 1)

    def test_non_string_threat_description(self):
        for value in (123, True):
            with self.subTest(value=value):
                result = align_yara_rule_description([{'threat': value}], 'Test repo')
                self.assertTrue(any(str(value) in item.get('description', '') for item in result))

    def test_non_string_description_is_normalized_to_text(self):
        self.assertEqual(
            align_yara_rule_description([{'description': 123}], 'Test repo'),
            [{'description': '123'}],
        )

    def test_invalid_scores_fall_back_to_metadata_or_base_score(self):
        for value in ('high', '', True):
            with self.subTest(value=value):
                rule = {'rule_name': 'Example', 'metadata': [{'score': value}]}
                self.assertEqual(evaluate_yara_rule_score(rule, {'rule_base_score': 75}), 75)

    def test_numeric_scores_including_zero_are_preserved(self):
        for value in (0, '0', 42, '42'):
            with self.subTest(value=value):
                rule = {'rule_name': 'Example', 'metadata': [{'score': value}]}
                self.assertEqual(evaluate_yara_rule_score(rule, {'rule_base_score': 75}), int(value))
