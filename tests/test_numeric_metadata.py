"""Numeric normalization must not undo explicit package exclusions."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from plyara import Plyara

from main.rule_output import write_yara_packages
from main.rule_processors import process_yara_rules
from test_rule_output_guardrails import TEST_CONFIG, build_repo_payload


class TestNumericMetadata(unittest.TestCase):
    def process(self, metadata, quality=80):
        rule = Plyara().parse_string('rule Example { condition: filesize >= 0 }')[0]
        rule['metadata'] = metadata
        repos = build_repo_payload([rule])
        repos[0]['quality'] = quality
        with patch('main.rule_processors.align_yara_rule_date', side_effect=lambda meta, *_: meta), \
                patch('main.rule_processors.retrieve_custom_importance_score', return_value=None):
            process_yara_rules(repos, dict(TEST_CONFIG, meta_data_order=[]))
        return repos, {key: value for item in rule['metadata'] for key, value in item.items()}

    def test_negative_score_and_quality_are_clamped(self):
        _, metadata = self.process([{'score': -5}], quality=-10)
        self.assertEqual(metadata['score'], 0)
        self.assertEqual(metadata['quality'], 0)

    def test_boolean_control_metadata_is_not_retained_as_integer(self):
        _, metadata = self.process([{'score': 75}, {'importance': True}], quality=True)
        self.assertIs(type(metadata['quality']), int)
        self.assertIs(type(metadata['importance']), int)
        self.assertEqual(metadata['quality'], 0)
        self.assertEqual(metadata['importance'], 0)

    def test_non_numeric_control_metadata_is_zero(self):
        _, metadata = self.process([{'score': 75}, {'importance': 'unknown'}], quality='unknown')
        self.assertEqual(metadata['quality'], 0)
        self.assertEqual(metadata['importance'], 0)

    def test_negative_importance_still_excludes_rule(self):
        repos, metadata = self.process([{'score': 90}, {'importance': -10}])
        self.assertEqual(metadata['importance'], -10)
        package = dict(TEST_CONFIG['yara_rule_packages'][0], force_exclude_importance_level=0)
        config = dict(TEST_CONFIG, yara_rule_packages=[package])
        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            try:
                os.chdir(directory)
                packages = write_yara_packages(repos, 'test', 'test', config)
                self.assertFalse(Path(packages[0]['file_path']).exists())
            finally:
                os.chdir(previous)

    def test_valid_control_metadata_is_preserved(self):
        _, metadata = self.process([{'score': 75}, {'importance': 60}], quality=80)
        self.assertEqual([metadata[key] for key in ('score', 'quality', 'importance')], [75, 80, 60])
