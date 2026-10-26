"""QA and provenance regressions, using the real YARA compiler."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import plyara
from git import Repo

from main.rule_processors import process_yara_rules
from qa.rule_qa import check_yara_packages, evaluate_rules_quality, get_yara_qa_commit_hash


class TestQaGuardrails(unittest.TestCase):
    def test_no_packages_is_not_a_successful_build(self):
        self.assertFalse(check_yara_packages([]))

    def test_comment_only_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'empty.yar'
            path.write_text('// Build header without any rules\n')
            self.assertFalse(check_yara_packages([{'name': 'empty', 'file_path': str(path)}]))

    def test_real_package_compiles(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'valid.yar'
            path.write_text('rule Example { condition: true }')
            self.assertTrue(check_yara_packages([{'name': 'valid', 'file_path': str(path)}]))

    def test_zero_custom_score_is_applied(self):
        rule = plyara.Plyara().parse_string('rule Example { condition: true }')[0]
        rule['metadata'] = [{'quality': 80}, {'score': 75}]
        repos = [{'name': 'Example', 'rules_sets': [{'file_path': 'rule.yar', 'rules': [rule]}]}]
        with patch('qa.rule_qa.YaraQA.analyze_rule', return_value=[]), \
                patch('qa.rule_qa.YaraQA.analyze_live_rule_performance', return_value=[]), \
                patch('qa.rule_qa.retrieve_custom_score', return_value=0), \
                patch('qa.rule_qa.retrieve_custom_quality_reduction', return_value=0), \
                patch('qa.rule_qa.write_issues_to_file'):
            evaluate_rules_quality(repos, {'issue_levels': {1: 0, 2: -10, 3: -20, 4: -100}})
        self.assertIn({'score': 0}, rule['metadata'])

    def test_zero_custom_importance_is_applied(self):
        rule = plyara.Plyara().parse_string('rule Example { condition: true }')[0]
        repo = {'name': 'Example', 'author': 'Author', 'url': 'https://example.com/repo',
                'repo_path': 'unused', 'commit_hash': 'abc', 'license_url': 'N/A', 'quality': 80,
                'rules_sets': [{'file_path': 'rule.yar', 'rules': [rule]}]}
        with patch('main.rule_processors.retrieve_custom_importance_score', return_value=0), \
                patch('main.rule_processors.align_yara_rule_date', side_effect=lambda metadata, *args: metadata):
            process_yara_rules([repo], {'rule_base_score': 75, 'meta_data_order': []})
        self.assertIn({'importance': 0}, rule['metadata'])

    def test_qa_revision_is_checked_out_head_even_when_detached(self):
        with tempfile.TemporaryDirectory() as directory:
            qa_path = Path(directory) / 'qa'
            repo = Repo.init(qa_path / 'yaraQA', initial_branch='main')
            path = qa_path / 'yaraQA' / 'sample'
            path.write_text('one')
            repo.index.add(['sample'])
            first = repo.index.commit('first')
            path.write_text('two')
            repo.index.add(['sample'])
            repo.index.commit('second')
            repo.git.checkout(first.hexsha)
            # Resolve the submodule location independently of the working directory.
            with patch('qa.rule_qa.__file__', str(qa_path / 'rule_qa.py')):
                self.assertEqual(get_yara_qa_commit_hash(), first.hexsha)
