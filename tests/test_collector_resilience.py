"""Offline collection tests using actual local Git repositories."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from git import Repo

from main.rule_collector import process_yara_file, retrieve_yara_rule_sets


class TestCollectorResilience(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.repo = Repo.init(self.source, initial_branch='main')
        (self.source / 'rules').mkdir()
        (self.source / 'rules' / 'sample.yar').write_text('rule MainRule { condition: true }')
        self.commit()

    def commit(self):
        self.repo.git.add(A=True)
        self.repo.index.commit('fixture')

    def collect(self, configs=None):
        configs = configs or [self.config()]
        clone = Repo.clone_from
        with patch('main.rule_collector.Repo.clone_from',
                   side_effect=lambda url, path, **kwargs: clone(str(self.source), path, **kwargs)):
            return retrieve_yara_rule_sets(str(self.root / 'staging'), configs)

    @staticmethod
    def config(branch='main', url='https://example.com/owner/source'):
        return {'name': branch, 'author': 'Author', 'url': url, 'branch': branch, 'quality': 80}

    def test_nested_license_is_preserved(self):
        (self.source / 'rules' / 'LICENSE.txt').write_text('Nested license terms')
        self.commit()
        result = self.collect()[0]
        self.assertEqual(result['license'], 'Nested license terms')
        self.assertTrue(result['license_url'].endswith('/rules/LICENSE.txt'))

    def test_root_license_takes_precedence(self):
        (self.source / 'rules' / 'LICENSE.txt').write_text('Nested license terms')
        (self.source / 'LICENSE').write_text('Root license terms')
        self.commit()
        self.assertEqual(self.collect()[0]['license'], 'Root license terms')

    def test_different_branches_have_separate_checkouts(self):
        self.repo.git.checkout('-b', 'alternate')
        (self.source / 'rules' / 'sample.yar').write_text('rule AlternateRule { condition: false }')
        self.commit()
        results = self.collect([self.config(), self.config('alternate')])
        names = [repo['rules_sets'][0]['rules'][0]['rule_name'] for repo in results]
        self.assertEqual(names, ['MainRule', 'AlternateRule'])
        self.assertNotEqual(results[0]['repo_path'], results[1]['repo_path'])
        self.assertNotEqual(results[0]['commit_hash'], results[1]['commit_hash'])

    def test_dotted_repository_name_is_preserved(self):
        result = self.collect([self.config(url='https://example.com/owner/source.rules.git/')])[0]
        self.assertEqual(result['repo'], 'source.rules')

    def test_unreadable_encoding_does_not_abort_other_files(self):
        (self.source / 'rules' / 'bad.yar').write_bytes(b'\xff\xfeinvalid')
        self.commit()
        result = self.collect()[0]
        self.assertEqual([r['rules'][0]['rule_name'] for r in result['rules_sets']], ['MainRule'])

    def test_utf8_bom_is_accepted(self):
        path = self.root / 'bom.yar'
        path.write_text('rule BomRule { condition: true }', encoding='utf-8-sig')
        rules = []
        process_yara_file(str(path), str(self.root), rules)
        self.assertEqual(rules[0]['rules'][0]['rule_name'], 'BomRule')

    def test_missing_configured_path_fails_instead_of_silently_losing_rules(self):
        config = self.config()
        config['path'] = 'missing-directory'
        with self.assertRaisesRegex(FileNotFoundError, 'Configured rule directory'):
            self.collect([config])
