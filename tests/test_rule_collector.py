"""
Test the rule collector.
"""
import unittest
import os
import tempfile
import yaml
from git import Actor, Repo
from pathlib import Path
from unittest.mock import patch
from main.rule_collector import retrieve_yara_rule_sets


class TestRuleCollector(unittest.TestCase):
    """
    Test the rule collector.
    """
    def test_retrieve_yara_rule_sets(self):
        """
        Test the retrieve_yara_rule_sets function.
        """
        # Use a fixed local source; upstream contents and os.walk order can vary.
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_path = Path(tmp_dir) / 'source'
            source = Repo.init(source_path)
            (source_path / 'rules.yar').write_text(
                'rule First { condition: true } rule Second { condition: false }')
            nested_path = source_path / 'nested'
            nested_path.mkdir()
            (nested_path / 'more.yara').write_text('rule Third { condition: true }')
            source.index.add(['rules.yar', 'nested/more.yara'])
            identity = Actor('Test', 'test@example.invalid')
            source.index.commit('Fixture', author=identity, committer=identity)
            yara_repos = [{'name': 'test', 'author': 'test',
                           'url': 'https://example.invalid/owner/rules',
                           'branch': source.active_branch.name, 'quality': 90}]
            clone = Repo.clone_from
            with patch('main.rule_collector.Repo.clone_from',
                       side_effect=lambda url, destination, **kw: clone(str(source_path), destination, **kw)):
                result = retrieve_yara_rule_sets(str(Path(tmp_dir) / 'repos'), yara_repos)
        
        # Check the result
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'test')
        counts = {group['file_path']: len(group['rules']) for group in result[0]['rules_sets']}
        self.assertEqual(counts, {'rules.yar': 2, 'nested/more.yara': 1})

    def test_all_repos_have_rules(self):
        """
        Test that all repos yield at least one rule.
        """
        config_path = os.path.join(os.path.dirname(__file__), '..', 'yara-forge-config.yml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        # Subset of stable repos for test speed/reliability
        repos = [r for r in config['yara_repositories'] 
                 if r['name'] in ['Signature Base', 'ReversingLabs', 'R3c0nst']]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = retrieve_yara_rule_sets(tmp_dir, repos)
            self.assertEqual(len(result), len(repos))
            for repo_res in result:
                total_rules = sum(len(rs['rules']) for rs in repo_res['rules_sets'])
                self.assertGreater(total_rules, 0, f"Repo '{repo_res['name']}' extracted 0 rules")


if __name__ == '__main__':
    unittest.main()
