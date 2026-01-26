"""
Test the rule collector.
"""
import unittest
import os
import tempfile
import yaml
from main.rule_collector import retrieve_yara_rule_sets


class TestRuleCollector(unittest.TestCase):
    """
    Test the rule collector.
    """
    def test_retrieve_yara_rule_sets(self):
        """
        Test the retrieve_yara_rule_sets function.
        """
        # Mock the inputs
        repo_staging_dir = './repos'
        yara_repos = [{'name': 'test', 'author': 'test', 'url': 'https://github.com/Neo23x0/YARA-Style-Guide', 'branch': 'master', 'quality': 90}]
        
        # Call the function
        result = retrieve_yara_rule_sets(repo_staging_dir, yara_repos)
        
        # Check the result
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'test')
        self.assertEqual(len(result[0]['rules_sets']), 8)
        self.assertEqual(len(result[0]['rules_sets'][0]['rules']), 2)

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
